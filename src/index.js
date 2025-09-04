import { CONFIG, createConfig } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Docker request识别
 */
function isDockerRequest(request, url) {
  if (url.pathname.startsWith('/v2/')) return true;
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) return true;
  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) return true;
  return false;
}

/**
 * Git request识别
 */
function isGitRequest(request, url) {
  if (url.pathname.endsWith('/info/refs')) return true;
  if (
    url.pathname.endsWith('/git-upload-pack') ||
    url.pathname.endsWith('/git-receive-pack')
  ) return true;
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) return true;
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) return true;
  return false;
}

/**
 * AI inference请求识别
 */
function isAIInferenceRequest(request, url) {
  if (url.pathname.startsWith('/ip/')) return true;
  const aiEndpoints = [
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/messages',
    '/v1/predictions',
    '/v1/generate',
    '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];
  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) return true;
  const contentType = request.headers.get('Content-Type') || '';
  if (
    contentType.includes('application/json') &&
    request.method === 'POST' &&
    (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    )
  ) return true;
  return false;
}

/**
 * DockerHub仓库scope提取（支持官方与组织仓库）
 */
function extractDockerScope(url) {
  // /cr/docker/alpine  => repository:library/alpine:pull
  // /cr/docker/nginxinc/nginx-unprivileged => repository:nginxinc/nginx-unprivileged:pull
  const parts = url.pathname.split('/');
  if (parts.length === 4 && parts[1] === 'cr' && parts[2] === 'docker') {
    return `repository:library/${parts[3]}:pull`;
  }
  if (parts.length > 4 && parts[1] === 'cr' && parts[2] === 'docker') {
    return `repository:${parts.slice(3).join('/')}:pull`;
  }
  return '';
}

/**
 * 请求校验
 */
function validateRequest(request, url, config = CONFIG) {
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods =
    isGit || isDocker || isAI
      ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
      : config.SECURITY.ALLOWED_METHODS;

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }
  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }
  return { valid: true };
}

/**
 * 错误响应
 */
function createErrorResponse(message, status, includeDetails = false) {
  const errorBody = includeDetails
    ? JSON.stringify({ error: message, status, timestamp: new Date().toISOString() })
    : message;

  return new Response(errorBody, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': includeDetails ? 'application/json' : 'text/plain'
      })
    )
  });
}

/**
 * 安全响应头
 */
function addSecurityHeaders(headers) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; script-src 'none'");
  headers.set('Permissions-Policy', 'interest-cohort=()');
  return headers;
}

/**
 * 解析WWW-Authenticate
 */
function parseAuthenticate(authenticateStr) {
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * 拉取Docker Token
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set('service', wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set('scope', scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set('Authorization', authorization);
  }
  return await fetch(url, { method: 'GET', headers });
}

/**
 * Docker未授权响应
 */
function responseUnauthorized(url) {
  const headers = new Headers();
  headers.set('WWW-Authenticate', `Bearer realm="https://${url.hostname}/v2/auth",service="Xget"`);
  return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
    status: 401,
    headers
  });
}

/**
 * 主处理逻辑
 */
async function handleRequest(request, env, ctx) {
  try {
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);

    const monitor = new PerformanceMonitor();
    // Docker API版本确认
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    // 根路径重定向
    if (url.pathname === '/' || url.pathname === '') {
      const HOME_PAGE_URL = 'https://github.com/xixu-me/Xget';
      return Response.redirect(HOME_PAGE_URL, 302);
    }

    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // 标准化路径
    let platform;
    let effectivePath = url.pathname;

    // DockerHub路径特殊处理
    if (isDocker) {
      if (!url.pathname.startsWith('/cr/docker')) {
        return createErrorResponse('container registry requests must use /cr/docker prefix', 400);
      }
      // 转换为 /v2/library/alpine 或 /v2/org/image
      let dockerPath = url.pathname.replace(/^\/cr\/docker/, '');
      if (dockerPath.split('/').length === 2) {
        // 只有镜像名，补上 library
        dockerPath = `/library${dockerPath}`;
      }
      effectivePath = dockerPath;
      platform = 'docker';
    } else {
      // 平台自动检测
      const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
        const pathA = `/${a.replace('-', '/')}/`;
        const pathB = `/${b.replace('-', '/')}/`;
        return pathB.length - pathA.length;
      });

      platform =
        sortedPlatforms.find(key => {
          const expectedPrefix = `/${key.replace('-', '/')}/`;
          return effectivePath.startsWith(expectedPrefix);
        }) || effectivePath.split('/')[1];
    }

    if (!platform || !config.PLATFORMS[platform]) {
      const HOME_PAGE_URL = 'https://github.com/xixu-me/Xget';
      return Response.redirect(HOME_PAGE_URL, 302);
    }

    // 路径转换
    const targetPath = isDocker
      ? effectivePath
      : transformPath(effectivePath, platform);

    // DockerHub最终访问路径
    let finalTargetPath;
    let targetUrl;
    if (platform === 'docker') {
      finalTargetPath = `/v2${targetPath}`;
      targetUrl = `https://registry-1.docker.io${finalTargetPath}${url.search}`;
    } else if (platform.startsWith('cr-')) {
      finalTargetPath = `/v2${targetPath}`;
      targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    } else {
      finalTargetPath = targetPath;
      targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    }
    const authorization = request.headers.get('Authorization');

    // DockerHub /v2/auth处理（获取token）
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL('https://registry-1.docker.io/v2/');
      const resp = await fetch(newUrl.toString(), { method: 'GET', redirect: 'follow' });
      if (resp.status !== 401) return resp;
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (!authenticateStr) return resp;
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope');
      if (!scope) scope = extractDockerScope(url);
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // 检查类型
    const isGit = isGitRequest(request, url);
    const isAI = isAIInferenceRequest(request, url);

    // 缓存
    const cache = caches.default;
    const cacheKey = new Request(targetUrl, request);
    let response;

    if (!isGit && !isDocker && !isAI) {
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const fullContentKey = new Request(targetUrl, {
          method: request.method,
          headers: new Headers(
            [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
          )
        });
        response = await cache.match(fullContentKey);
        if (response) {
          monitor.mark('cache_hit_full_content');
          return response;
        }
      }
    }

    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow'
    };

    // POST/PUT/PATCH需带body
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }
    const requestHeaders = fetchOptions.headers;

    if (isGit || isDocker || isAI) {
      for (const [key, value] of request.headers.entries()) {
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-upload-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
      }
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-receive-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-receive-pack-request');
        }
      }
      if (isAI) {
        if (request.method === 'POST' && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/json');
        }
        if (!requestHeaders.has('User-Agent')) {
          requestHeaders.set('User-Agent', 'Xget-AI-Proxy/1.0');
        }
      }
    } else {
      Object.assign(fetchOptions, {
        cf: {
          http3: true,
          cacheTtl: config.CACHE_DURATION,
          cacheEverything: true,
          minify: {
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true
        }
      });

      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
      requestHeaders.set('Connection', 'keep-alive');
      requestHeaders.set('User-Agent', 'Wget/1.21.3');
      requestHeaders.set('Origin', request.headers.get('Origin') || '*');

      const rangeHeader = request.headers.get('Range');
      const isMediaFile = targetUrl.match(
        /\.(mp4|avi|mkv|mov|wmv|flv|webm|mp3|wav|flac|aac|ogg|jpg|jpeg|png|gif|bmp|svg|pdf|zip|rar|7z|tar|gz|bz2|xz)$/i
      );
      if (isMediaFile || rangeHeader) {
        requestHeaders.set('Accept-Encoding', 'identity');
      }
      if (rangeHeader) {
        requestHeaders.set('Range', rangeHeader);
      }
    }

    // 重试机制
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark(`attempt_${attempts}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);
        const finalFetchOptions = { ...fetchOptions, signal: controller.signal };

        // HEAD请求特殊处理
        if (request.method === 'HEAD') {
          response = await fetch(targetUrl, finalFetchOptions);
          if (response.ok && !response.headers.get('Content-Length')) {
            const getResponse = await fetch(targetUrl, {
              ...finalFetchOptions,
              method: 'GET'
            });
            if (getResponse.ok) {
              const headHeaders = new Headers(response.headers);
              const contentLength = getResponse.headers.get('Content-Length');
              if (contentLength) {
                headHeaders.set('Content-Length', contentLength);
              } else {
                const arrayBuffer = await getResponse.arrayBuffer();
                headHeaders.set('Content-Length', arrayBuffer.byteLength.toString());
              }
              response = new Response(null, {
                status: getResponse.status,
                statusText: getResponse.statusText,
                headers: headHeaders
              });
            }
          }
        } else {
          response = await fetch(targetUrl, finalFetchOptions);
        }
        clearTimeout(timeoutId);

        // DockerHub 401自动token获取
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge');
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);
              let scope = extractDockerScope(url);
              const tokenResponse = await fetchToken(wwwAuthenticate, scope, '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);
                  const retryResponse = await fetch(targetUrl, {
                    ...finalFetchOptions,
                    headers: retryHeaders
                  });
                  if (retryResponse.ok) {
                    response = retryResponse;
                    monitor.mark('docker_token_success');
                    break;
                  }
                }
              }
            } catch (error) {
              console.log('Token fetch failed:', error);
            }
          }
          return responseUnauthorized(url);
        }

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }
        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return createErrorResponse('Request timeout', 408);
        }
        if (attempts >= config.MAX_RETRIES) {
          const message = error instanceof Error ? error.message : String(error);
          return createErrorResponse(
            `Failed after ${config.MAX_RETRIES} attempts: ${message}`,
            500,
            true
          );
        }
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    if (!response) {
      return createErrorResponse('No response received after all retry attempts', 500, true);
    }

    if (!response.ok && response.status !== 206) {
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return createErrorResponse(
          `Authentication required for this container registry resource. This may be a private repository. Original error: ${errorText}`,
          401,
          true
        );
      }
      const errorText = await response.text().catch(() => 'Unknown error');
      return createErrorResponse(
        `Upstream server error (${response.status}): ${errorText}`,
        response.status,
        true
      );
    }

    let responseBody = response.body;

    // PyPI与npm内容重写
    if (platform === 'pypi' && response.headers.get('content-type')?.includes('text/html')) {
      const originalText = await response.text();
      const rewrittenText = originalText.replace(
        /https:\/\/files\.pythonhosted\.org/g,
        `${url.origin}/pypi/files`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }
    if (platform === 'npm' && response.headers.get('content-type')?.includes('application/json')) {
      const originalText = await response.text();
      const rewrittenText = originalText.replace(
        /https:\/\/registry\.npmjs\.org\/([^\/]+)/g,
        `${url.origin}/npm/$1`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    const headers = new Headers(response.headers);

    if (isGit || isDocker) {
      // 保留全部header
    } else {
      headers.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Accept-Ranges', 'bytes');

      if (!headers.has('Content-Length') && response.status === 200) {
        try {
          const contentLength = response.headers.get('Content-Length');
          if (contentLength) {
            headers.set('Content-Length', contentLength);
          }
        } catch (error) {
          console.warn('Could not set Content-Length header:', error);
        }
      }
      addSecurityHeaders(headers);
    }

    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers
    });

    // 缓存
    if (
      !isGit && !isDocker && !isAI &&
      ['GET', 'HEAD'].includes(request.method) &&
      response.ok && response.status === 200
    ) {
      const rangeHeader = request.headers.get('Range');
      const cacheKey = rangeHeader
        ? new Request(targetUrl, {
            method: request.method,
            headers: new Headers(
              [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
            )
          })
        : new Request(targetUrl, request);

      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));
      if (rangeHeader && response.status === 200) {
        const rangedResponse = await cache.match(new Request(targetUrl, request));
        if (rangedResponse) {
          monitor.mark('range_cache_hit_after_full_cache');
          return rangedResponse;
        }
      }
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI ? finalResponse : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResponse(`Internal Server Error: ${message}`, 500, true);
  }
}

/**
 * 性能header
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, {
    status: response.status,
    headers
  });
}

export default {
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};