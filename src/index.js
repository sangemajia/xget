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
 * Detects if a request is a container registry operation
 */
function isDockerRequest(request, url) {
  if (url.pathname.startsWith('/v2/')) return true;
  
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) return true;
  
  const accept = request.headers.get('Accept') || '';
  return (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  );
}

/**
 * Detects if a request is a Git operation
 */
function isGitRequest(request, url) {
  if (url.pathname.endsWith('/info/refs')) return true;
  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) return true;
  
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) return true;
  
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }
  
  const contentType = request.headers.get('Content-Type') || '';
  return contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack');
}

/**
 * Check if the request is for an AI inference provider
 */
function isAIInferenceRequest(request, url) {
  if (url.pathname.startsWith('/ip/')) return true;
  
  const aiEndpoints = [
    '/v1/chat/completions', '/v1/completions', '/v1/messages',
    '/v1/predictions', '/v1/generate', '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];
  
  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) return true;
  
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json') && request.method === 'POST') {
    return (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    );
  }
  
  return false;
}

/**
 * Validates incoming requests against security rules
 */
function validateRequest(request, url, config = CONFIG) {
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods = isGit || isDocker || isAI
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
 * Creates a standardized error response
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
 * Adds security headers to the response
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
 * Parses Docker WWW-Authenticate header
 */
function parseAuthenticate(authenticateStr) {
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (!matches || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches authentication token from container registry
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service) {
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
 * Creates unauthorized response for container registry
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
 * Handles incoming requests with caching, retries, and security measures
 */
async function handleRequest(request, env, ctx) {
  try {
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);
    const monitor = new PerformanceMonitor();

    // Handle Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    // Redirect root path to GitHub repository
    if (url.pathname === '/' || url.pathname === '') {
      return Response.redirect('https://github.com/xixu-me/Xget', 302);
    }

    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // Parse platform and path
    let platform;
    let effectivePath = url.pathname;

    // Handle container registry paths
    if (isDocker) {
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return createErrorResponse('Container registry requests must use /cr/ prefix', 400);
      }
      effectivePath = url.pathname.replace(/^\/v2/, '');
    }

    // Platform detection
    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    platform = sortedPlatforms.find(key => {
      const expectedPrefix = `/${key.replace('-', '/')}/`;
      return effectivePath.startsWith(expectedPrefix);
    }) || effectivePath.split('/')[1];

    if (!platform || !config.PLATFORMS[platform]) {
      return Response.redirect('https://github.com/xixu-me/Xget', 302);
    }

    // Transform URL based on platform
    const targetPath = transformPath(effectivePath, platform);
    const finalTargetPath = platform.startsWith('cr-') ? `/v2${targetPath}` : targetPath;
    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle Docker authentication
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(`${config.PLATFORMS[platform]}/v2/`);
      const resp = await fetch(newUrl.toString(), { method: 'GET', redirect: 'follow' });
      
      if (resp.status !== 401) return resp;
      
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (!authenticateStr) return resp;
      
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope');
      
      // 关键修复：处理 Docker Hub 官方镜像的 scope
      if (platform === 'cr-docker' && scope) {
        // 解析 scope 格式：repository:<repo>:<action>
        const [type, repo, action] = scope.split(':');
        
        // 如果是官方镜像（没有命名空间），添加 library/ 前缀
        if (type === 'repository' && !repo.includes('/')) {
          scope = `repository:library/${repo}:${action}`;
        }
      }
      
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    const isGit = isGitRequest(request, url);
    const isAI = isAIInferenceRequest(request, url);

    // Check cache first (skip for Git, Docker, AI)
    let response;
    if (!isGit && !isDocker && !isAI) {
      // @ts-ignore - Cloudflare Workers cache API
      const cache = caches.default;
      const cacheKey = new Request(targetUrl, request);
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

    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }

    const requestHeaders = fetchOptions.headers;

    // Set appropriate headers
    if (isGit || isDocker || isAI) {
      for (const [key, value] of request.headers.entries()) {
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }

      if (isGit && request.method === 'POST') {
        if (url.pathname.endsWith('/git-upload-pack') && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
        if (url.pathname.endsWith('/git-receive-pack') && !requestHeaders.has('Content-Type')) {
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
          minify: { javascript: true, css: true, html: true },
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

    // Implement retry mechanism
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark(`attempt_${attempts}`);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        const finalFetchOptions = {
          ...fetchOptions,
          signal: controller.signal
        };

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

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }

        // Special handling for Docker authentication
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge');
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);
              let scope = '';
              const pathParts = url.pathname.split('/');
              
              // Docker Hub specific handling
              if (platform === 'cr-docker') {
                if (pathParts.length >= 6 && pathParts[1] === 'v2' && pathParts[2] === 'cr' && pathParts[3] === 'docker') {
                  const repoParts = pathParts.slice(4, -2);
                  if (repoParts.length > 0) {
                    let repoName = repoParts.join('/');
                    // Handle official image shorthand
                    if (!repoName.includes('/') && !repoName.includes(':')) {
                      repoName = `library/${repoName}`;
                    }
                    scope = `repository:${repoName}:pull`;
                  }
                }
              } else {
                // Other container registries
                if (pathParts.length >= 4 && pathParts[1] === 'v2') {
                  const repoPath = pathParts.slice(4).join('/');
                  const repoParts = repoPath.split('/');
                  if (repoParts.length >= 1) {
                    const repoName = repoParts.slice(0, -2).join('/');
                    if (repoName) {
                      scope = `repository:${repoName}:pull`;
                    }
                  }
                }
              }

              if (!scope) {
                scope = 'repository:library/hello-world:pull';
              }

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
                    monitor.mark('success');
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
        if (error.name === 'AbortError') {
          return createErrorResponse('Request timeout', 408);
        }
        if (attempts >= config.MAX_RETRIES) {
          return createErrorResponse(
            `Failed after ${config.MAX_RETRIES} attempts: ${error.message}`,
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

    // Handle URL rewriting for different platforms
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

    if (!isGit && !isDocker) {
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

    // Cache successful responses
    if (!isGit && !isDocker && !isAI && ['GET', 'HEAD'].includes(request.method) && 
        response.ok && response.status === 200) {
      const rangeHeader = request.headers.get('Range');
      const cacheKey = rangeHeader
        ? new Request(targetUrl, {
            method: request.method,
            headers: new Headers(
              [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
            )
          })
        : new Request(targetUrl, request);

      ctx.waitUntil(caches.default.put(cacheKey, finalResponse.clone()));
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI
      ? finalResponse
      : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    return createErrorResponse(`Internal Server Error: ${error.message}`, 500, true);
  }
}

/**
 * Adds performance metrics to response headers
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