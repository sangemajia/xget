import { CONFIG, createConfig } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * 性能监控类，用于记录请求处理过程中的时间指标
 */
class PerformanceMonitor {
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * 记录一个时间点
   * @param {string} name - 时间点名称
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`时间点 "${name}" 已存在`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * 获取所有性能指标
   * @returns {Object} 包含所有时间点的对象
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * 判断是否为 Docker 容器注册表请求
 * @param {Request} request - 请求对象
 * @param {URL} url - 解析后的 URL 对象
 * @returns {boolean} 是否为 Docker 请求
 */
function isDockerRequest(request, url) {
  // 检查是否为 Docker Registry API v2 端点
  if (url.pathname.startsWith('/v2/')) return true;

  // 检查 Docker 客户端特有的 User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) return true;

  // 检查 Docker 客户端特有的 Accept 头
  const accept = request.headers.get('Accept') || '';
  return (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  );
}

/**
 * 判断是否为 Git 操作请求
 * @param {Request} request - 请求对象
 * @param {URL} url - 解析后的 URL 对象
 * @returns {boolean} 是否为 Git 请求
 */
function isGitRequest(request, url) {
  // 检查 Git 特有的端点
  if (url.pathname.endsWith('/info/refs')) return true;
  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) return true;

  // 检查 Git 特有的 User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) return true;

  // 检查 Git 特有的查询参数
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }

  // 检查 Git 特有的 Content-Type
  const contentType = request.headers.get('Content-Type') || '';
  return contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack');
}

/**
 * 判断是否为 AI 推理请求
 * @param {Request} request - 请求对象
 * @param {URL} url - 解析后的 URL 对象
 * @returns {boolean} 是否为 AI 请求
 */
function isAIInferenceRequest(request, url) {
  // 检查 AI 推理特有的路径前缀
  if (url.pathname.startsWith('/ip/')) return true;

  // 检查常见的 AI 推理 API 端点
  const aiEndpoints = [
    '/v1/chat/completions', '/v1/completions', '/v1/messages',
    '/v1/predictions', '/v1/generate', '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];
  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) return true;

  // 检查 AI 特有的 Content-Type 和请求方法
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
 * 验证请求的合法性
 * @param {Request} request - 请求对象
 * @param {URL} url - 解析后的 URL 对象
 * @param {import('./config/index.js').ApplicationConfig} config - 应用配置
 * @returns {{valid: boolean, error?: string, status?: number}} 验证结果
 */
function validateRequest(request, url, config = CONFIG) {
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  // 允许的方法：安全方法 + Git/Docker/AI 扩展方法
  const allowedMethods = isGit || isDocker || isAI
    ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
    : config.SECURITY.ALLOWED_METHODS;

  // 检查请求方法是否合法
  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  // 检查路径长度是否合法
  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * 创建标准化错误响应
 * @param {string} message - 错误信息
 * @param {number} status - HTTP 状态码
 * @param {boolean} includeDetails - 是否包含详细错误信息
 * @returns {Response} 错误响应对象
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
 * 为响应添加安全头部
 * @param {Headers} headers - 原始响应头
 * @returns {Headers} 添加安全头部后的响应头
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
 * 解析 Docker 的 WWW-Authenticate 头部
 * @param {string} authenticateStr - WWW-Authenticate 头部值
 * @returns {{realm: string, service: string}} 解析后的认证信息
 */
function parseAuthenticate(authenticateStr) {
  // 正则匹配 Bearer realm="..." 和 service="..."
  const re = /Bearer realm="([^"]+)",\s*service="([^"]+)"/;
  const match = authenticateStr.match(re);
  if (!match || match.length < 3) {
    throw new Error(`无效的 Www-Authenticate 头部: ${authenticateStr}`);
  }
  return {
    realm: match[1],
    service: match[2]
  };
}

/**
 * 从容器注册表获取认证令牌
 * @param {{realm: string, service: string}} wwwAuthenticate - 解析后的认证信息
 * @param {string} scope - 认证范围
 * @param {string} authorization - 原始请求的 Authorization 头部值
 * @returns {Promise<Response>} 获取令牌的响应
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
 * 创建容器注册表未授权响应
 * @param {URL} url - 请求的 URL 对象
 * @returns {Response} 未授权响应
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
 * 处理请求的核心逻辑（缓存、重试、安全等）
 * @param {Request} request - 请求对象
 * @param {Object} env - 环境变量
 * @param {ExecutionContext} ctx - Cloudflare Workers 执行上下文
 * @returns {Promise<Response>} 最终响应对象
 */
async function handleRequest(request, env, ctx) {
  try {
    // 初始化配置（环境变量覆盖默认配置）
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);
    const monitor = new PerformanceMonitor();

    // 处理 Docker API 版本检查（/v2/ 端点）
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    // 重定向根路径到 GitHub 仓库
    if (url.pathname === '/' || url.pathname === '') {
      return Response.redirect('https://github.com/xixu-me/Xget', 302);
    }

    // 验证请求合法性
    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // 解析目标平台和路径
    let platform;
    let effectivePath = url.pathname;

    // 处理容器注册表路径（去除 /v2 前缀）
    if (isDocker) {
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return createErrorResponse('容器注册表请求必须使用 /cr/ 前缀', 400);
      }
      effectivePath = url.pathname.replace(/^\/v2/, ''); // 转换为 /cr/docker/alpine/...
    }

    // 检测目标平台（按路径长度倒序匹配，优先更具体的路径）
    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    platform = sortedPlatforms.find(key => {
      const expectedPrefix = `/${key.replace('-', '/')}/`;
      return effectivePath.startsWith(expectedPrefix);
    }) || effectivePath.split('/')[1]; // 备用：取路径第一段作为平台

    // 验证平台是否存在
    if (!platform || !config.PLATFORMS[platform]) {
      return Response.redirect('https://github.com/xixu-me/Xget', 302);
    }

    // 转换路径为目标平台的格式
    const targetPath = transformPath(effectivePath, platform);
    const finalTargetPath = platform.startsWith('cr-') ? `/v2${targetPath}` : targetPath; // 容器注册表添加 /v2 前缀
    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`; // 拼接完整目标 URL
    const authorization = request.headers.get('Authorization'); // 原始请求的认证头

    // 处理 Docker 认证（/v2/auth 端点）
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(`${config.PLATFORMS[platform]}/v2/`);
      const resp = await fetch(newUrl.toString(), { method: 'GET', redirect: 'follow' });

      if (resp.status !== 401) return resp; // 非 401 响应直接返回

      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (!authenticateStr) return resp; // 无认证头直接返回

      // 解析认证信息并获取令牌
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope'); // 从请求参数中获取 scope

      // 特殊处理 Docker Hub 官方镜像的 scope（自动添加 library/ 前缀）
      if (platform === 'cr-docker' && scope) {
        const [type, repo, action] = scope.split(':');
        if (type === 'repository' && !repo.includes('/')) {
          scope = `repository:library/${repo}:${action}`; // 官方镜像添加 library/ 前缀
        }
      }

      // 获取令牌（优先使用空认证头获取公共令牌）
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // 检测是否为 Git 或 AI 请求
    const isGit = isGitRequest(request, url);
    const isAI = isAIInferenceRequest(request, url);

    // 缓存处理（跳过 Git/Docker/AI 请求）
    let response;
    if (!isGit && !isDocker && !isAI) {
      // @ts-ignore - Cloudflare Workers 内置缓存 API
      const cache = caches.default;
      const cacheKey = new Request(targetUrl, request); // 构造缓存键（包含请求方法和头部）

      // 尝试命中缓存
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }

      // 处理 Range 请求的缓存（先尝试完整内容缓存）
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const fullContentKey = new Request(targetUrl, {
          method: request.method,
          headers: new Headers(
            [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range') // 移除 Range 头
          )
        });
        response = await cache.match(fullContentKey);
        if (response) {
          monitor.mark('cache_hit_full_content');
          return response;
        }
      }
    }

    // 构造请求选项
    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow' // 跟随重定向
    };

    // 处理 POST/PUT/PATCH 请求体（仅 Git/Docker/AI 需要）
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }

    // 构造请求头
    const requestHeaders = fetchOptions.headers;

    // Git/Docker/AI 请求：复制原始请求头（避免协议破坏）
    if (isGit || isDocker || isAI) {
      for (const [key, value] of request.headers.entries()) {
        // 跳过可能干扰代理的头部
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      // 设置 Git 特有头部
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1'); // Git 客户端默认 UA
      }

      // 设置 Git 上传/接收包的 Content-Type
      if (isGit && request.method === 'POST') {
        if (url.pathname.endsWith('/git-upload-pack') && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
        if (url.pathname.endsWith('/git-receive-pack') && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-receive-pack-request');
        }
      }

      // 设置 AI 推理请求头部
      if (isAI) {
        if (request.method === 'POST' && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/json'); // AI API 通常使用 JSON
        }
        if (!requestHeaders.has('User-Agent')) {
          requestHeaders.set('User-Agent', 'Xget-AI-Proxy/1.0'); // 自定义 AI 代理 UA
        }
      }
    } else {
      // 普通文件下载请求：设置优化头部
      Object.assign(fetchOptions, {
        cf: {
          http3: true, // 启用 HTTP/3
          cacheTtl: config.CACHE_DURATION, // 缓存 TTL（秒）
          cacheEverything: true, // 缓存所有内容
          minify: { // 压缩资源
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true // 预连接优化
        }
      });

      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br'); // 支持压缩
      requestHeaders.set('Connection', 'keep-alive'); // 保持长连接
      requestHeaders.set('User-Agent', 'Wget/1.21.3'); // 默认 UA
      requestHeaders.set('Origin', request.headers.get('Origin') || '*'); // 允许跨域

      // 处理 Range 请求和媒体文件的压缩
      const rangeHeader = request.headers.get('Range');
      const isMediaFile = targetUrl.match(
        /\.(mp4|avi|mkv|mov|wmv|flv|webm|mp3|wav|flac|aac|ogg|jpg|jpeg|png|gif|bmp|svg|pdf|zip|rar|7z|tar|gz|bz2|xz)$/i
      );

      if (isMediaFile || rangeHeader) {
        requestHeaders.set('Accept-Encoding', 'identity'); // 媒体文件不压缩
      }

      if (rangeHeader) {
        requestHeaders.set('Range', rangeHeader); // 传递 Range 头
      }
    }

    // 实现重试机制（最多 MAX_RETRIES 次）
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark(`attempt_${attempts}`); // 记录尝试次数

        // 设置超时（使用 AbortController）
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        // 构造最终请求选项（包含信号和头部）
        const finalFetchOptions = {
          ...fetchOptions,
          signal: controller.signal
        };

        // 处理 HEAD 请求（确保获取 Content-Length）
        if (request.method === 'HEAD') {
          response = await fetch(targetUrl, finalFetchOptions);

          // 如果 HEAD 响应缺少 Content-Length，重试 GET 请求获取
          if (response.ok && !response.headers.get('Content-Length')) {
            const getResponse = await fetch(targetUrl, {
              ...finalFetchOptions,
              method: 'GET'
            });

            if (getResponse.ok) {
              // 从 GET 响应中复制 Content-Length 到 HEAD 响应
              const headHeaders = new Headers(response.headers);
              const contentLength = getResponse.headers.get('Content-Length');
              if (contentLength) {
                headHeaders.set('Content-Length', contentLength);
              } else {
                // 若 GET 响应仍无 Content-Length，读取 body 计算长度
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
          response = await fetch(targetUrl, finalFetchOptions); // 普通请求
        }

        clearTimeout(timeoutId); // 清除超时计时器

        // 检查响应状态（200 或 206 视为成功）
        if (response.ok || response.status === 206) {
          monitor.mark('success'); // 记录成功
          break; // 退出重试循环
        }

        // 处理 Docker 认证失败（401 状态码）
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge'); // 记录认证挑战

          // 尝试获取公共令牌（无认证头）
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);
              let scope = '';

              // 推断 Docker Hub 的认证范围（处理官方镜像）
              const pathParts = url.pathname.split('/');
              if (pathParts.length >= 6 && 
                  pathParts[1] === 'v2' && 
                  pathParts[2] === 'cr' && 
                  pathParts[3] === 'docker') {
                const repoParts = pathParts.slice(4, -2); // 提取仓库路径（如 alpine）
                if (repoParts.length > 0) {
                  let repoName = repoParts.join('/');
                  // 官方镜像添加 library/ 前缀
                  if (!repoName.includes('/') && !repoName.includes(':')) {
                    repoName = `library/${repoName}`;
                  }
                  scope = `repository:${repoName}:pull`; // 正确的认证范围
                }
              }

              // 若无法推断范围，使用默认公共仓库
              if (!scope) {
                scope = 'repository:library/hello-world:pull';
              }

              // 获取公共令牌
              const tokenResponse = await fetchToken(wwwAuthenticate, scope, '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  // 使用令牌重试原始请求
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);
                  const retryResponse = await fetch(targetUrl, {
                    ...finalFetchOptions,
                    headers: retryHeaders
                  });

                  if (retryResponse.ok) {
                    response = retryResponse; // 重试成功
                    monitor.mark('success');
                    break;
                  }
                }
              }
            } catch (error) {
              console.log('获取令牌失败:', error); // 记录错误日志
            }
          }

          // 无法获取令牌，返回未授权响应
          return responseUnauthorized(url);
        }

        // 客户端错误（4xx）无需重试
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }

        // 服务端错误（5xx）或重定向（3xx）重试
        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error.name === 'AbortError') {
          return createErrorResponse('请求超时', 408); // 超时错误
        }
        if (attempts >= config.MAX_RETRIES) {
          return createErrorResponse(
            `重试 ${config.MAX_RETRIES} 次后失败: ${error.message}`,
            500,
            true
          ); // 最终失败
        }
        // 等待后重试
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    // 检查最终响应是否有效
    if (!response) {
      return createErrorResponse('所有重试尝试均失败', 500, true);
    }

    if (!response.ok && response.status !== 206) {
      // Docker 认证失败的特殊处理
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return createErrorResponse(
          `需要认证才能访问此资源（可能是私有仓库）。原始错误: ${errorText}`,
          401,
          true
        );
      }
      // 其他服务端错误
      const errorText = await response.text().catch(() => '未知错误');
      return createErrorResponse(
        `上游服务器错误 (${response.status}): ${errorText}`,
        response.status,
        true
      );
    }

    // 处理响应体（如 URL 重写）
    let responseBody = response.body;

    // PyPI 简单索引 URL 重写（files.pythonhosted.org → 自身）
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

    // npm 注册表 URL 重写（registry.npmjs.org → 自身）
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

    // 构造最终响应头
    const headers = new Headers(response.headers);

    // 非 Git/Docker 请求添加安全头和缓存控制
    if (!isGit && !isDocker) {
      headers.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff'); // 防止 MIME 类型嗅探
      headers.set('Accept-Ranges', 'bytes'); // 支持 Range 请求
      addSecurityHeaders(headers); // 添加安全头
    }

    // 构造最终响应对象
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers
    });

    // 缓存成功响应（仅 GET/HEAD 请求，200 状态码）
    if (!isGit && !isDocker && !isAI && 
        ['GET', 'HEAD'].includes(request.method) && 
        response.ok && 
        response.status === 200) {
      const rangeHeader = request.headers.get('Range');
      const cacheKey = rangeHeader
        ? new Request(targetUrl, {
            method: request.method,
            headers: new Headers(
              [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
            )
          })
        : new Request(targetUrl, request);

      ctx.waitUntil(caches.default.put(cacheKey, finalResponse.clone())); // 异步缓存
    }

    monitor.mark('complete'); // 记录处理完成
    return isGit || isDocker || isAI
      ? finalResponse // Git/Docker/AI 直接返回响应
      : addPerformanceHeaders(finalResponse, monitor); // 普通请求添加性能头
  } catch (error) {
    console.error('处理请求时发生错误:', error); // 记录严重错误
    return createErrorResponse(`内部服务器错误: ${error.message}`, 500, true);
  }
}

/**
 * 为普通响应添加性能指标头
 * @param {Response} response - 原始响应对象
 * @param {PerformanceMonitor} monitor - 性能监控实例
 * @returns {Response} 添加性能头后的响应对象
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

// 导出 Cloudflare Worker 入口
export default {
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};