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
  headers.set('Permissions-Policy', 'interest-cohort=()");
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
