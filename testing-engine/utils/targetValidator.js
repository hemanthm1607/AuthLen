/**
 * utils/targetValidator.js — Safety and Authorization Validator for Testing Engine
 * Strict safety rules:
 * - Only permits localhost, 127.0.0.1, or explicitly authorized staging domains
 * - Enforces request limits and strict timeouts
 * - Masks sensitive credentials from evidence logs
 */
const http = require('http');
const https = require('https');

const ALLOWED_LOCALHOST_PATTERNS = [
  /^localhost(:[0-9]+)?$/i,
  /^127\.0\.0\.1(:[0-9]+)?$/,
  /^\[::1\](:[0-9]+)?$/,
  /^[a-z0-9-]+\.local(:[0-9]+)?$/i,
];

function validateTargetUrl(rawUrl, isExplicitlyAuthorized = false) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'Target URL is required.' };
  }

  let parsed;
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl);
    parsed = new URL(hasScheme ? rawUrl : `http://${rawUrl}`);
  } catch (err) {
    return { valid: false, error: 'Malformed target URL provided.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Target URL must use HTTP or HTTPS protocol.' };
  }

  const isLocal = ALLOWED_LOCALHOST_PATTERNS.some((pattern) => pattern.test(parsed.host));

  if (!isLocal && !isExplicitlyAuthorized) {
    return {
      valid: false,
      error: 'Safety restriction: Only localhost and explicitly authorized environments can be audited.',
      isLocal: false,
    };
  }

  // Preserve path and search parameters accurately
  const normalizedPath = (parsed.pathname && parsed.pathname !== '/')
    ? parsed.pathname.replace(/\/+$/, '')
    : '';
  const search = parsed.search || '';
  const fullUrl = `${parsed.origin}${normalizedPath}${search}`;

  return {
    valid: true,
    url: fullUrl || parsed.origin,
    origin: parsed.origin,
    protocol: parsed.protocol,
    host: parsed.host,
    hostname: parsed.hostname,
    port: parsed.port,
    pathname: parsed.pathname || '/',
    search: parsed.search || '',
    isLocal,
  };
}

/**
 * Safe HTTP request helper with timeout and automatic cleanup
 */
async function safeFetch(url, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeout || 4000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const startTime = Date.now();
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'AuthLens-Security-Engine/1.0 (Authorized Audit)',
        'Accept': 'application/json, text/html, */*',
        ...(options.headers || {}),
      },
    });
    const duration = Date.now() - startTime;
    clearTimeout(timeoutId);

    const headersObj = {};
    response.headers.forEach((val, key) => {
      headersObj[key.toLowerCase()] = val;
    });

    const text = await response.text().catch(() => '');

    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      // Non-JSON response
    }

    return {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      headers: headersObj,
      rawHeaders: response.headers,
      duration,
      text,
      json,
    };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      return { error: 'Request timed out (safety abort triggered)', timedOut: true };
    }
    return { error: err.message, failed: true };
  }
}

/**
 * Redact any potential credentials from evidence strings
 */
function sanitizeEvidence(text) {
  if (!text) return '';
  return String(text)
    .replace(/(password|passwd|pwd|token|secret)=([^&;\s]+)/gi, '$1=[REDACTED]')
    .replace(/("password"|"secret"|"token"):\s*"[^"]+"/gi, '$1:"[REDACTED]"');
}

module.exports = {
  validateTargetUrl,
  safeFetch,
  sanitizeEvidence,
};
