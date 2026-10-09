/**
 * utils/targetValidator.js — Safety and Authorization Validator for Testing Engine
 * Strict safety rules:
 * - Only permits localhost, 127.0.0.1, or explicitly authorized staging domains
 * - Prohibits link-local and cloud metadata addresses (169.254.169.254, etc.)
 * - Validates redirect targets against SSRF protections
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

const BLOCKED_METADATA_PATTERNS = [
  /^169\.254\./,
  /^metadata\.google\.internal$/i,
  /^100\.100\.100\.200$/,
];

function isBlockedMetadataHost(hostname) {
  if (!hostname) return false;
  return BLOCKED_METADATA_PATTERNS.some((pattern) => pattern.test(hostname));
}

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

  // SSRF Protection: Block cloud metadata and link-local addresses unconditionally
  if (isBlockedMetadataHost(parsed.hostname)) {
    return {
      valid: false,
      error: 'Safety restriction: Link-local and cloud metadata addresses are prohibited.',
      isLocal: false,
    };
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
 * Safe HTTP request helper with timeout, redirect SSRF protection, and automatic cleanup
 */
async function safeFetch(url, options = {}) {
  try {
    const parsed = new URL(url);
    if (isBlockedMetadataHost(parsed.hostname)) {
      return { error: 'Safety restriction: Request to metadata address blocked.', failed: true };
    }
  } catch (err) {
    return { error: `Invalid URL: ${err.message}`, failed: true };
  }

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
        'Accept': 'application/json, text/html, application/xhtml+xml, */*',
        ...(options.headers || {}),
      },
    });
    const duration = Date.now() - startTime;
    clearTimeout(timeoutId);

    // Validate redirect location for SSRF defense
    if (response.redirected && response.url) {
      try {
        const redirectedParsed = new URL(response.url);
        if (isBlockedMetadataHost(redirectedParsed.hostname)) {
          return { error: 'Redirected to prohibited metadata address.', failed: true };
        }
      } catch (_) {}
    }

    const headersObj = {};
    response.headers.forEach((val, key) => {
      headersObj[key.toLowerCase()] = val;
    });

    const locationHeader = response.headers.get('location');
    if (locationHeader) {
      try {
        const resolvedLoc = new URL(locationHeader, url);
        if (isBlockedMetadataHost(resolvedLoc.hostname)) {
          return { error: 'Redirect Location targets prohibited metadata address.', failed: true };
        }
      } catch (_) {}
    }

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
      location: locationHeader,
      url: response.url || url,
      redirected: response.redirected,
      duration,
      text,
      json,
    };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      return { error: 'Request timed out (safety abort triggered)', timedOut: true };
    }
    const causeStr = err.cause ? (err.cause.code || err.cause.message || String(err.cause)) : '';
    const errorMsg = causeStr ? `${err.message} (${causeStr})` : err.message;
    return {
      error: errorMsg,
      failed: true,
      cause: err.cause,
      code: err.cause?.code || err.code,
    };
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

/**
 * Validates whether the target host and port is online and accepting connections.
 * Strictly detects offline targets (ECONNREFUSED, ENOTFOUND) while permitting listening servers (including 4xx/5xx and aborting sockets).
 */
async function checkTargetReachability(url, timeoutMs = 3500) {
  try {
    const res = await safeFetch(url, { timeout: timeoutMs, method: 'GET' });
    const isConnRefused =
      res.code === 'ECONNREFUSED' ||
      res.cause?.code === 'ECONNREFUSED' ||
      res.error?.includes('ECONNREFUSED') ||
      res.code === 'ENOTFOUND' ||
      res.cause?.code === 'ENOTFOUND' ||
      res.error?.includes('ENOTFOUND');

    if (isConnRefused) {
      return { reachable: false, error: 'Connection refused (target host/port is offline).' };
    }
    return { reachable: true, status: res.status };
  } catch (err) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.message?.includes('ECONNREFUSED')) {
      return { reachable: false, error: 'Connection refused (target host/port is offline).' };
    }
    return { reachable: true, status: null };
  }
}

module.exports = {
  validateTargetUrl,
  safeFetch,
  sanitizeEvidence,
  isBlockedMetadataHost,
  checkTargetReachability,
};
