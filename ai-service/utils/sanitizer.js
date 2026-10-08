/**
 * ai-service/utils/sanitizer.js — Data Sanitization & Redaction Utility
 * Ensures secrets, tokens, passwords, session identifiers, and PII are redacted
 * before assessment findings are passed to LLM models.
 */

// Regex patterns for sensitive credentials and tokens
const SENSITIVE_PATTERNS = [
  // Passwords in JSON, headers, or query params (quoted or unquoted)
  { regex: /(?:"?(?:password|passwd|pwd|secret|token|apiKey|access_token)"?)\s*[:=]\s*"?[^"\s,;}]+"?/gi, replacement: '"[REDACTED_CREDENTIAL]"' },
  // Bearer tokens and JWTs
  { regex: /Bearer\s+([a-zA-Z0-9_\-\.]+)/gi, replacement: 'Bearer [REDACTED_TOKEN]' },
  { regex: /eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+/g, replacement: '[REDACTED_JWT]' },
  // Session IDs & Cookies
  { regex: /(connect\.sid|authlens_session|session_id|session)=[a-zA-Z0-9%\-_]+/gi, replacement: '$1=[REDACTED_SESSION_ID]' },
  // Email addresses (preserve domain for context, redact local-part if personal)
  { regex: /([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/g, replacement: '[user_redacted]@$2' },
  // Hex reset tokens (32+ chars)
  { regex: /[a-fA-F0-9]{32,64}/g, replacement: '[REDACTED_HEX_TOKEN]' },
];

/**
 * Sanitizes arbitrary text string
 * @param {string} text
 * @returns {string}
 */
function sanitizeString(text) {
  if (typeof text !== 'string') return '';
  let sanitized = text;
  for (const { regex, replacement } of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(regex, replacement);
  }
  return sanitized;
}

/**
 * Sanitizes an array of findings for model consumption
 * @param {Array<Object>} findings
 * @returns {Array<Object>}
 */
function sanitizeFindings(findings) {
  if (!Array.isArray(findings)) return [];

  return findings.map((f) => ({
    id: f.id || 'FINDING',
    title: sanitizeString(f.title || ''),
    category: f.category || 'Security',
    severity: f.severity || 'Medium',
    status: f.status || 'FAIL',
    evidence: sanitizeString(f.evidence || ''),
    risk: sanitizeString(f.risk || ''),
    recommendation: sanitizeString(f.recommendation || ''),
    codeBefore: f.codeBefore ? sanitizeString(f.codeBefore) : null,
    codeAfter: f.codeAfter ? sanitizeString(f.codeAfter) : null,
    isAutomated: Boolean(f.isAutomated),
  }));
}

module.exports = {
  sanitizeString,
  sanitizeFindings,
};
