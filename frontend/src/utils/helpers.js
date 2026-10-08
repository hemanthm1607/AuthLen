/**
 * helpers.js — Pure utility functions for AuthLens UI
 */

/** Return a CSS class suffix for a severity string */
export function severityClass(severity) {
  const map = {
    critical: 'critical',
    high:     'high',
    medium:   'medium',
    low:      'low',
    info:     'info',
    pass:     'pass',
    fail:     'fail',
  };
  return map[severity?.toLowerCase()] ?? 'info';
}

/** Convert a 0–100 score to a human-readable grade */
export function scoreGrade(score) {
  if (score >= 90) return { grade: 'A', label: 'Excellent' };
  if (score >= 75) return { grade: 'B', label: 'Good' };
  if (score >= 60) return { grade: 'C', label: 'Fair' };
  if (score >= 45) return { grade: 'D', label: 'Poor' };
  return { grade: 'F', label: 'Critical' };
}

/** Get a semantic colour token based on score */
export function scoreColor(score) {
  if (score >= 80) return 'var(--success)';
  if (score >= 60) return 'var(--sev-medium)';
  if (score >= 40) return 'var(--sev-high)';
  return 'var(--sev-critical)';
}

/** Format ISO date string to readable form */
export function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

/** Capitalize first letter */
export function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/** SVG arc path for a progress ring */
export function ringPath(radius, percent) {
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percent / 100) * circumference;
  return { circumference, offset };
}

/**
 * Format error for the AI Security Advisor interface
 * Distinguishes rate limits, quota exhaustion, temporary server failures, and timeouts.
 *
 * @param {Error|Object} err
 * @returns {string} User-friendly error message
 */
export function formatAiAdvisorError(err) {
  if (!err) return 'An unexpected error occurred while communicating with the AI service.';

  const errorData = err.data || {};
  const code = errorData.code || err.code || '';
  const rawMsg = err.message || errorData.error || '';
  const lowerMsg = rawMsg.toLowerCase();

  if (code === 'RATE_LIMIT_EXCEEDED' || lowerMsg.includes('too many ai requests') || (lowerMsg.includes('rate limit') && !lowerMsg.includes('quota'))) {
    return 'Too many AI requests. Please wait and try again.';
  }

  if (code === 'QUOTA_EXHAUSTED' || lowerMsg.includes('quota is exhausted') || lowerMsg.includes('exceeded your current quota') || lowerMsg.includes('quota exceeded') || lowerMsg.includes('check your plan and billing')) {
    return 'AI usage quota is exhausted. Check your Gemini API quota and billing settings.';
  }

  if (code === 'TEMPORARY_SERVICE_FAILURE' || code === 'AI_TIMEOUT' || err.status === 503 || err.status === 504 || lowerMsg.includes('temporarily unavailable') || lowerMsg.includes('timed out') || lowerMsg.includes('timeout')) {
    return 'The AI service is temporarily unavailable. Please try again later.';
  }

  if (code === 'AI_AUTH_FAILED' || err.status === 401 || err.status === 403) {
    return errorData.error || rawMsg || 'AI authentication failed. Please verify API key configuration.';
  }

  if (
    code === 'AI_RESPONSE_TRUNCATED' ||
    code === 'AI_JSON_PARSE_FAILED' ||
    code === 'AI_MISSING_REQUIRED_FIELD' ||
    code === 'AI_INVALID_SCHEMA' ||
    lowerMsg.includes('failed to parse ai json') ||
    lowerMsg.includes('unterminated string') ||
    lowerMsg.includes('truncated')
  ) {
    return 'The AI service returned an incomplete response. Please try again.';
  }

  return errorData.error || rawMsg || 'The AI service is temporarily unavailable. Please try again later.';
}

