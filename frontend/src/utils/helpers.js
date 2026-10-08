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
