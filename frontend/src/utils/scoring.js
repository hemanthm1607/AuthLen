/**
 * scoring.js — Client-Side Standardized Scoring & Category Derivation Engine
 * Matches testing-engine/utils/scoring.js
 */

export const SEVERITY_PENALTIES = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export const CATEGORY_DEFINITIONS = [
  {
    id: 'security',
    label: 'Security',
    matcher: (cat) => cat === 'security',
    defaultDesc: 'Authentication throttling, session tokens, transport encryption',
  },
  {
    id: 'usability',
    label: 'Usability',
    matcher: (cat) => cat === 'usability',
    defaultDesc: 'Password masking toggle, error guidance, session options',
  },
  {
    id: 'accessibility',
    label: 'Accessibility',
    matcher: (cat) => cat === 'accessibility',
    defaultDesc: 'WCAG 2.1 AA compliance, accessible labels, focus & tab order',
  },
  {
    id: 'recovery',
    label: 'Account Recovery',
    matcher: (cat) => cat === 'account recovery' || cat === 'recovery',
    defaultDesc: 'Self-service password reset, enumeration defense, token lifecycle',
  },
];

export function normalizeStatus(status) {
  if (!status) return 'NEEDS_REVIEW';
  const s = String(status).trim().toUpperCase();
  if (s === 'PASS') return 'PASS';
  if (s === 'FAIL') return 'FAIL';
  if (s === 'NOT_APPLICABLE' || s === 'NOT APPLICABLE') return 'NOT_APPLICABLE';
  return 'NEEDS_REVIEW';
}

export function normalizeSeverity(severity) {
  if (!severity) return 'low';
  const s = String(severity).trim().toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

export function calculateSummary(findings = []) {
  const list = Array.isArray(findings) ? findings : [];
  const failedFindings = list.filter((f) => normalizeStatus(f.status) === 'FAIL');

  return {
    total: list.length,
    passed: list.filter((f) => normalizeStatus(f.status) === 'PASS').length,
    failed: failedFindings.length,
    needsReview: list.filter((f) => normalizeStatus(f.status) === 'NEEDS_REVIEW').length,
    notApplicable: list.filter((f) => normalizeStatus(f.status) === 'NOT_APPLICABLE').length,
    critical: failedFindings.filter((f) => normalizeSeverity(f.severity) === 'critical').length,
    high: failedFindings.filter((f) => normalizeSeverity(f.severity) === 'high').length,
    medium: failedFindings.filter((f) => normalizeSeverity(f.severity) === 'medium').length,
    low: failedFindings.filter((f) => normalizeSeverity(f.severity) === 'low').length,
  };
}

export function calculateOverallScore(findings = []) {
  const summary = calculateSummary(findings);
  const deduction =
    summary.critical * SEVERITY_PENALTIES.critical +
    summary.high * SEVERITY_PENALTIES.high +
    summary.medium * SEVERITY_PENALTIES.medium +
    summary.low * SEVERITY_PENALTIES.low;

  return Math.max(0, Math.min(100, 100 - deduction));
}

export function calculateCategoryScores(findings = []) {
  const list = Array.isArray(findings) ? findings : [];

  return CATEGORY_DEFINITIONS.map((def) => {
    const catFindings = list.filter((f) => {
      const rawCat = (f.category || '').trim().toLowerCase();
      return def.matcher(rawCat);
    });

    const total = catFindings.length;
    const fails = catFindings.filter((f) => normalizeStatus(f.status) === 'FAIL');
    const passes = catFindings.filter((f) => normalizeStatus(f.status) === 'PASS');
    const reviews = catFindings.filter((f) => normalizeStatus(f.status) === 'NEEDS_REVIEW');
    const notApps = catFindings.filter((f) => normalizeStatus(f.status) === 'NOT_APPLICABLE');

    // Case 1: No findings recorded in this category
    if (total === 0) {
      return {
        id: def.id,
        label: def.label,
        score: null,
        max: 100,
        statusText: 'Not evaluated',
        hasSufficientData: false,
        isApplicable: false,
        trend: 'Not evaluated',
        description: def.defaultDesc,
        stats: { total: 0, passed: 0, failed: 0, needsReview: 0, notApplicable: 0 },
      };
    }

    // Case 2: All checks in this category are NOT_APPLICABLE
    if (notApps.length === total) {
      return {
        id: def.id,
        label: def.label,
        score: null,
        max: 100,
        statusText: 'Not Applicable',
        hasSufficientData: false,
        isApplicable: false,
        trend: 'Not applicable to target',
        description: 'Target does not implement or expose these controls',
        stats: { total, passed: 0, failed: 0, needsReview: 0, notApplicable: total },
      };
    }

    // Case 3: 0 PASS and 0 FAIL (only NEEDS_REVIEW and/or NOT_APPLICABLE)
    if (passes.length === 0 && fails.length === 0) {
      const statusText = reviews.length > 0 ? 'Insufficient data' : 'Not Applicable';
      const trend = reviews.length > 0 ? 'Controls require manual review' : 'Not applicable to target';
      const desc = reviews.length > 0
        ? `${reviews.length} check${reviews.length === 1 ? '' : 's'} require manual review`
        : 'Controls not applicable to target';

      return {
        id: def.id,
        label: def.label,
        score: null,
        max: 100,
        statusText,
        hasSufficientData: false,
        isApplicable: reviews.length > 0,
        trend,
        description: desc,
        stats: {
          total,
          passed: 0,
          failed: 0,
          needsReview: reviews.length,
          notApplicable: notApps.length,
        },
      };
    }

    // Case 4: Category has applicable evidence (passes > 0 or fails > 0)
    const deduction = fails.reduce((sum, f) => {
      const sev = normalizeSeverity(f.severity);
      return sum + (SEVERITY_PENALTIES[sev] || 0);
    }, 0);

    const score = Math.max(0, Math.min(100, 100 - deduction));

    let statusText = 'Secure';
    if (score < 60) statusText = 'Needs Hardening';
    else if (score < 80) statusText = 'Adequate';

    let trend = 'Passing core controls';
    if (fails.some((f) => normalizeSeverity(f.severity) === 'critical')) {
      trend = 'Critical vulnerabilities present';
    } else if (fails.some((f) => normalizeSeverity(f.severity) === 'high')) {
      trend = 'High-risk vulnerabilities detected';
    } else if (fails.length > 0) {
      trend = 'Remediation required';
    } else if (reviews.length > 0) {
      trend = 'Passing core controls (partial review needed)';
    }

    const descParts = [];
    if (passes.length > 0) descParts.push(`${passes.length} passed`);
    if (fails.length > 0) descParts.push(`${fails.length} failed`);
    if (reviews.length > 0) descParts.push(`${reviews.length} review needed`);
    if (notApps.length > 0) descParts.push(`${notApps.length} n/a`);

    return {
      id: def.id,
      label: def.label,
      score,
      max: 100,
      statusText,
      hasSufficientData: true,
      isApplicable: true,
      trend,
      description: descParts.join(', ') || def.defaultDesc,
      stats: {
        total,
        passed: passes.length,
        failed: fails.length,
        needsReview: reviews.length,
        notApplicable: notApps.length,
      },
    };
  });
}
