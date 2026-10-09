/**
 * testing-engine/index.js — AuthLens Testing Engine Orchestrator
 * Coordinates security, usability, accessibility, and account recovery auditing modules.
 */
const { validateTargetUrl } = require('./utils/targetValidator');
const securityRunner  = require('./security');
const usabilityRunner = require('./usability');
const a11yRunner      = require('./accessibility');
const recoveryRunner  = require('./recovery');

/**
 * Executes full authentication audit against the authorized target
 * @param {Object} options
 * @param {string} options.targetUrl - URL to audit
 * @param {boolean} options.isAuthorized - User confirmation of authorization
 */
async function runAllTests(options = {}) {
  const opts = typeof options === 'string' ? { targetUrl: options, isAuthorized: true } : (options || {});
  const { targetUrl = 'http://localhost:4000', isAuthorized = true } = opts;

  const targetValidation = validateTargetUrl(targetUrl, isAuthorized);
  if (!targetValidation.valid) {
    throw new Error(targetValidation.error);
  }

  const startTime = Date.now();

  // Run modules in parallel with safety boundaries
  const [secFindings, useFindings, a11yFindings, recFindings] = await Promise.all([
    securityRunner.run(targetValidation).catch((err) => [{
      id: 'SEC-ERR',
      title: 'Security module execution error',
      category: 'Security',
      severity: 'Medium',
      status: 'NEEDS_REVIEW',
      evidence: err.message,
      risk: 'Module failed to execute.',
      recommendation: 'Check server logs.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    }]),
    usabilityRunner.run(targetValidation).catch((err) => [{
      id: 'USE-ERR',
      title: 'Usability module execution error',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: err.message,
      risk: 'Module failed to execute.',
      recommendation: 'Check server logs.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    }]),
    a11yRunner.run(targetValidation).catch((err) => [{
      id: 'A11Y-ERR',
      title: 'Accessibility module execution error',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: err.message,
      risk: 'Module failed to execute.',
      recommendation: 'Check server logs.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    }]),
    recoveryRunner.run(targetValidation).catch((err) => [{
      id: 'REC-ERR',
      title: 'Account recovery module execution error',
      category: 'Account Recovery',
      severity: 'Medium',
      status: 'NEEDS_REVIEW',
      evidence: err.message,
      risk: 'Module failed to execute.',
      recommendation: 'Check server logs.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    }]),
  ]);

  const allFindings = [
    ...secFindings,
    ...useFindings,
    ...a11yFindings,
    ...recFindings,
  ];

  const durationMs = Date.now() - startTime;
  const duration = `${(durationMs / 1000).toFixed(1)}s`;

  // Compute severity statistics for findings with FAIL or NEEDS_REVIEW
  const failedFindings = allFindings.filter((f) => f.status === 'FAIL');
  const summary = {
    total: allFindings.length,
    passed: allFindings.filter((f) => f.status === 'PASS').length,
    failed: failedFindings.length,
    needsReview: allFindings.filter((f) => f.status === 'NEEDS_REVIEW').length,
    notApplicable: allFindings.filter((f) => f.status === 'NOT_APPLICABLE').length,
    critical: failedFindings.filter((f) => f.severity.toLowerCase() === 'critical').length,
    high: failedFindings.filter((f) => f.severity.toLowerCase() === 'high').length,
    medium: failedFindings.filter((f) => f.severity.toLowerCase() === 'medium').length,
    low: failedFindings.filter((f) => f.severity.toLowerCase() === 'low').length,
  };

  // Calculate realistic weighted security score (0 to 100)
  // Deductions: Critical: -25, High: -15, Medium: -8, Low: -3
  const deduction =
    summary.critical * 25 +
    summary.high * 15 +
    summary.medium * 8 +
    summary.low * 3;

  const overallScore = Math.max(0, Math.min(100, 100 - deduction));

  // Category score calculations
  function calculateCategoryScore(categoryName) {
    const catFindings = allFindings.filter((f) => f.category === categoryName);
    if (catFindings.length === 0) return 100;
    const catFails = catFindings.filter((f) => f.status === 'FAIL');
    const catDeduction = catFails.reduce((acc, f) => {
      const sev = f.severity.toLowerCase();
      if (sev === 'critical') return acc + 30;
      if (sev === 'high') return acc + 20;
      if (sev === 'medium') return acc + 10;
      return acc + 5;
    }, 0);
    return Math.max(0, Math.min(100, 100 - catDeduction));
  }

  function getCategoryTrend(categoryName) {
    const catFindings = allFindings.filter((f) => f.category === categoryName);
    if (catFindings.length === 0) return 'Not evaluated';
    const catFails = catFindings.filter((f) => f.status === 'FAIL');
    const catReviews = catFindings.filter((f) => f.status === 'NEEDS_REVIEW');
    const catNotApp = catFindings.filter((f) => f.status === 'NOT_APPLICABLE');
    const catPasses = catFindings.filter((f) => f.status === 'PASS');

    if (catFails.some((f) => f.severity.toLowerCase() === 'critical')) {
      return 'Critical vulnerabilities present';
    }
    if (catFails.some((f) => f.severity.toLowerCase() === 'high')) {
      return 'High-risk vulnerabilities detected';
    }
    if (catFails.length > 0) {
      return 'Remediation required';
    }
    if (catPasses.length > 0) {
      return 'Passing core controls';
    }
    if (catReviews.length > 0) {
      return 'Controls require manual review';
    }
    if (catNotApp.length === catFindings.length) {
      return 'Not applicable to target';
    }
    return 'Evaluated against baseline';
  }

  const categoryScores = [
    {
      id: 'security',
      label: 'Security',
      score: calculateCategoryScore('Security'),
      max: 100,
      trend: getCategoryTrend('Security'),
    },
    {
      id: 'usability',
      label: 'Usability',
      score: calculateCategoryScore('Usability'),
      max: 100,
      trend: getCategoryTrend('Usability'),
    },
    {
      id: 'accessibility',
      label: 'Accessibility',
      score: calculateCategoryScore('Accessibility'),
      max: 100,
      trend: getCategoryTrend('Accessibility'),
    },
    {
      id: 'recovery',
      label: 'Account Recovery',
      score: calculateCategoryScore('Account Recovery'),
      max: 100,
      trend: getCategoryTrend('Account Recovery'),
    },
  ];

  return {
    target: targetValidation.url,
    date: new Date().toISOString(),
    duration,
    overallScore,
    categoryScores,
    summary,
    findings: allFindings,
  };
}

module.exports = {
  runAllTests,
};
