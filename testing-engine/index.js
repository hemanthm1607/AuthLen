/**
 * testing-engine/index.js — AuthLens Testing Engine Orchestrator
 * Coordinates security, usability, accessibility, and account recovery auditing modules.
 */
const { validateTargetUrl, checkTargetReachability } = require('./utils/targetValidator');
const {
  calculateSummary,
  calculateOverallScore,
  calculateCategoryScores,
} = require('./utils/scoring');
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

  // Pre-flight reachability validation: ensure target is online before running checks
  const reachability = await checkTargetReachability(targetValidation.url);
  if (!reachability.reachable) {
    throw new Error(`Target is unreachable at ${targetValidation.url} (${reachability.error || 'Connection refused'}). Please verify that the target service is online.`);
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

  // Compute standardized statistics, overall score, and category scorecards
  const summary = calculateSummary(allFindings);
  const overallScore = calculateOverallScore(allFindings);
  const categoryScores = calculateCategoryScores(allFindings);

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
  calculateSummary,
  calculateOverallScore,
  calculateCategoryScores,
};
