/**
 * ai-service/adapters/mockAdapter.js — Deterministic Mock Adapter for Automated Testing
 * Used in unit/integration test suites to verify recommendation formatting,
 * error handling, and frontend rendering without consuming external API quota.
 */

/**
 * Generates synthetic recommendations directly from provided findings
 * @param {string} userPrompt
 * @param {Object} options
 * @returns {Promise<string>}
 */
async function generate(userPrompt, options = {}) {
  // If simulated failure requested for test assertions
  if (options.simulateError) {
    throw new Error('Simulated upstream AI provider failure.');
  }

  if (options.simulateTimeout) {
    const err = new Error('The operation was aborted due to timeout.');
    err.name = 'TimeoutError';
    throw err;
  }

  if (options.simulateMalformed) {
    return '{"incomplete_json": true,';
  }

  const findings = options.findings || [];

  const recommendations = findings.map((f) => ({
    findingId: f.id || 'FINDING',
    problemSummary: `Remediation required for ${f.title || 'observed authentication issue'}`,
    whyItMatters: f.risk || 'Poses risk to authentication integrity.',
    recommendedFix: f.recommendation || 'Apply standard security controls and test verification.',
    codePatch: (f.codeBefore && f.codeAfter) ? {
      file: f.targetFile || f.target_file || null,
      before: f.codeBefore,
      after: f.codeAfter,
    } : null,
    affectedComponents: [f.category || 'Security'],
    potentialSideEffects: 'Verify that legitimate traffic from proxies is not inadvertently restricted.',
    verificationSteps: [
      `Execute ${f.id} test probe against target and verify status transition.`,
      'Review server logs to confirm no unhandled exceptions are thrown.',
    ],
    confidenceLevel: 'High',
    manualReviewRequired: true,
  }));

  return JSON.stringify(recommendations);
}

module.exports = {
  name: 'mock',
  defaultModel: 'mock-v1',
  generate,
};
