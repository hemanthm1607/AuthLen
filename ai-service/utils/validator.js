/**
 * ai-service/utils/validator.js — Response Validation & Normalization Utility
 * Ensures AI outputs conform strictly to the required structured schema.
 */

/**
 * Extracts and parses JSON from raw LLM text
 * @param {string} rawText
 * @returns {Array<Object>}
 */
function parseJsonFromText(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    throw new Error('Empty response received from AI provider.');
  }

  // Strip markdown code block fences if present
  let cleaned = rawText.trim();
  if (cleaned.startsWith('```json')) {
    cleaned = cleaned.slice(7);
  } else if (cleaned.startsWith('```')) {
    cleaned = cleaned.slice(3);
  }

  if (cleaned.endsWith('```')) {
    cleaned = cleaned.slice(0, -3);
  }
  cleaned = cleaned.trim();

  try {
    const parsed = JSON.parse(cleaned);
    // If wrapped in an object e.g. { recommendations: [...] }, unwrap
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.recommendations)) return parsed.recommendations;
    if (parsed && Array.isArray(parsed.findings)) return parsed.findings;
    throw new Error('AI response was not a valid recommendations array.');
  } catch (err) {
    throw new Error(`Failed to parse AI JSON response: ${err.message}`);
  }
}

/**
 * Validates and normalizes each recommendation object
 * @param {Array<Object>} recommendations
 * @param {Array<Object>} originalFindings
 * @returns {Array<Object>}
 */
function validateRecommendations(recommendations, originalFindings = []) {
  if (!Array.isArray(recommendations)) {
    throw new Error('Recommendations must be an array.');
  }

  const validFindingIds = new Set(originalFindings.map((f) => f.id));

  return recommendations.map((rec, index) => {
    const findingId = rec.findingId || (originalFindings[index] ? originalFindings[index].id : `FINDING-${index + 1}`);

    // If findingId does not match any finding in the assessment, flag it
    const isKnownFinding = validFindingIds.size === 0 || validFindingIds.has(findingId);

    const codePatch = rec.codePatch || {};

    return {
      findingId,
      isVerifiedFinding: isKnownFinding,
      problemSummary: typeof rec.problemSummary === 'string' ? rec.problemSummary : (rec.summary || 'Vulnerability remediation needed'),
      whyItMatters: typeof rec.whyItMatters === 'string' ? rec.whyItMatters : (rec.risk || 'Poses risk to authentication integrity'),
      recommendedFix: typeof rec.recommendedFix === 'string' ? rec.recommendedFix : (rec.recommendation || 'Apply standard security controls'),
      codePatch: {
        file: typeof codePatch.file === 'string' ? codePatch.file : 'backend/server.js',
        before: typeof codePatch.before === 'string' ? codePatch.before : null,
        after: typeof codePatch.after === 'string' ? codePatch.after : null,
      },
      affectedComponents: Array.isArray(rec.affectedComponents) ? rec.affectedComponents : ['Authentication Router'],
      potentialSideEffects: typeof rec.potentialSideEffects === 'string' ? rec.potentialSideEffects : 'Review changes in a staging environment prior to production.',
      verificationSteps: Array.isArray(rec.verificationSteps) && rec.verificationSteps.length > 0
        ? rec.verificationSteps
        : ['Verify behavior against authorized test target before deployment.'],
      confidenceLevel: ['High', 'Medium', 'Low'].includes(rec.confidenceLevel) ? rec.confidenceLevel : 'Medium',
      manualReviewRequired: typeof rec.manualReviewRequired === 'boolean' ? rec.manualReviewRequired : true,
    };
  });
}

module.exports = {
  parseJsonFromText,
  validateRecommendations,
};
