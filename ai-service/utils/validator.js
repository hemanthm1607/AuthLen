/**
 * ai-service/utils/validator.js — Response Validation & Normalization Utility
 * Ensures AI outputs conform strictly to the required structured schema.
 */

/**
 * Safely extracts JSON candidate string from raw LLM output without fragile regex.
 * Handles:
 * 1. Direct JSON (starts with [ or { and ends with ] or })
 * 2. Markdown code fences with optional language tag (```json or ```) and arbitrary text before/after
 * 3. Outermost structural boundaries [ ... ] or { ... }
 *
 * @param {string} rawText
 * @returns {string}
 */
function extractJsonCandidate(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return '';
  }

  const trimmed = rawText.trim();
  if (!trimmed) {
    return '';
  }

  // 1. Direct match: already properly framed JSON
  if (
    (trimmed.startsWith('[') && trimmed.endsWith(']')) ||
    (trimmed.startsWith('{') && trimmed.endsWith('}'))
  ) {
    return trimmed;
  }

  // 2. Markdown fence extraction (find first opening fence and matching closing fence)
  const firstFence = trimmed.indexOf('```');
  if (firstFence !== -1) {
    const newlineAfterFence = trimmed.indexOf('\n', firstFence);
    if (newlineAfterFence !== -1) {
      const closingFence = trimmed.lastIndexOf('```');
      if (closingFence > newlineAfterFence) {
        const candidate = trimmed.slice(newlineAfterFence + 1, closingFence).trim();
        if (candidate) {
          return candidate;
        }
      }
    }
  }

  // 3. Structural bracket scanning: find outermost matching delimiters
  const firstBracket = trimmed.indexOf('[');
  const lastBracket = trimmed.lastIndexOf(']');
  if (firstBracket !== -1 && lastBracket > firstBracket) {
    return trimmed.slice(firstBracket, lastBracket + 1);
  }

  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    return trimmed.slice(firstBrace, lastBrace + 1);
  }

  return trimmed;
}

/**
 * Extracts and parses JSON from raw LLM text
 * @param {string} rawText
 * @returns {Array<Object>}
 */
function parseJsonFromText(rawText) {
  if (!rawText || typeof rawText !== 'string' || !rawText.trim()) {
    const err = new Error('Empty response received from AI provider.');
    err.code = 'AI_EMPTY_RESPONSE';
    err.status = 502;
    throw err;
  }

  const candidate = extractJsonCandidate(rawText);

  let parsed;
  try {
    parsed = JSON.parse(candidate);
  } catch (err) {
    const isTruncated =
      err.message.includes('Unterminated') ||
      err.message.includes('Unexpected end of JSON') ||
      err.message.includes('position');

    const parseErr = new Error(`Failed to parse AI JSON response: ${err.message}`);
    parseErr.code = isTruncated ? 'AI_RESPONSE_TRUNCATED' : 'AI_JSON_PARSE_FAILED';
    parseErr.status = 502;
    parseErr.isTruncated = isTruncated;
    parseErr.originalMessage = err.message;
    throw parseErr;
  }

  // Unwrap recommendations if packaged in an object
  let recommendations = null;
  if (Array.isArray(parsed)) {
    recommendations = parsed;
  } else if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.recommendations)) {
      recommendations = parsed.recommendations;
    } else if (Array.isArray(parsed.findings)) {
      recommendations = parsed.findings;
    } else if (Array.isArray(parsed.items)) {
      recommendations = parsed.items;
    }
  }

  if (!recommendations) {
    const err = new Error('AI response was not a valid recommendations array.');
    err.code = 'AI_INVALID_SCHEMA';
    err.status = 502;
    throw err;
  }

  return recommendations;
}

/**
 * Validates and normalizes each recommendation object against expected schema
 * @param {Array<Object>} recommendations
 * @param {Array<Object>} originalFindings
 * @param {Object} [options]
 * @returns {Array<Object>}
 */
function validateRecommendations(recommendations, originalFindings = [], options = {}) {
  if (!Array.isArray(recommendations)) {
    const err = new Error('Recommendations must be an array.');
    err.code = 'AI_INVALID_SCHEMA';
    err.status = 502;
    throw err;
  }

  const requireFields = options.requireFields !== false;
  const validFindingIds = new Set(originalFindings.map((f) => f.id));

  return recommendations.map((rec, index) => {
    if (!rec || typeof rec !== 'object') {
      const err = new Error(`Recommendation at index ${index} must be an object.`);
      err.code = 'AI_INVALID_SCHEMA';
      err.status = 502;
      throw err;
    }

    // Strict validation of required core fields
    if (requireFields) {
      if (!rec.problemSummary && !rec.summary) {
        const err = new Error(`Recommendation at index ${index} is missing required field: "problemSummary".`);
        err.code = 'AI_MISSING_REQUIRED_FIELD';
        err.field = 'problemSummary';
        err.status = 502;
        throw err;
      }
      if (!rec.recommendedFix && !rec.recommendation) {
        const err = new Error(`Recommendation at index ${index} is missing required field: "recommendedFix".`);
        err.code = 'AI_MISSING_REQUIRED_FIELD';
        err.field = 'recommendedFix';
        err.status = 502;
        throw err;
      }
    }

    const findingId = rec.findingId || (originalFindings[index] ? originalFindings[index].id : `FINDING-${index + 1}`);
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
  extractJsonCandidate,
  parseJsonFromText,
  validateRecommendations,
};
