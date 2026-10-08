/**
 * ai-service/adapters/geminiAdapter.js — Google Gemini REST API Adapter
 * =========================================================================
 * Directly calls the Gemini v1beta REST API using Node.js native fetch.
 * Implements:
 * - Precise error categorization (rate-limits vs. quota exhaustion vs. auth vs. server failures)
 * - Bounded retries with exponential backoff and jitter for retryable errors only
 * - Respect for Retry-After headers
 * - Fast-fail for non-retryable errors (quota exhaustion, invalid API keys, billing)
 * - Safe request timeouts
 * - Zero API key exposure in logs or errors
 */

const { SYSTEM_INSTRUCTION } = require('../utils/promptBuilder');

const SUPPORTED_DEFAULT_MODEL = 'gemini-3.5-flash';
const DEFAULT_TIMEOUT_MS = 20000; // 20s per-request timeout
const DEFAULT_MAX_RETRIES = 2;    // Max 2 retries (3 total attempts)
const DEFAULT_MAX_OUTPUT_TOKENS = 8192; // 8192 output tokens to prevent truncated JSON responses

// Known decommissioned/unsupported models on Gemini v1beta generateContent endpoint
const DEPRECATED_MODELS = [
  'gemini-2.5-flash',
  'gemini-1.5-flash',
  'gemini-1.5-flash-latest',
  'gemini-1.5-pro',
  'gemini-1.0-pro',
];

/**
 * Validates whether the configured model supports application/json output mode
 * @param {string} [modelName]
 * @returns {boolean}
 */
function supportsJsonMode(modelName) {
  if (!modelName || typeof modelName !== 'string') return false;
  const m = modelName.trim().toLowerCase();
  if (m.includes('1.0')) return false; // Gemini 1.0 does not support JSON mode
  return (
    m.includes('1.5') ||
    m.includes('2.0') ||
    m.includes('2.5') ||
    m.includes('3.0') ||
    m.includes('3.5')
  );
}

/**
 * JSON Schema for structured security recommendations
 */
const RECOMMENDATIONS_JSON_SCHEMA = {
  type: 'ARRAY',
  description: 'List of security and accessibility remediation recommendations',
  items: {
    type: 'OBJECT',
    properties: {
      findingId: { type: 'STRING' },
      problemSummary: { type: 'STRING' },
      whyItMatters: { type: 'STRING' },
      recommendedFix: { type: 'STRING' },
      codePatch: {
        type: 'OBJECT',
        properties: {
          file: { type: 'STRING' },
          before: { type: 'STRING' },
          after: { type: 'STRING' },
        },
        required: ['file', 'before', 'after'],
      },
      affectedComponents: {
        type: 'ARRAY',
        items: { type: 'STRING' },
      },
      potentialSideEffects: { type: 'STRING' },
      verificationSteps: {
        type: 'ARRAY',
        items: { type: 'STRING' },
      },
      confidenceLevel: { type: 'STRING', enum: ['High', 'Medium', 'Low'] },
      manualReviewRequired: { type: 'BOOLEAN' },
    },
    required: [
      'findingId',
      'problemSummary',
      'whyItMatters',
      'recommendedFix',
      'codePatch',
      'affectedComponents',
      'potentialSideEffects',
      'verificationSteps',
      'confidenceLevel',
      'manualReviewRequired',
    ],
  },
};

/**
 * Resolves requested model name, falling back to supported default if unset or deprecated
 * @param {string} [requestedModel]
 * @returns {string}
 */
function resolveModelName(requestedModel) {
  const model = (requestedModel || process.env.GEMINI_MODEL || SUPPORTED_DEFAULT_MODEL).trim();
  if (DEPRECATED_MODELS.includes(model)) {
    console.warn(`[GEMINI ADAPTER] Model "${model}" is decommissioned or unsupported on API v1beta. Automatically upgrading to "${SUPPORTED_DEFAULT_MODEL}".`);
    return SUPPORTED_DEFAULT_MODEL;
  }
  return model;
}

/**
 * Classifies an HTTP error from Gemini into structured error categories
 *
 * @param {number} status - HTTP status code
 * @param {string} rawMsg - Message string from body or status
 * @param {Object} [errorJson] - Parsed error object
 * @param {Object|Headers} [headers] - Response headers
 * @returns {Error} Enhanced Error instance with .code, .status, .retryable, .retryAfterSeconds
 */
function classifyGeminiError(status, rawMsg, errorJson = {}, headers = {}) {
  const msg = rawMsg || '';
  const lowerMsg = msg.toLowerCase();
  const errorObj = errorJson.error || errorJson;
  const statusStr = (errorObj.status || '').toLowerCase();
  const reason = (errorObj.details && errorObj.details[0] && errorObj.details[0].reason) || '';

  // 1. Invalid API Key / Unauthorized
  if (
    status === 400 &&
    (lowerMsg.includes('api_key_invalid') || lowerMsg.includes('api key not valid') || lowerMsg.includes('invalid api key'))
  ) {
    const err = new Error('Provided GEMINI_API_KEY is invalid or unauthorized. Please verify your Google AI Studio API key.');
    err.code = 'AI_AUTH_FAILED';
    err.status = 401;
    err.retryable = false;
    return err;
  }

  // 2. Permission Denied / Forbidden
  if (status === 403 || statusStr === 'permission_denied' || reason === 'PERMISSION_DENIED') {
    const err = new Error('Access denied by Gemini API. Please check your API key permissions and Google Cloud project settings.');
    err.code = 'AI_AUTH_FAILED';
    err.status = 403;
    err.retryable = false;
    return err;
  }

  // 3. Billing Related
  if (
    reason === 'BILLING_DISABLED' ||
    reason === 'BILLING_ACCOUNT_NOT_FOUND' ||
    (status === 402 && lowerMsg.includes('billing'))
  ) {
    const err = new Error('Gemini API billing is disabled or account payment issue detected. Please check your Google Cloud billing settings.');
    err.code = 'BILLING_ERROR';
    err.status = 402;
    err.retryable = false;
    return err;
  }

  // 4. Model Not Found / Unavailable
  if (status === 404 || lowerMsg.includes('not found') || lowerMsg.includes('not supported for generatecontent') || lowerMsg.includes('no longer available')) {
    const err = new Error(`Configured Gemini model is not found or unsupported for generateContent on API v1beta. Supported model: "${SUPPORTED_DEFAULT_MODEL}".`);
    err.code = 'MODEL_UNAVAILABLE';
    err.status = 404;
    err.retryable = false;
    return err;
  }

  // 5. Rate Limits vs. Quota Exhaustion (429 or RESOURCE_EXHAUSTED)
  if (status === 429 || statusStr === 'resource_exhausted' || reason === 'RESOURCE_EXHAUSTED' || reason === 'QUOTA_EXCEEDED' || lowerMsg.includes('quota') || lowerMsg.includes('rate limit')) {
    // Check if it is a transient rate limit (RPM/QPS/burst/temporary)
    const isTransientRateLimit =
      (lowerMsg.includes('rate limit') || lowerMsg.includes('too many requests') || lowerMsg.includes('rpm') || lowerMsg.includes('qps') || lowerMsg.includes('retry-after')) &&
      !lowerMsg.includes('quota metric') &&
      !lowerMsg.includes('quota is exhausted') &&
      !lowerMsg.includes('plan and billing') &&
      !lowerMsg.includes('current quota') &&
      !lowerMsg.includes('per day');

    if (isTransientRateLimit) {
      let retryAfterSeconds = null;
      const rawHeader = headers && (typeof headers.get === 'function' ? headers.get('retry-after') : headers['retry-after']);
      if (rawHeader) {
        const parsedSec = parseInt(rawHeader, 10);
        if (!isNaN(parsedSec) && parsedSec > 0) {
          retryAfterSeconds = parsedSec;
        }
      }

      const err = new Error('Too many AI requests. Please wait and try again.');
      err.code = 'RATE_LIMIT_EXCEEDED';
      err.status = 429;
      err.retryable = true; // Retryable with backoff
      err.retryAfterSeconds = retryAfterSeconds;
      return err;
    }

    // Default 429 / RESOURCE_EXHAUSTED is Quota Exhaustion (plan, daily quota, credit exhaustion)
    const err = new Error('AI usage quota is exhausted. Check your Gemini API quota and billing settings.');
    err.code = 'QUOTA_EXHAUSTED';
    err.status = 429;
    err.retryable = false; // Quota exhaustion must NOT be retried
    return err;
  }

  // 6. Temporary Server Failures (500, 502, 503, 504)
  if (status >= 500 && status <= 599) {
    const err = new Error('The AI service is temporarily unavailable. Please try again later.');
    err.code = 'TEMPORARY_SERVICE_FAILURE';
    err.status = 503;
    err.retryable = true; // Transient server errors can be retried
    return err;
  }

  // 7. Generic Fallback
  const err = new Error(msg || 'An unexpected error occurred while communicating with the Gemini AI service.');
  err.code = 'AI_REQUEST_FAILED';
  err.status = status || 500;
  err.retryable = false;
  return err;
}

/**
 * Calculates exponential backoff delay with jitter
 * @param {number} attempt - Zero-indexed attempt number
 * @param {number|null} retryAfterSeconds - Seconds from Retry-After header
 * @returns {number} Delay in milliseconds
 */
function calculateBackoffDelay(attempt, retryAfterSeconds = null) {
  if (retryAfterSeconds && retryAfterSeconds > 0) {
    // Respect Retry-After header, clamped between 500ms and 8000ms
    return Math.min(Math.max(retryAfterSeconds * 1000, 500), 8000);
  }
  // Exponential backoff: base 1000ms * 2^attempt + jitter (0-400ms), max 5000ms
  const base = 1000 * Math.pow(2, attempt);
  const jitter = Math.floor(Math.random() * 400);
  return Math.min(base + jitter, 5000);
}

/**
 * Sleeps for a given duration
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Executes a structured completion request against Google Gemini with bounded retries
 *
 * @param {string} userPrompt
 * @param {Object} options
 * @returns {Promise<string>} Raw text response
 */
async function generate(userPrompt, options = {}) {
  const apiKey = options.apiKey !== undefined ? options.apiKey : process.env.GEMINI_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    const err = new Error('GEMINI_API_KEY is not configured in backend/.env.');
    err.code = 'AI_PROVIDER_NOT_CONFIGURED';
    err.status = 503;
    throw err;
  }

  const model = resolveModelName(options.model);
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxRetries = options.maxRetries !== undefined ? options.maxRetries : DEFAULT_MAX_RETRIES;

  // Never embed API key in URL query string to prevent leak via URL logs
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  const maxOutputTokens =
    options.maxOutputTokens ||
    parseInt(process.env.GEMINI_MAX_OUTPUT_TOKENS, 10) ||
    DEFAULT_MAX_OUTPUT_TOKENS;

  const generationConfig = {
    temperature: 0.2,
    maxOutputTokens,
  };

  // Explicitly request JSON output mode if supported by the model
  if (supportsJsonMode(model)) {
    generationConfig.response_mime_type = 'application/json';
    if (options.useSchema !== false) {
      generationConfig.response_schema = RECOMMENDATIONS_JSON_SCHEMA;
    }
  } else {
    console.warn(`[GEMINI ADAPTER] Model "${model}" may not support response_mime_type: application/json. Relying on prompt formatting.`);
  }

  const payload = {
    system_instruction: {
      parts: [{ text: SYSTEM_INSTRUCTION }],
    },
    contents: [
      {
        role: 'user',
        parts: [{ text: userPrompt }],
      },
    ],
    generationConfig,
  };

  let lastError = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        let parsedMsg = `HTTP ${response.status} ${response.statusText}`;
        let parsedJson = {};
        try {
          parsedJson = JSON.parse(errorBody);
          if (parsedJson.error && parsedJson.error.message) {
            parsedMsg = parsedJson.error.message;
          }
        } catch (_) {}

        // Categorize the error
        const categorizedError = classifyGeminiError(response.status, parsedMsg, parsedJson, response.headers);

        // If not retryable, or if we have exhausted retries, throw immediately
        if (!categorizedError.retryable || attempt >= maxRetries) {
          throw categorizedError;
        }

        // Bounded retryable backoff
        const delayMs = calculateBackoffDelay(attempt, categorizedError.retryAfterSeconds);
        console.warn(`[GEMINI ADAPTER] ${categorizedError.message} (Attempt ${attempt + 1}/${maxRetries + 1}). Retrying in ${delayMs}ms...`);
        await sleep(delayMs);
        lastError = categorizedError;
        continue;
      }

      const data = await response.json();

      // Check prompt feedback for upstream safety blocks
      if (data.promptFeedback && data.promptFeedback.blockReason) {
        const blockErr = new Error(`Gemini request was blocked by safety policy (${data.promptFeedback.blockReason}).`);
        blockErr.code = 'AI_RESPONSE_BLOCKED';
        blockErr.status = 400;
        blockErr.finishReason = data.promptFeedback.blockReason;
        blockErr.retryable = false;
        throw blockErr;
      }

      const candidate = data.candidates && data.candidates[0];
      if (!candidate) {
        throw new Error('Gemini API returned no completion candidates.');
      }

      // Check finishReason for token limits or safety interruptions
      const finishReason = candidate.finishReason;
      if (finishReason === 'MAX_TOKENS') {
        const truncErr = new Error('Gemini response was truncated due to output token limit (finishReason: MAX_TOKENS). Incomplete JSON cannot be processed safely.');
        truncErr.code = 'AI_RESPONSE_TRUNCATED';
        truncErr.status = 502;
        truncErr.finishReason = 'MAX_TOKENS';
        truncErr.retryable = false;
        throw truncErr;
      }

      if (['SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT', 'SPII'].includes(finishReason)) {
        const safetyErr = new Error(`Gemini response was blocked by safety policy (finishReason: ${finishReason}).`);
        safetyErr.code = 'AI_RESPONSE_BLOCKED';
        safetyErr.status = 400;
        safetyErr.finishReason = finishReason;
        safetyErr.retryable = false;
        throw safetyErr;
      }

      if (!candidate.content || !candidate.content.parts || !candidate.content.parts[0] || !candidate.content.parts[0].text) {
        throw new Error('Gemini API returned an empty or blocked completion response.');
      }

      return candidate.content.parts[0].text;
    } catch (err) {
      // Abort / Timeout handling
      if (err.name === 'TimeoutError' || (err.message && err.message.toLowerCase().includes('timeout'))) {
        const timeoutErr = new Error('AI provider request timed out. Please try again.');
        timeoutErr.code = 'AI_TIMEOUT';
        timeoutErr.status = 504;
        timeoutErr.retryable = false;
        throw timeoutErr;
      }

      // If already a categorized error
      if (err.code) {
        if (!err.retryable || attempt >= maxRetries) {
          throw err;
        }
        const delayMs = calculateBackoffDelay(attempt, err.retryAfterSeconds);
        await sleep(delayMs);
        lastError = err;
        continue;
      }

      // Transient network failure (e.g. connection reset)
      if (attempt < maxRetries) {
        const delayMs = calculateBackoffDelay(attempt);
        console.warn(`[GEMINI ADAPTER] Network error: ${err.message}. Retrying in ${delayMs}ms...`);
        await sleep(delayMs);
        lastError = err;
        continue;
      }

      // Max retries exceeded
      const finalErr = new Error('The AI service is temporarily unavailable. Please try again later.');
      finalErr.code = 'TEMPORARY_SERVICE_FAILURE';
      finalErr.status = 503;
      throw finalErr;
    }
  }

  throw lastError || new Error('The AI service is temporarily unavailable. Please try again later.');
}

module.exports = {
  name: 'gemini',
  get defaultModel() {
    return resolveModelName(process.env.GEMINI_MODEL);
  },
  resolveModelName,
  supportsJsonMode,
  SUPPORTED_DEFAULT_MODEL,
  DEFAULT_MAX_OUTPUT_TOKENS,
  RECOMMENDATIONS_JSON_SCHEMA,
  classifyGeminiError,
  calculateBackoffDelay,
  generate,
};
