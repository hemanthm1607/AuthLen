/**
 * ai-service/adapters/groqAdapter.js — Groq Cloud REST API Adapter
 * =========================================================================
 * Directly calls Groq's OpenAI-compatible completions API using native fetch.
 * Implements:
 * - Ultra-low latency GPT-OSS-120B inference
 * - Explicit JSON mode (response_format: { type: "json_object" })
 * - Token ceiling and finish_reason inspection
 * - Precise error categorization (401 auth, 429 rate-limit, 5xx temporary server failures, timeouts)
 * - Zero API key exposure in logs or errors
 */

const { SYSTEM_INSTRUCTION } = require('../utils/promptBuilder');

const DEFAULT_MODEL = 'openai/gpt-oss-120b';
const DEFAULT_TIMEOUT_MS = 20000;
const DEFAULT_MAX_TOKENS = 8000;

/**
 * Classifies an HTTP error from Groq into structured error categories
 * @param {number} status - HTTP status code
 * @param {string} rawMsg - Message string from body or status
 * @param {Object} [errorJson] - Parsed error object
 * @param {Object|Headers} [headers] - Response headers
 * @returns {Error} Enhanced Error instance with .code, .status, .retryAfterSeconds
 */
function classifyGroqError(status, rawMsg, errorJson = {}, headers = {}) {
  const msg = rawMsg || '';
  const lowerMsg = msg.toLowerCase();

  // 1. Invalid API Key / Unauthorized
  if (status === 401 || lowerMsg.includes('invalid api key') || lowerMsg.includes('unauthorized')) {
    const err = new Error('Provided GROQ_API_KEY is invalid or unauthorized. Please verify your Groq Cloud API key.');
    err.code = 'AI_AUTH_FAILED';
    err.status = 401;
    err.retryable = false;
    return err;
  }

  // 2. Permission Denied / Forbidden
  if (status === 403 || lowerMsg.includes('permission_denied') || lowerMsg.includes('forbidden')) {
    const err = new Error('Access denied by Groq API. Please check your API key permissions and project settings.');
    err.code = 'AI_AUTH_FAILED';
    err.status = 403;
    err.retryable = false;
    return err;
  }

  // 3. Rate Limits
  if (status === 429 || lowerMsg.includes('rate limit') || lowerMsg.includes('too many requests')) {
    let retryAfterSeconds = null;
    const rawHeader = headers && (typeof headers.get === 'function' ? headers.get('retry-after') : headers['retry-after']);
    if (rawHeader) {
      const parsedSec = parseInt(rawHeader, 10);
      if (!isNaN(parsedSec) && parsedSec > 0) {
        retryAfterSeconds = parsedSec;
      }
    }

    const err = new Error('Too many AI requests to Groq. Please wait and try again.');
    err.code = 'RATE_LIMIT_EXCEEDED';
    err.status = 429;
    err.retryable = true;
    err.retryAfterSeconds = retryAfterSeconds;
    return err;
  }

  // 4. Model Not Found / Unsupported
  if (status === 404 || lowerMsg.includes('model not found') || lowerMsg.includes('does not exist')) {
    const err = new Error(`Configured Groq model is not found or unsupported. Default model: "${DEFAULT_MODEL}".`);
    err.code = 'MODEL_UNAVAILABLE';
    err.status = 404;
    err.retryable = false;
    return err;
  }

  // 5. Temporary Server Failures (500, 502, 503, 504)
  if (status >= 500 && status <= 599) {
    const err = new Error('The Groq AI service is temporarily unavailable. Please try again later.');
    err.code = 'TEMPORARY_SERVICE_FAILURE';
    err.status = 503;
    err.retryable = true;
    return err;
  }

  // 6. Generic Fallback
  const err = new Error(msg || 'An unexpected error occurred while communicating with the Groq AI service.');
  err.code = 'AI_REQUEST_FAILED';
  err.status = status || 500;
  err.retryable = false;
  return err;
}

/**
 * Executes a structured completion request against Groq
 * @param {string} userPrompt
 * @param {Object} [options]
 * @returns {Promise<string>}
 */
async function generate(userPrompt, options = {}) {
  const apiKey = options.apiKey !== undefined ? options.apiKey : process.env.GROQ_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    const err = new Error('GROQ_API_KEY is not configured in backend/.env.');
    err.code = 'AI_PROVIDER_NOT_CONFIGURED';
    err.status = 503;
    throw err;
  }

  const model = (options.model || process.env.GROQ_MODEL || DEFAULT_MODEL).trim();
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxTokens = options.maxTokens || parseInt(process.env.GROQ_MAX_TOKENS, 10) || DEFAULT_MAX_TOKENS;

  const url = 'https://api.groq.com/openai/v1/chat/completions';

  const payload = {
    model,
    messages: [
      { role: 'system', content: SYSTEM_INSTRUCTION },
      { role: 'user', content: userPrompt },
    ],
    response_format: { type: 'json_object' },
    temperature: 0.2,
    max_tokens: maxTokens,
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
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

      const categorizedError = classifyGroqError(response.status, parsedMsg, parsedJson, response.headers);
      throw categorizedError;
    }

    const data = await response.json();
    const choice = data.choices && data.choices[0];
    if (!choice || !choice.message || !choice.message.content) {
      throw new Error('Groq API returned an empty completion response.');
    }

    // Inspect finish reason for token truncation
    if (choice.finish_reason === 'length') {
      const truncErr = new Error('Groq response was truncated due to output token limit (finish_reason: length). Incomplete JSON cannot be processed safely.');
      truncErr.code = 'AI_RESPONSE_TRUNCATED';
      truncErr.status = 502;
      truncErr.finishReason = 'length';
      truncErr.retryable = false;
      throw truncErr;
    }

    return choice.message.content;
  } catch (err) {
    if (err.name === 'TimeoutError' || (err.message && err.message.toLowerCase().includes('timeout'))) {
      const timeoutErr = new Error('Groq AI provider request timed out. Please try again.');
      timeoutErr.code = 'AI_TIMEOUT';
      timeoutErr.status = 504;
      timeoutErr.retryable = false;
      throw timeoutErr;
    }

    // Rethrow already categorized errors
    throw err;
  }
}

module.exports = {
  name: 'groq',
  get defaultModel() {
    return process.env.GROQ_MODEL || DEFAULT_MODEL;
  },
  DEFAULT_MODEL,
  DEFAULT_MAX_TOKENS,
  classifyGroqError,
  generate,
};
