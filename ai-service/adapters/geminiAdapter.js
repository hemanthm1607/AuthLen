/**
 * ai-service/adapters/geminiAdapter.js — Google Gemini REST API Adapter
 * Directly calls the Gemini v1beta REST API using Node.js native fetch.
 * No external third-party SDK dependencies required.
 */

const { SYSTEM_INSTRUCTION } = require('../utils/promptBuilder');

const DEFAULT_MODEL = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
const DEFAULT_TIMEOUT_MS = 20000; // 20s timeout

/**
 * Executes a structured completion request against Google Gemini
 * @param {string} userPrompt
 * @param {Object} options
 * @returns {Promise<string>} Raw text response
 */
async function generate(userPrompt, options = {}) {
  const apiKey = options.apiKey || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in backend/.env.');
  }

  const model = options.model || process.env.GEMINI_MODEL || DEFAULT_MODEL;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

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
    generationConfig: {
      response_mime_type: 'application/json',
      temperature: 0.2,
      maxOutputTokens: 3000,
    },
  };

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
    try {
      const parsed = JSON.parse(errorBody);
      if (parsed.error && parsed.error.message) {
        parsedMsg = parsed.error.message;
      }
    } catch (_) {}

    if (response.status === 400 && (parsedMsg.includes('API_KEY_INVALID') || parsedMsg.toLowerCase().includes('api key not valid'))) {
      throw new Error('Provided GEMINI_API_KEY is invalid or unauthorized. Please verify your Google AI Studio API key.');
    }
    if (response.status === 404 || parsedMsg.includes('not found') || parsedMsg.includes('not supported for generateContent')) {
      throw new Error(`Gemini model "${model}" is not found or unsupported for generateContent on API v1beta. Please use "gemini-3.5-flash".`);
    }
    if (response.status === 429) {
      throw new Error('Gemini API rate limit or quota exceeded. Please try again shortly.');
    }

    throw new Error(`Gemini API error: ${parsedMsg}`);
  }

  const data = await response.json();
  const candidate = data.candidates && data.candidates[0];
  if (!candidate || !candidate.content || !candidate.content.parts || !candidate.content.parts[0]) {
    throw new Error('Gemini API returned an empty or blocked completion response.');
  }

  return candidate.content.parts[0].text;
}

module.exports = {
  name: 'gemini',
  get defaultModel() {
    return process.env.GEMINI_MODEL || DEFAULT_MODEL;
  },
  generate,
};
