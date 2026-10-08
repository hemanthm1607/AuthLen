/**
 * ai-service/adapters/openaiAdapter.js — OpenAI Chat Completions REST Adapter
 * Directly calls OpenAI API using Node.js native fetch.
 */

const { SYSTEM_INSTRUCTION } = require('../utils/promptBuilder');

const DEFAULT_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const DEFAULT_TIMEOUT_MS = 20000;

/**
 * Executes a structured completion request against OpenAI
 * @param {string} userPrompt
 * @param {Object} options
 * @returns {Promise<string>}
 */
async function generate(userPrompt, options = {}) {
  const apiKey = options.apiKey || process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error('OPENAI_API_KEY is not configured in backend/.env.');
  }

  const model = options.model || DEFAULT_MODEL;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  const url = 'https://api.openai.com/v1/chat/completions';

  const payload = {
    model,
    messages: [
      { role: 'system', content: SYSTEM_INSTRUCTION },
      { role: 'user', content: userPrompt },
    ],
    response_format: { type: 'json_object' },
    temperature: 0.2,
  };

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
    try {
      const parsed = JSON.parse(errorBody);
      if (parsed.error && parsed.error.message) {
        parsedMsg = parsed.error.message;
      }
    } catch (_) {}

    if (response.status === 401) {
      throw new Error('Provided OPENAI_API_KEY is invalid or unauthorized.');
    }
    throw new Error(`OpenAI API error: ${parsedMsg}`);
  }

  const data = await response.json();
  const choice = data.choices && data.choices[0];
  if (!choice || !choice.message || !choice.message.content) {
    throw new Error('OpenAI API returned an empty completion response.');
  }

  return choice.message.content;
}

module.exports = {
  name: 'openai',
  defaultModel: DEFAULT_MODEL,
  generate,
};
