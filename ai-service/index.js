/**
 * ai-service/index.js — AuthLens AI Recommendations Service
 * Provider-agnostic orchestrator synthesizing contextual vulnerability
 * remediation patches from actual assessment findings.
 */

const path = require('path');
const fs = require('fs');

// Ensure environment variables from backend/.env are loaded even when ai-service is loaded standalone from root
try {
  let dotenvLoaded = false;
  try {
    const dotenv = require('dotenv');
    dotenv.config({ path: path.resolve(__dirname, '../backend/.env') });
    dotenvLoaded = true;
  } catch (_) {
    try {
      const dotenvPath = require.resolve('dotenv', { paths: [path.resolve(__dirname, '../backend')] });
      const dotenv = require(dotenvPath);
      dotenv.config({ path: path.resolve(__dirname, '../backend/.env') });
      dotenvLoaded = true;
    } catch (_) {}
  }

  // Pure fallback parser if dotenv package cannot be resolved from this location
  if (!dotenvLoaded) {
    const envPath = path.resolve(__dirname, '../backend/.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      content.split(/\r?\n/).forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx !== -1) {
          const key = trimmed.slice(0, eqIdx).trim();
          let val = trimmed.slice(eqIdx + 1).trim();
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          if (key && !(key in process.env)) {
            process.env[key] = val;
          }
        }
      });
    }
  }
} catch (_) {}

const { sanitizeFindings } = require('./utils/sanitizer');
const { buildUserPrompt } = require('./utils/promptBuilder');
const { parseJsonFromText, validateRecommendations } = require('./utils/validator');

const geminiAdapter = require('./adapters/geminiAdapter');
const openaiAdapter = require('./adapters/openaiAdapter');
const mockAdapter   = require('./adapters/mockAdapter');

/**
 * Returns current AI provider configuration status
 * @returns {Object}
 */
function getProviderStatus() {
  const preferred = (process.env.AI_PROVIDER || 'gemini').trim().toLowerCase();

  const hasGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim());
  const hasOpenAI = Boolean(process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.trim());

  let activeProvider = null;
  let activeModel = null;

  if (preferred === 'gemini' && hasGemini) {
    activeProvider = 'gemini';
    activeModel = geminiAdapter.resolveModelName ? geminiAdapter.resolveModelName(process.env.GEMINI_MODEL) : geminiAdapter.defaultModel;
  } else if (preferred === 'openai' && hasOpenAI) {
    activeProvider = 'openai';
    activeModel = process.env.OPENAI_MODEL || openaiAdapter.defaultModel;
  } else if (hasGemini) {
    activeProvider = 'gemini';
    activeModel = geminiAdapter.resolveModelName ? geminiAdapter.resolveModelName(process.env.GEMINI_MODEL) : geminiAdapter.defaultModel;
  } else if (hasOpenAI) {
    activeProvider = 'openai';
    activeModel = process.env.OPENAI_MODEL || openaiAdapter.defaultModel;
  }

  const configured = Boolean(activeProvider);

  return {
    configured,
    provider: activeProvider,
    model: activeModel,
    message: configured
      ? `AI remediation synthesis active using ${activeProvider.toUpperCase()} (${activeModel}).`
      : 'AI provider is not configured. Set GEMINI_API_KEY or OPENAI_API_KEY in backend/.env to generate live recommendations.',
  };
}

/**
 * Generates contextual remediation recommendations from real assessment findings
 * @param {Array<Object>} findings - Actual findings from PostgreSQL
 * @param {Object} context - Assessment context (target, overallScore, date)
 * @param {Object} options - Runtime options (forceAdapter, timeoutMs, apiKey)
 * @returns {Promise<Object>}
 */
async function generateRecommendations(findings = [], context = {}, options = {}) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return {
      recommendations: [],
      provider: null,
      model: null,
      message: 'No findings to analyze for this assessment.',
      generatedAt: new Date().toISOString(),
    };
  }

  // 1. Sanitize findings to strip passwords, tokens, cookies, and sensitive PII
  const sanitized = sanitizeFindings(findings);

  // 2. Select adapter
  const status = getProviderStatus();
  let adapter = null;

  if (options.forceAdapter === 'mock') {
    adapter = mockAdapter;
  } else if (options.forceAdapter === 'gemini') {
    adapter = geminiAdapter;
  } else if (options.forceAdapter === 'openai') {
    adapter = openaiAdapter;
  } else if (status.provider === 'gemini') {
    adapter = geminiAdapter;
  } else if (status.provider === 'openai') {
    adapter = openaiAdapter;
  }

  if (!adapter) {
    const err = new Error(status.message);
    err.code = 'AI_PROVIDER_NOT_CONFIGURED';
    err.status = 503;
    throw err;
  }

  // 3. Compose prompt with strict JSON schema instructions and untrusted data barriers
  const prompt = buildUserPrompt(sanitized, context);

  // 4. Execute completion with safe timeout
  const rawText = await adapter.generate(prompt, {
    ...options,
    findings: sanitized, // Passed to mock adapter if active
  });

  // 5. Parse JSON response
  const rawJson = parseJsonFromText(rawText);

  // 6. Validate and normalize recommendations against schema and original finding IDs
  const validated = validateRecommendations(rawJson, findings);

  return {
    recommendations: validated,
    provider: adapter.name,
    model: options.model || adapter.defaultModel,
    generatedAt: new Date().toISOString(),
    totalAnalyzed: findings.length,
    recommendationsCount: validated.length,
  };
}

module.exports = {
  getProviderStatus,
  generateRecommendations,
  geminiAdapter,
  openaiAdapter,
  mockAdapter,
};
