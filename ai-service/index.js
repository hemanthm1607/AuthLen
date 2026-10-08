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
const groqAdapter   = require('./adapters/groqAdapter');
const openaiAdapter = require('./adapters/openaiAdapter');
const mockAdapter   = require('./adapters/mockAdapter');

/**
 * Returns current AI provider configuration status
 * @returns {Object}
 */
function getProviderStatus() {
  const preferred = (process.env.AI_PROVIDER || '').trim().toLowerCase();

  const hasGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim());
  const hasGroq   = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.trim());
  const hasOpenAI = Boolean(process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.trim());

  let activeProvider = null;
  let activeModel = null;

  // 1. Explicit provider preference
  if (preferred === 'groq') {
    if (hasGroq) {
      activeProvider = 'groq';
      activeModel = process.env.GROQ_MODEL || groqAdapter.defaultModel;
    } else {
      // Explicitly requested Groq but GROQ_API_KEY is missing.
      // Must NOT silently fall back to Gemini.
      return {
        configured: false,
        provider: 'groq',
        model: process.env.GROQ_MODEL || groqAdapter.defaultModel,
        message: 'AI provider is set to GROQ but GROQ_API_KEY is not configured in backend/.env.',
      };
    }
  } else if (preferred === 'openai') {
    if (hasOpenAI) {
      activeProvider = 'openai';
      activeModel = process.env.OPENAI_MODEL || openaiAdapter.defaultModel;
    } else {
      return {
        configured: false,
        provider: 'openai',
        model: process.env.OPENAI_MODEL || openaiAdapter.defaultModel,
        message: 'AI provider is set to OPENAI but OPENAI_API_KEY is not configured in backend/.env.',
      };
    }
  } else if (preferred === 'gemini') {
    if (hasGemini) {
      activeProvider = 'gemini';
      activeModel = geminiAdapter.resolveModelName ? geminiAdapter.resolveModelName(process.env.GEMINI_MODEL) : geminiAdapter.defaultModel;
    } else {
      return {
        configured: false,
        provider: 'gemini',
        model: geminiAdapter.resolveModelName ? geminiAdapter.resolveModelName(process.env.GEMINI_MODEL) : geminiAdapter.defaultModel,
        message: 'AI provider is set to GEMINI but GEMINI_API_KEY is not configured in backend/.env.',
      };
    }
  } else {
    // 2. Default resolution priority when AI_PROVIDER is unset: Gemini -> Groq -> OpenAI
    if (hasGemini) {
      activeProvider = 'gemini';
      activeModel = geminiAdapter.resolveModelName ? geminiAdapter.resolveModelName(process.env.GEMINI_MODEL) : geminiAdapter.defaultModel;
    } else if (hasGroq) {
      activeProvider = 'groq';
      activeModel = process.env.GROQ_MODEL || groqAdapter.defaultModel;
    } else if (hasOpenAI) {
      activeProvider = 'openai';
      activeModel = process.env.OPENAI_MODEL || openaiAdapter.defaultModel;
    }
  }

  const configured = Boolean(activeProvider);

  return {
    configured,
    provider: activeProvider,
    model: activeModel,
    message: configured
      ? `AI remediation synthesis active using ${activeProvider.toUpperCase()} (${activeModel}).`
      : 'AI provider is not configured. Set GEMINI_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY in backend/.env to generate live recommendations.',
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

  if (options.adapter) {
    adapter = options.adapter;
  } else if (options.forceAdapter === 'mock') {
    adapter = mockAdapter;
  } else if (options.forceAdapter === 'groq') {
    adapter = module.exports.groqAdapter || groqAdapter;
  } else if (options.forceAdapter === 'gemini') {
    adapter = module.exports.geminiAdapter || geminiAdapter;
  } else if (options.forceAdapter === 'openai') {
    adapter = module.exports.openaiAdapter || openaiAdapter;
  } else if (status.provider === 'groq') {
    adapter = module.exports.groqAdapter || groqAdapter;
  } else if (status.provider === 'gemini') {
    adapter = module.exports.geminiAdapter || geminiAdapter;
  } else if (status.provider === 'openai') {
    adapter = module.exports.openaiAdapter || openaiAdapter;
  }

  if (!adapter) {
    const err = new Error(status.message);
    err.code = 'AI_PROVIDER_NOT_CONFIGURED';
    err.status = 503;
    throw err;
  }

  // 3. Compose prompt with strict JSON schema instructions and untrusted data barriers
  const prompt = buildUserPrompt(sanitized, context);

  // 4. Execute completion with bounded recovery retry for malformed/truncated responses
  const maxRecoveryRetries = options.disableRecovery ? 0 : 1;
  let validated = null;
  let lastError = null;

  for (let attempt = 0; attempt <= maxRecoveryRetries; attempt++) {
    const isRecovery = attempt > 0;
    const currentPrompt = isRecovery
      ? `${prompt}

CRITICAL RECOVERY INSTRUCTION:
Your previous response could not be parsed as valid JSON or was truncated.
Please respond ONLY with a complete, syntactically correct JSON array conforming to the specified schema.
Do not include conversational text or truncate the output.`
      : prompt;

    try {
      const rawText = await adapter.generate(currentPrompt, {
        ...options,
        findings: sanitized, // Passed to mock adapter if active
        isRecoveryAttempt: isRecovery,
        maxOutputTokens: options.maxOutputTokens || 8192,
      });

      // 5. Parse JSON response
      const rawJson = parseJsonFromText(rawText);

      // 6. Validate and normalize recommendations against schema and original finding IDs
      validated = validateRecommendations(rawJson, findings, { requireFields: options.requireFields !== false });
      break; // Successfully parsed and validated!
    } catch (err) {
      lastError = err;

      // Fail fast on non-retryable operational errors (quota, auth, rate limit, billing, unconfigured)
      if (
        err.code === 'RATE_LIMIT_EXCEEDED' ||
        err.code === 'QUOTA_EXHAUSTED' ||
        err.code === 'AI_AUTH_FAILED' ||
        err.code === 'BILLING_ERROR' ||
        err.code === 'MODEL_UNAVAILABLE' ||
        err.code === 'AI_TIMEOUT' ||
        err.code === 'AI_PROVIDER_NOT_CONFIGURED' ||
        options.disableRecovery === true
      ) {
        throw err;
      }

      if (attempt >= maxRecoveryRetries) {
        console.error(`[AI SERVICE] Recovery retry limit reached. Final error: ${err.message}`);
        const finalErr = new Error(
          err.code === 'AI_RESPONSE_TRUNCATED'
            ? 'The AI service response was truncated and could not be recovered. Please try with fewer findings.'
            : (err.message || 'Failed to parse AI JSON response after recovery retry.')
        );
        finalErr.code = err.code || 'AI_JSON_PARSE_FAILED';
        finalErr.status = err.status || 502;
        throw finalErr;
      }

      console.warn(`[AI SERVICE] Response malformed or truncated (${err.message}). Executing bounded recovery attempt 1/${maxRecoveryRetries}...`);
    }
  }

  if (!validated) {
    throw lastError || new Error('Failed to obtain valid recommendations from AI service.');
  }

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
  groqAdapter,
  openaiAdapter,
  mockAdapter,
};
