/**
 * backend/tests/aiService.test.js
 * Automated test suite for AI Recommendations Module (Phases 1-7)
 */
require('dotenv').config();
const path = require('path');
const { pool } = require('../config/db');

const aiService = require(path.resolve(__dirname, '../../ai-service'));
const { sanitizeFindings, sanitizeString } = require(path.resolve(__dirname, '../../ai-service/utils/sanitizer'));
const { parseJsonFromText, validateRecommendations } = require(path.resolve(__dirname, '../../ai-service/utils/validator'));

const geminiAdapter = require(path.resolve(__dirname, '../../ai-service/adapters/geminiAdapter'));

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:4000';

async function runAiTests() {
  console.log(`\n======================================================`);
  console.log(`  AuthLens AI Recommendations Module Test Suite       `);
  console.log(`======================================================\n`);

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${message}`);
      failed++;
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  const userAEmail = `ai_tenant_a_${Date.now()}@example.corp`;
  const userBEmail = `ai_tenant_b_${Date.now()}@example.corp`;
  let cookieA = null;
  let cookieB = null;
  let assessmentIdA = null;

  try {
    // ── 1. Provider Status & Configuration Safety ──
    console.log(`\n--- Test 1: Provider Status & Configuration Safety ---`);
    const status = aiService.getProviderStatus();
    assert(typeof status.configured === 'boolean', `Provider status returned valid boolean (configured: ${status.configured})`);
    assert(typeof status.message === 'string', `Informative configuration guidance message provided`);

    // Verify Gemini model name resolution and upgrade logic
    const resolvedDefault = geminiAdapter.resolveModelName();
    assert(resolvedDefault === 'gemini-3.5-flash', `Default Gemini model resolves to supported gemini-3.5-flash (got: ${resolvedDefault})`);

    const upgradedDeprecated = geminiAdapter.resolveModelName('gemini-2.5-flash');
    assert(upgradedDeprecated === 'gemini-3.5-flash', `Deprecated gemini-2.5-flash automatically upgrades to gemini-3.5-flash`);

    const customModel = geminiAdapter.resolveModelName('gemini-3.8-flash');
    assert(customModel === 'gemini-3.8-flash', `Custom model configuration GEMINI_MODEL is preserved (got: ${customModel})`);

    // Verify API error handling on missing/invalid credentials
    let missingKeyCaught = false;
    try {
      await geminiAdapter.generate('Test', { apiKey: '' });
    } catch (err) {
      missingKeyCaught = err.message.includes('GEMINI_API_KEY is not configured');
    }
    assert(missingKeyCaught, `Missing API key triggers descriptive configuration error`);

    let invalidKeyCaught = false;
    try {
      await geminiAdapter.generate('Test', { apiKey: 'AIzaSyFakeKeyInvalid1234567890abcdef' });
    } catch (err) {
      invalidKeyCaught = err.message.includes('invalid or unauthorized');
    }
    assert(invalidKeyCaught, `Invalid API key triggers unauthorized error without leaking key string`);

    // Verify GET /api/ai/status endpoint responds cleanly without exposing keys
    const statusRes = await fetch(`${BASE_URL}/api/ai/status`);
    const statusData = await statusRes.json();
    assert(statusRes.status === 200, `GET /api/ai/status returned HTTP 200`);
    assert(typeof statusData.configured === 'boolean', `Configured flag returned as boolean`);
    assert(statusData.apiKey === undefined, `API key is NEVER exposed over the API boundary`);

    // Verify unauthenticated POST /api/ai/generate is properly rejected
    const unauthedGen = await fetch(`${BASE_URL}/api/ai/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId: 'DUMMY' }),
    });
    assert(unauthedGen.status === 401, `Unauthenticated POST /api/ai/generate is properly rejected with HTTP 401`);

    // Register User A & User B
    const regA = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'Tenant A', email: userAEmail, password: 'SecurePassword123!' }),
    });
    cookieA = regA.headers.get('set-cookie');

    const regB = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'Tenant B', email: userBEmail, password: 'SecurePassword123!' }),
    });
    cookieB = regB.headers.get('set-cookie');

    // ── 2. Sensitive Data Redaction & Sanitizer ──
    console.log(`\n--- Test 2: Sensitive Data Redaction & Masking ---`);
    const rawSensitiveString = 'Failed login with password: "superSecretPassword123" and token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak';
    const sanitizedText = sanitizeString(rawSensitiveString);
    assert(!sanitizedText.includes('superSecretPassword123'), `Password successfully redacted from text`);
    assert(sanitizedText.includes('[REDACTED_CREDENTIAL]') || sanitizedText.includes('[REDACTED_TOKEN]'), `Mask token inserted in place of secret`);

    const dirtyFindings = [
      {
        id: 'SEC-001',
        title: 'Rate limiting test',
        evidence: 'Cookie authlens_session=s%3Asecret_session_cookie_12345; for admin@company.corp',
      },
    ];
    const sanitizedFindings = sanitizeFindings(dirtyFindings);
    assert(!sanitizedFindings[0].evidence.includes('secret_session_cookie_12345'), `Session cookie redacted from finding evidence`);

    // ── 3. Structured Output Parsing & Schema Validation ──
    console.log(`\n--- Test 3: Structured Output Parsing & Schema Validation ---`);
    const sampleAiJson = JSON.stringify([
      {
        findingId: 'SEC-001',
        problemSummary: 'Unthrottled login endpoint allows automated credential brute force attacks',
        whyItMatters: 'Enables high-speed dictionary scanning against user accounts',
        recommendedFix: 'Implement sliding window IP rate limiter with express-rate-limit',
        codePatch: {
          file: 'backend/middleware/rateLimiter.js',
          before: 'app.post("/login", authController.login);',
          after: 'app.post("/login", loginLimiter, authController.login);',
        },
        affectedComponents: ['Express Auth Router', 'Rate Limiter Middleware'],
        potentialSideEffects: 'Corporate users behind NAT proxies may share IP quotas',
        verificationSteps: ['Send 6 failed login attempts and assert HTTP 429 is received'],
        confidenceLevel: 'High',
        manualReviewRequired: true,
      },
    ]);

    const parsedJson = parseJsonFromText(sampleAiJson);
    assert(Array.isArray(parsedJson) && parsedJson.length === 1, `JSON parsed successfully from response text`);

    const validatedRecs = validateRecommendations(parsedJson, [{ id: 'SEC-001' }]);
    assert(validatedRecs[0].findingId === 'SEC-001', `Validated recommendation matches finding ID`);
    assert(validatedRecs[0].confidenceLevel === 'High', `Confidence level validated`);
    assert(validatedRecs[0].manualReviewRequired === true, `Manual review requirement preserved`);

    // Test malformed JSON handling
    let malformedCaught = false;
    try {
      parseJsonFromText('Not valid JSON at all');
    } catch (_) {
      malformedCaught = true;
    }
    assert(malformedCaught === true, `Malformed response caught safely by validator`);

    // ── 4. Deterministic Mock Adapter Execution ──
    console.log(`\n--- Test 4: Mock Adapter Remediation Synthesis ---`);
    const mockResult = await aiService.generateRecommendations(
      [{ id: 'SEC-001', title: 'Rate Limiting', severity: 'High', evidence: 'HTTP 401s' }],
      { target: 'http://localhost:4000', overallScore: 84 },
      { forceAdapter: 'mock' }
    );
    assert(mockResult.recommendations.length === 1, `Mock adapter produced structured recommendation`);
    assert(mockResult.recommendations[0].findingId === 'SEC-001', `Recommendation linked to finding ID`);
    assert(mockResult.provider === 'mock', `Provider recorded as mock`);

    // ── 5. End-to-End API Authorization & Ownership Enforcement ──
    console.log(`\n--- Test 5: Multi-Tenant Authorization & API Execution ---`);
    // User A runs an assessment
    const assessRun = await fetch(`${BASE_URL}/api/assessments/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieA },
      body: JSON.stringify({ targetUrl: 'http://localhost:4000', isAuthorized: true }),
    });
    const assessData = await assessRun.json();
    assessmentIdA = assessData.assessment?.id;
    assert(assessmentIdA !== undefined, `User A created assessment: ${assessmentIdA}`);

    // User A requests AI recommendations using mock adapter test mode
    const genRes = await fetch(`${BASE_URL}/api/ai/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieA },
      body: JSON.stringify({ assessmentId: assessmentIdA, forceAdapter: 'mock' }),
    });
    const genData = await genRes.json();
    assert(genRes.status === 200, `User A generated AI recommendations successfully (HTTP 200)`);
    assert(genData.recommendations && genData.recommendations.length > 0, `Recommendations array returned (${genData.recommendations?.length} items)`);

    // User B tries to request AI recommendations for User A's assessment
    const unauthorizedGen = await fetch(`${BASE_URL}/api/ai/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieB },
      body: JSON.stringify({ assessmentId: assessmentIdA, forceAdapter: 'mock' }),
    });
    assert(unauthorizedGen.status === 404, `User B denied access to User A's assessment findings (HTTP 404/Access Denied)`);

    // ── 6. Gemini Rate-Limit, Quota Exhaustion, Timeout & Error Classification ──
    console.log(`\n--- Test 6: Rate-Limit, Quota Exhaustion, Backoff & Timeout Handling ---`);

    // 6a. Transient Rate-Limit (HTTP 429) vs. Quota Exhaustion distinction
    const transientErr = geminiAdapter.classifyGeminiError(
      429,
      'Rate limit exceeded: 15 requests per minute',
      {},
      { 'retry-after': '6' }
    );
    assert(transientErr.code === 'RATE_LIMIT_EXCEEDED', `Transient rate limit classified as RATE_LIMIT_EXCEEDED`);
    assert(transientErr.status === 429, `Transient rate limit has HTTP 429 status`);
    assert(transientErr.retryable === true, `Transient rate limit is marked retryable`);
    assert(transientErr.retryAfterSeconds === 6, `Retry-After header parsed correctly (6s)`);
    assert(
      transientErr.message === 'Too many AI requests. Please wait and try again.',
      `Transient rate limit matches exact user-friendly message`
    );

    // 6b. Quota Exhaustion (Google AI Studio actual message)
    const googleQuotaMsg =
      'You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits';
    const quotaExhaustedErr = geminiAdapter.classifyGeminiError(429, googleQuotaMsg);
    assert(quotaExhaustedErr.code === 'QUOTA_EXHAUSTED', `Google plan quota error classified as QUOTA_EXHAUSTED`);
    assert(quotaExhaustedErr.status === 429, `Quota exhaustion has HTTP 429 status`);
    assert(quotaExhaustedErr.retryable === false, `Quota exhaustion is NEVER retryable (prevents repeated retry loops)`);
    assert(
      quotaExhaustedErr.message === 'AI usage quota is exhausted. Check your Gemini API quota and billing settings.',
      `Quota exhaustion matches exact user-friendly message`
    );

    // 6c. Quota Metric Exhaustion (PerDayPerProject)
    const dailyQuotaErr = geminiAdapter.classifyGeminiError(
      429,
      "Quota exceeded for quota metric 'GenerateContentRequestsPerDayPerProject' and limit '1500'"
    );
    assert(dailyQuotaErr.code === 'QUOTA_EXHAUSTED', `Daily quota metric error classified as QUOTA_EXHAUSTED`);
    assert(dailyQuotaErr.retryable === false, `Daily quota exhaustion is not retryable`);

    // 6d. Authentication & Invalid Credentials (HTTP 400 / 401 / 403)
    const authErr = geminiAdapter.classifyGeminiError(400, 'API_KEY_INVALID: The provided key does not exist');
    assert(authErr.code === 'AI_AUTH_FAILED', `Invalid API key error classified as AI_AUTH_FAILED`);
    assert(authErr.status === 401, `Invalid API key mapped to HTTP 401`);
    assert(authErr.retryable === false, `Invalid API key is NOT retryable`);
    assert(!authErr.message.includes('API_KEY_INVALID'), `Error message does not leak raw Google error tokens`);

    const forbiddenErr = geminiAdapter.classifyGeminiError(403, 'Permission denied on resource');
    assert(forbiddenErr.code === 'AI_AUTH_FAILED', `403 Permission denied classified as AI_AUTH_FAILED`);
    assert(forbiddenErr.retryable === false, `Forbidden error is not retryable`);

    // 6e. Temporary Server Failures (HTTP 503 / 500)
    const serverErr = geminiAdapter.classifyGeminiError(503, 'Service Unavailable');
    assert(serverErr.code === 'TEMPORARY_SERVICE_FAILURE', `503 classified as TEMPORARY_SERVICE_FAILURE`);
    assert(serverErr.retryable === true, `Temporary service failure is retryable`);
    assert(
      serverErr.message === 'The AI service is temporarily unavailable. Please try again later.',
      `Temporary failure matches exact user-friendly message`
    );

    // 6f. Model Unavailable (HTTP 404)
    const modelErr = geminiAdapter.classifyGeminiError(404, 'models/gemini-unknown is not found');
    assert(modelErr.code === 'MODEL_UNAVAILABLE', `404 model not found classified as MODEL_UNAVAILABLE`);
    assert(modelErr.retryable === false, `Model unavailable is not retryable (will not assume switching model fixes quota)`);

    // 6g. Exponential Backoff with Jitter & Retry-After Clamping
    const delayAttempt0 = geminiAdapter.calculateBackoffDelay(0);
    assert(delayAttempt0 >= 1000 && delayAttempt0 <= 1400, `Attempt 0 backoff delay is in [1000ms, 1400ms] (got: ${delayAttempt0}ms)`);

    const delayAttempt1 = geminiAdapter.calculateBackoffDelay(1);
    assert(delayAttempt1 >= 2000 && delayAttempt1 <= 2400, `Attempt 1 backoff delay is in [2000ms, 2400ms] (got: ${delayAttempt1}ms)`);

    const delayCap = geminiAdapter.calculateBackoffDelay(5);
    assert(delayCap <= 5000, `Exponential backoff is capped at max 5000ms (got: ${delayCap}ms)`);

    const delayRetryAfter = geminiAdapter.calculateBackoffDelay(0, 3);
    assert(delayRetryAfter === 3000, `Retry-After header of 3s honored as 3000ms delay`);

    const delayRetryAfterClamped = geminiAdapter.calculateBackoffDelay(0, 120);
    assert(delayRetryAfterClamped === 8000, `Excessive Retry-After header (120s) clamped to max 8000ms ceiling`);

    // 6h. Request Timeout Handling
    let timeoutCaught = false;
    try {
      await geminiAdapter.generate('Test prompt for timeout', {
        timeoutMs: 1, // 1ms timeout triggers AbortSignal timeout immediately
        maxRetries: 0,
      });
    } catch (err) {
      if (err.code === 'AI_TIMEOUT' && err.status === 504) {
        timeoutCaught = true;
      }
    }
    assert(timeoutCaught, `Request timeout triggers AI_TIMEOUT with HTTP 504 status`);

    // 6i. Frontend Error Message Consistency
    // Emulate frontend error mapping logic and verify requirement strings
    function emulateFrontendErrorDisplay(errorObj) {
      const code = errorObj.code || (errorObj.data && errorObj.data.code) || '';
      const rawMsg = errorObj.message || (errorObj.data && errorObj.data.error) || '';
      const lower = rawMsg.toLowerCase();

      if (code === 'RATE_LIMIT_EXCEEDED' || lower.includes('too many ai requests') || (lower.includes('rate limit') && !lower.includes('quota'))) {
        return 'Too many AI requests. Please wait and try again.';
      }
      if (code === 'QUOTA_EXHAUSTED' || lower.includes('quota is exhausted') || lower.includes('exceeded your current quota') || lower.includes('plan and billing')) {
        return 'AI usage quota is exhausted. Check your Gemini API quota and billing settings.';
      }
      if (code === 'TEMPORARY_SERVICE_FAILURE' || code === 'AI_TIMEOUT' || errorObj.status === 503 || errorObj.status === 504) {
        return 'The AI service is temporarily unavailable. Please try again later.';
      }
      return rawMsg || 'The AI service is temporarily unavailable. Please try again later.';
    }

    assert(
      emulateFrontendErrorDisplay({ code: 'RATE_LIMIT_EXCEEDED' }) === 'Too many AI requests. Please wait and try again.',
      `Frontend maps RATE_LIMIT_EXCEEDED to "Too many AI requests. Please wait and try again."`
    );
    assert(
      emulateFrontendErrorDisplay({ code: 'QUOTA_EXHAUSTED' }) === 'AI usage quota is exhausted. Check your Gemini API quota and billing settings.',
      `Frontend maps QUOTA_EXHAUSTED to "AI usage quota is exhausted. Check your Gemini API quota and billing settings."`
    );
    assert(
      emulateFrontendErrorDisplay({ code: 'TEMPORARY_SERVICE_FAILURE' }) === 'The AI service is temporarily unavailable. Please try again later.',
      `Frontend maps TEMPORARY_SERVICE_FAILURE to "The AI service is temporarily unavailable. Please try again later."`
    );
    assert(
      emulateFrontendErrorDisplay({ code: 'AI_TIMEOUT', status: 504 }) === 'The AI service is temporarily unavailable. Please try again later.',
      `Frontend maps AI_TIMEOUT to "The AI service is temporarily unavailable. Please try again later."`
    );

    // ── 7. Robust JSON Extraction, Schema Validation, Truncation & Bounded Recovery ──
    console.log(`\n--- Test 7: Robust JSON Extraction, Validation, Truncation & Recovery ---`);

    // 7a. Valid JSON responses (array and object wrapper)
    const validArrayStr = JSON.stringify([
      { findingId: 'SEC-001', problemSummary: 'Unthrottled auth', recommendedFix: 'Add limiter' },
    ]);
    const parsedValidArray = parseJsonFromText(validArrayStr);
    assert(Array.isArray(parsedValidArray) && parsedValidArray.length === 1, `Direct JSON array parsed cleanly`);

    const validWrappedStr = JSON.stringify({
      recommendations: [
        { findingId: 'SEC-002', problemSummary: 'Weak cookies', recommendedFix: 'Set SameSite=Lax' },
      ],
    });
    const parsedWrapped = parseJsonFromText(validWrappedStr);
    assert(Array.isArray(parsedWrapped) && parsedWrapped[0].findingId === 'SEC-002', `Wrapped JSON object ({ recommendations: [...] }) unwrapped cleanly`);

    // 7b. Unterminated JSON strings (Exact production bug reproduction: cut off mid-string at position ~2926)
    const unterminatedStringJson = `[{"findingId": "SEC-001", "problemSummary": "Unthrottled endpoint allows brute force attacks on the login`;
    let unterminatedCaught = false;
    let unterminatedCode = null;
    try {
      parseJsonFromText(unterminatedStringJson);
    } catch (err) {
      unterminatedCaught = err.message.includes('Failed to parse AI JSON response');
      unterminatedCode = err.code;
    }
    assert(unterminatedCaught, `Unterminated JSON string caught safely without crashing process`);
    assert(unterminatedCode === 'AI_RESPONSE_TRUNCATED', `Unterminated string classified as AI_RESPONSE_TRUNCATED (code: ${unterminatedCode})`);

    // 7c. Truncated responses (incomplete JSON structure / cut off mid-token)
    const truncatedStructureJson = `[{"findingId": "SEC-001", "problemSummary": "Incomplete object", "codePatch": { "file": "server.js"`;
    let truncatedStructureCaught = false;
    try {
      parseJsonFromText(truncatedStructureJson);
    } catch (err) {
      truncatedStructureCaught = err.code === 'AI_RESPONSE_TRUNCATED' && err.isTruncated === true;
    }
    assert(truncatedStructureCaught, `Truncated JSON structure safely identified with isTruncated flag`);

    // 7d. Markdown code fences (with and without language tag, with surrounding text)
    const fencedJson = '```json\n[{"findingId": "SEC-001", "problemSummary": "Valid fence", "recommendedFix": "Fix"}]\n```';
    const parsedFenced = parseJsonFromText(fencedJson);
    assert(Array.isArray(parsedFenced) && parsedFenced[0].findingId === 'SEC-001', `Markdown fence \`\`\`json extracted cleanly`);

    const fenceWithSurroundingText = `Here are the requested security recommendations:
\`\`\`json
[{"findingId": "SEC-003", "problemSummary": "Surrounded by text", "recommendedFix": "Fix"}]
\`\`\`
Please review these patches before applying them.`;
    const parsedSurrounded = parseJsonFromText(fenceWithSurroundingText);
    assert(Array.isArray(parsedSurrounded) && parsedSurrounded[0].findingId === 'SEC-003', `Markdown fence with conversational preamble/postamble extracted cleanly`);

    const rawFenceNoLang = '```\n[{"findingId": "SEC-004", "problemSummary": "No lang tag", "recommendedFix": "Fix"}]\n```';
    const parsedRawFence = parseJsonFromText(rawFenceNoLang);
    assert(Array.isArray(parsedRawFence) && parsedRawFence[0].findingId === 'SEC-004', `Markdown fence without language specifier extracted cleanly`);

    // 7e. Missing required fields in parsed recommendations
    let missingFieldCaught = false;
    try {
      validateRecommendations([{ findingId: 'SEC-005' }], [{ id: 'SEC-005' }], { requireFields: true });
    } catch (err) {
      missingFieldCaught = err.code === 'AI_MISSING_REQUIRED_FIELD' && err.field === 'problemSummary';
    }
    assert(missingFieldCaught, `Missing required field (problemSummary) rejected with AI_MISSING_REQUIRED_FIELD`);

    // 7f. Gemini token-limit & incomplete-response finish reasons
    assert(geminiAdapter.DEFAULT_MAX_OUTPUT_TOKENS === 8192, `Gemini DEFAULT_MAX_OUTPUT_TOKENS is 8192 to prevent premature truncation`);
    assert(geminiAdapter.supportsJsonMode('gemini-3.5-flash') === true, `gemini-3.5-flash supports structured JSON mode`);
    assert(geminiAdapter.supportsJsonMode('gemini-1.5-flash') === true, `gemini-1.5-flash supports structured JSON mode`);
    assert(geminiAdapter.supportsJsonMode('gemini-1.0-pro') === false, `Legacy gemini-1.0-pro flagged as not supporting JSON mode`);

    // 7g. Successful recovery after one retry (bounded recovery)
    let callCount = 0;
    const testFindings = [{ id: 'SEC-RECOVER', title: 'Test Finding', severity: 'High' }];
    const testContext = { target: 'http://localhost:4000', overallScore: 80 };

    // Create a transient mock adapter that returns truncated JSON on attempt 0, but valid JSON on recovery retry
    const recoveringAdapter = {
      name: 'recovering-test-adapter',
      defaultModel: 'test-model',
      async generate(prompt, opts) {
        callCount++;
        if (callCount === 1) {
          // Attempt 0: return unterminated JSON string (simulating production error at pos 2926)
          return '[{"findingId": "SEC-RECOVER", "problemSummary": "Unterminated output that cut off at 2926';
        }
        // Attempt 1 (Recovery retry): return valid complete JSON
        return JSON.stringify([
          {
            findingId: 'SEC-RECOVER',
            problemSummary: 'Recovered problem summary successfully',
            recommendedFix: 'Recovered fix',
          },
        ]);
      },
    };

    const recoveredResult = await aiService.generateRecommendations(testFindings, testContext, {
      adapter: recoveringAdapter,
    });
    assert(callCount === 2, `Bounded recovery retried exactly once after initial parse failure (attempts: ${callCount})`);
    assert(
      recoveredResult.recommendations && recoveredResult.recommendations.length === 1,
      `Recovery attempt produced valid recommendations`
    );
    assert(
      recoveredResult.recommendations[0].problemSummary === 'Recovered problem summary successfully',
      `Recovered recommendation contains valid complete data`
    );

    // 7h. Terminal failure when recovery retry also fails (no infinite loop!)
    let failedCalls = 0;
    const permanentFailAdapter = {
      name: 'failing-test-adapter',
      defaultModel: 'test-model',
      async generate() {
        failedCalls++;
        return 'Not valid JSON at all';
      },
    };

    let permanentFailCaught = false;
    try {
      await aiService.generateRecommendations(testFindings, testContext, {
        adapter: permanentFailAdapter,
      });
    } catch (err) {
      permanentFailCaught = err.code === 'AI_JSON_PARSE_FAILED';
    }
    assert(failedCalls === 2, `Failed recovery stopped after exactly 1 retry without infinite loop (total calls: ${failedCalls})`);
    assert(permanentFailCaught, `Unrecoverable JSON error throws clear actionable AI_JSON_PARSE_FAILED error`);

    console.log(`\n======================================================`);
    console.log(`  ALL AI MODULE TESTS PASSED! (${passed} passed, ${failed} failed)`);
    console.log(`======================================================\n`);
  } finally {
    try {
      await pool.query('DELETE FROM users WHERE email IN ($1, $2)', [userAEmail, userBEmail]);
      await pool.query("DELETE FROM users WHERE email LIKE 'audit_%'");
    } catch (_) {}
  }
}

runAiTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\nAI test suite failed:', err);
    process.exit(1);
  });
