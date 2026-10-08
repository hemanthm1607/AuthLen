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
    // ── 1. Provider Status & Missing Key Handling ──
    console.log(`\n--- Test 1: Provider Status & Configuration Safety ---`);
    const status = aiService.getProviderStatus();
    assert(typeof status.configured === 'boolean', `Provider status returned valid boolean (configured: ${status.configured})`);
    assert(typeof status.message === 'string', `Informative configuration guidance message provided`);

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
