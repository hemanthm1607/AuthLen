/**
 * backend/tests/fullIntegration.test.js
 * End-to-End Verification Suite for AuthLens (Phases 1-6)
 */
require('dotenv').config();
const { pool } = require('../config/db');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:4000';

async function resetServerLimiter() {
  try {
    await fetch(`${BASE_URL}/api/auth/reset-rate-limit`, { method: 'POST' });
  } catch (_) {}
}

async function runVerification() {
  console.log(`\n======================================================`);
  console.log(`  AuthLens Comprehensive End-to-End Verification    `);
  console.log(`  Target: ${BASE_URL}`);
  console.log(`======================================================\n`);

  let passedCount = 0;
  let failedCount = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  [PASS] ${message}`);
      passedCount++;
    } else {
      console.error(`  [FAIL] ${message}`);
      failedCount++;
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  await resetServerLimiter();

  const userAEmail = `e2e_tenant_alpha_${Date.now()}@example.corp`;
  const userBEmail = `e2e_tenant_beta_${Date.now()}@example.corp`;
  const initialPassword = 'SecureInitialPass123!';
  const updatedPassword = 'NewSecurePassword456!';

  let cookieA = null;
  let cookieB = null;
  let assessmentIdA = null;

  try {
    // ── Phase 1 & 3: Registration & Password Policy (SEC-002) ──
    console.log(`\n--- Test 1: Password Complexity Policy Enforcement (SEC-002) ---`);
    const weakReg = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'Weak User', email: 'weak@example.invalid', password: 'weak' }),
    });
    const weakJson = await weakReg.json();
    assert(weakReg.status === 400, `Weak password was rejected with HTTP 400 (got ${weakReg.status})`);
    assert(weakJson.error.includes('Password must be at least 8 characters'), `Error message correctly explains complexity requirements`);

    // Register User A
    const regA = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'User Alpha', email: userAEmail, password: initialPassword }),
    });
    cookieA = regA.headers.get('set-cookie');
    assert(regA.status === 201, `Valid registration succeeded with HTTP 201`);

    // Register User B
    const regB = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'User Beta', email: userBEmail, password: initialPassword }),
    });
    cookieB = regB.headers.get('set-cookie');
    assert(regB.status === 201, `Second tenant registered successfully`);

    // ── Phase 3: Login Rate Limiting & 429 Validation (SEC-001) ──
    console.log(`\n--- Test 2: Login Rate Limiter (SEC-001) ---`);
    await resetServerLimiter();

    const maxAttempts = parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 5;
    const probeStatuses = [];
    let received429 = false;
    let retryAfterHeader = null;

    for (let i = 1; i <= maxAttempts + 2; i++) {
      const probeRes = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: userAEmail, password: 'WrongPassword999!' }),
      });
      probeStatuses.push(probeRes.status);
      if (probeRes.status === 429) {
        received429 = true;
        retryAfterHeader = probeRes.headers.get('retry-after');
        break;
      }
    }

    assert(received429 === true, `Login rate limiter triggered HTTP 429 after threshold (sequence: [${probeStatuses.join(', ')}])`);
    assert(retryAfterHeader !== null, `Retry-After header present on 429 response (${retryAfterHeader}s)`);

    // Reset limiter
    await resetServerLimiter();

    // ── Phase 3: Session Invalidation on Logout (SEC-007) ──
    console.log(`\n--- Test 3: Session Invalidation on Logout (SEC-007) ---`);
    // Verify session active before logout
    const preMe = await fetch(`${BASE_URL}/api/auth/me`, { headers: { Cookie: cookieA } });
    assert(preMe.status === 200, `Active session verified before logout (HTTP 200)`);

    // Perform logout
    const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: cookieA },
    });
    assert(logoutRes.status === 200, `POST /api/auth/logout returned HTTP 200`);

    // Verify session rejected after logout
    const postMe = await fetch(`${BASE_URL}/api/auth/me`, { headers: { Cookie: cookieA } });
    assert(postMe.status === 401, `Subsequent request with logged-out cookie rejected with HTTP 401 (no zombie sessions)`);

    // Re-authenticate User A to establish fresh cookie
    await resetServerLimiter();
    const loginA = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userAEmail, password: initialPassword }),
    });
    cookieA = loginA.headers.get('set-cookie');
    assert(loginA.status === 200, `Re-authenticated User A successfully`);

    // ── Phase 5: Account Recovery Flow (REC-001, REC-002, REC-003) ──
    console.log(`\n--- Test 4: Account Recovery & Token Lifecycles (REC-001, REC-002, REC-003) ---`);
    // 4a: Non-existent email returns identical generic response (REC-002)
    const fakeForgot = await fetch(`${BASE_URL}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'nonexistent_account_999@example.corp' }),
    });
    const fakeJson = await fakeForgot.json();

    const realForgot = await fetch(`${BASE_URL}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userAEmail }),
    });
    const realJson = await realForgot.json();

    assert(fakeForgot.status === 200 && realForgot.status === 200, `Forgot password returned HTTP 200 for both emails`);
    assert(fakeJson.message === realJson.message, `Responses are identical preventing email enumeration`);

    // 4b: Retrieve token from DB to test reset
    const userRow = await pool.query('SELECT reset_token FROM users WHERE email = $1', [userAEmail]);
    const resetToken = userRow.rows[0]?.reset_token;
    assert(resetToken && resetToken.length >= 32, `Secure high-entropy reset token generated in database`);

    // 4c: Reset password with valid token
    const resetRes = await fetch(`${BASE_URL}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: resetToken, newPassword: updatedPassword }),
    });
    assert(resetRes.status === 200, `Password reset succeeded with HTTP 200`);

    // 4d: Single-use burning: Replay with same token MUST fail (REC-003)
    const replayRes = await fetch(`${BASE_URL}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: resetToken, newPassword: 'AnotherPassword789!' }),
    });
    assert(replayRes.status === 400, `Token reuse rejected with HTTP 400 (single-use token burned)`);

    // 4e: Verify old password fails & new password succeeds
    await resetServerLimiter();
    const oldLogin = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userAEmail, password: initialPassword }),
    });
    assert(oldLogin.status === 401, `Login with old password correctly rejected (HTTP 401)`);

    const newLogin = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userAEmail, password: updatedPassword }),
    });
    cookieA = newLogin.headers.get('set-cookie');
    assert(newLogin.status === 200, `Login with newly set password succeeded (HTTP 200)`);

    // ── Phase 2 & 6: Assessment Execution, Persistence & Isolation ──
    console.log(`\n--- Test 5: Assessment Engine & Database Persistence ---`);
    await resetServerLimiter();

    const assessRes = await fetch(`${BASE_URL}/api/assessments/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieA },
      body: JSON.stringify({ targetUrl: 'http://localhost:4000', isAuthorized: true }),
    });
    const assessData = await assessRes.json();
    assert(assessRes.status === 201, `Live assessment completed with HTTP 201`);
    assessmentIdA = assessData.assessment?.id;
    assert(assessmentIdA !== undefined, `Assessment ID generated: ${assessmentIdA}`);
    assert(assessData.findings && assessData.findings.length >= 10, `Assessment produced real findings (${assessData.findings.length} findings)`);

    // Verify SEC-001 in live findings
    const sec001 = assessData.findings.find((f) => f.id === 'SEC-001');
    assert(sec001 && sec001.status === 'PASS', `SEC-001 passed with observed rate limit evidence`);
    assert(sec001.evidence.includes('HTTP 429'), `SEC-001 evidence contains actual HTTP 429 observation`);

    // Verify SEC-002 in live findings
    const sec002 = assessData.findings.find((f) => f.id === 'SEC-002');
    assert(sec002 && sec002.status === 'PASS', `SEC-002 passed with observed password policy rejection`);

    // Verify SEC-007 in live findings
    const sec007 = assessData.findings.find((f) => f.id === 'SEC-007');
    assert(sec007 && sec007.status === 'PASS', `SEC-007 passed with observed session destruction evidence`);

    // 5b: History retrieval for User A
    const histRes = await fetch(`${BASE_URL}/api/assessments/history`, {
      headers: { Cookie: cookieA },
    });
    const histData = await histRes.json();
    assert(histRes.status === 200, `GET /api/assessments/history returned HTTP 200`);
    assert(histData.assessments.some((a) => a.id === assessmentIdA), `Assessment ${assessmentIdA} appears in history`);

    // 5c: Opening assessment displays its saved findings
    const detailRes = await fetch(`${BASE_URL}/api/assessments/${assessmentIdA}`, {
      headers: { Cookie: cookieA },
    });
    const detailData = await detailRes.json();
    assert(detailRes.status === 200, `GET /api/assessments/:id returned HTTP 200`);
    assert(detailData.findings && detailData.findings.length > 0, `Saved findings loaded persistently from PostgreSQL`);

    // 5d: Multi-tenant Isolation: User B CANNOT access User A's assessment
    console.log(`\n--- Test 6: Multi-Tenant Authorization Security ---`);
    const unauthorizedRes = await fetch(`${BASE_URL}/api/assessments/${assessmentIdA}`, {
      headers: { Cookie: cookieB },
    });
    assert(unauthorizedRes.status === 404, `User B denied access to User A's assessment record (HTTP 404/Access Denied)`);

    console.log(`\n======================================================`);
    console.log(`  ALL E2E INTEGRATION TESTS PASSED! (${passedCount} passed, ${failedCount} failed)`);
    console.log(`======================================================\n`);
  } finally {
    // Teardown test accounts
    try {
      await pool.query('DELETE FROM users WHERE email IN ($1, $2)', [userAEmail, userBEmail]);
      await pool.query("DELETE FROM users WHERE email LIKE 'audit_%'");
      await resetServerLimiter();
      console.log(`  [CLEANUP] Test users and temporary audit accounts removed from PostgreSQL.`);
    } catch (e) {
      console.warn(`  [CLEANUP WARNING]:`, e.message);
    }
  }
}

runVerification()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`\nIntegration tests terminated with error:`, err);
    process.exit(1);
  });
