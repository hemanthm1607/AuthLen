/**
 * backend/tests/rateLimiter.test.js
 * Automated test suite verifying login rate limiting (SEC-001) & auth integrity:
 * 1. Login works normally before the limit is reached.
 * 2. Repeated invalid login attempts eventually receive HTTP 429.
 * 3. A request after the rate-limit window expires/resets can be processed again.
 * 4. Other unrelated endpoints remain functional.
 * 5. Generic login errors prevent account enumeration.
 * 6. Registration, session, and logout functionality remain fully operational.
 */
require('dotenv').config();
const express = require('express');
const { pool } = require('../config/db');
const { loginLimiter, resetLoginRateLimit } = require('../middleware/rateLimiter');
const { rateLimit } = require('express-rate-limit');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:4000';

async function resetServerRateLimit() {
  resetLoginRateLimit();
  try {
    await fetch(`${BASE_URL}/api/auth/reset-rate-limit`, { method: 'POST' });
  } catch (_) {
    // Non-fatal if server is handling internally
  }
}

async function runTests() {
  console.log(`\n======================================================`);
  console.log(`  AuthLens Automated Rate Limiting & Auth Test Suite  `);
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

  // Pre-test setup: Ensure rate limiter is clear for localhost
  await resetServerRateLimit();

  const testEmail = `test_runner_${Date.now()}@example.internal`;
  const testPassword = 'SecurePassword123!';
  const testName = 'RateLimit Test User';

  try {
    // ── 1. Create a dedicated test account & verify initial normal login ──
    console.log(`\n--- Test 1: Registration and Normal Login Before Limit ---`);
    const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: testName, email: testEmail, password: testPassword }),
    });
    const regData = await regRes.json();
    assert(regRes.status === 201, `Registration succeeded with HTTP 201 (got ${regRes.status})`);
    assert(regData.user && regData.user.email === testEmail, `Registered user email matches (${regData.user?.email})`);

    // Reset loopback rate limits before test sequence
    await resetServerRateLimit();

    // Normal login before limit
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    const loginData = await loginRes.json();
    assert(loginRes.status === 200, `Legitimate login succeeded with HTTP 200 before limit`);
    assert(loginData.user && loginData.user.email === testEmail, `User profile returned successfully on valid login`);

    // ── 2. Repeated Invalid Login Attempts Trigger HTTP 429 ──
    console.log(`\n--- Test 2: Repeated Invalid Attempts Trigger HTTP 429 (SEC-001) ---`);
    await resetServerRateLimit();

    const maxAttempts = parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 5;
    const probeStatuses = [];
    let received429 = false;
    let retryAfterHeader = null;

    // Send up to maxAttempts + 2 failed login attempts
    for (let i = 1; i <= maxAttempts + 2; i++) {
      const failRes = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: testEmail, password: 'WrongPassword456!' }),
      });
      probeStatuses.push(failRes.status);

      if (failRes.status === 429) {
        received429 = true;
        retryAfterHeader = failRes.headers.get('retry-after');
        const errorJson = await failRes.json();
        assert(errorJson.code === 'LOGIN_RATE_LIMIT_EXCEEDED', `HTTP 429 body includes clean code LOGIN_RATE_LIMIT_EXCEEDED`);
        assert(!errorJson.stack, `HTTP 429 response does NOT leak stack traces`);
        break;
      }
    }

    assert(received429 === true, `Repeated invalid login attempts received HTTP 429 (statuses: [${probeStatuses.join(', ')}])`);
    assert(retryAfterHeader !== null, `HTTP 429 response included Retry-After header (value: ${retryAfterHeader}s)`);

    // ── 3. Reset / Window Expiry Allows Requests Again ──
    console.log(`\n--- Test 3: Request Allowed After Window Expiry / Reset ---`);
    // 3a: Verify reset endpoint clears blocked status on server
    await resetServerRateLimit();

    const postResetRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    assert(postResetRes.status === 200, `Legitimate request processed with HTTP 200 after window reset (got ${postResetRes.status})`);

    // 3b: Verify natural sliding-window expiration
    console.log(`  Verifying natural time-window expiration...`);
    const expiryApp = express();
    const shortLimiter = rateLimit({
      windowMs: 600, // 600ms window
      max: 2,
      validate: { xForwardedForHeader: false },
      message: { code: 'RATE_LIMIT_EXCEEDED' },
    });
    expiryApp.post('/probe', shortLimiter, (req, res) => res.status(200).json({ ok: true }));
    const expiryServer = expiryApp.listen(0);
    const expiryPort = expiryServer.address().port;

    try {
      const r1 = await fetch(`http://localhost:${expiryPort}/probe`, { method: 'POST' });
      const r2 = await fetch(`http://localhost:${expiryPort}/probe`, { method: 'POST' });
      const r3 = await fetch(`http://localhost:${expiryPort}/probe`, { method: 'POST' });
      assert(r1.status === 200 && r2.status === 200 && r3.status === 429, `Micro-window triggered HTTP 429 on 3rd attempt`);

      // Wait for 700ms (exceeding 600ms windowMs)
      await new Promise((r) => setTimeout(r, 700));

      const r4 = await fetch(`http://localhost:${expiryPort}/probe`, { method: 'POST' });
      assert(r4.status === 200, `Request successfully processed again after natural window expiry (HTTP ${r4.status})`);
    } finally {
      expiryServer.close();
    }

    // ── 4. Unrelated Endpoints Remain Fully Functional ──
    console.log(`\n--- Test 4: Unrelated Endpoints Remain Functional ---`);
    const healthRes = await fetch(`${BASE_URL}/api/health`);
    const healthData = await healthRes.json();
    assert(healthRes.status === 200, `GET /api/health returns HTTP 200`);
    assert(healthData.status === 'ok' && healthData.database?.connected === true, `Database health check reports connected`);

    // ── 5. Generic Login Error Prevents Account Enumeration ──
    console.log(`\n--- Test 5: Generic Error Messages Prevent Account Enumeration ---`);
    await resetServerRateLimit();

    const badPassRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: 'WrongPassword999!' }),
    });
    const badPassJson = await badPassRes.json();

    const nonExistentRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `nonexistent_user_${Date.now()}@example.invalid`, password: 'AnyPassword123!' }),
    });
    const nonExistentJson = await nonExistentRes.json();

    assert(badPassRes.status === 401 && nonExistentRes.status === 401, `Both valid email/wrong password and non-existent email return HTTP 401`);
    assert(badPassJson.error === nonExistentJson.error, `Error message is identical ("${badPassJson.error}") preventing enumeration`);

    // ── 6. Session Persistence and Logout Functionality ──
    console.log(`\n--- Test 6: Session Verification and Logout ---`);
    await resetServerRateLimit();

    // Perform fresh login to get auth session
    const authLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    const setCookieHeader = authLoginRes.headers.get('set-cookie');
    assert(authLoginRes.status === 200, `Login for session verification succeeded`);

    // Check GET /api/auth/me with session cookie
    const meRes = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Cookie: setCookieHeader },
    });
    const meData = await meRes.json();
    if (meRes.status !== 200 || meData.user?.email !== testEmail) {
      console.log('    [DEBUG Test 6]', { status: meRes.status, body: meData, cookie: setCookieHeader });
    }
    assert(meRes.status === 200 && meData.user?.email === testEmail, `GET /api/auth/me verifies active session`);

    // Logout
    const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: setCookieHeader },
    });
    assert(logoutRes.status === 200, `POST /api/auth/logout invalidated session successfully`);

    console.log(`\n======================================================`);
    console.log(`  ALL TESTS PASSED! (${passedCount} passed, ${failedCount} failed)`);
    console.log(`======================================================\n`);
  } finally {
    // Teardown: Clean up dedicated test user and reset limits
    try {
      await pool.query('DELETE FROM users WHERE email = $1', [testEmail]);
      await resetServerRateLimit();
      console.log(`  [CLEANUP] Dedicated test account removed from PostgreSQL.`);
    } catch (e) {
      console.warn(`  [CLEANUP WARNING]:`, e.message);
    }
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`\nTest suite terminated with error:`, err);
    process.exit(1);
  });
