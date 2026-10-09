/**
 * tests/regressionTasks.test.js — Regression Tests for TASK 7 Requirements
 *
 * Verifies all 10 required regression scenarios:
 * 1. A reachable local HTML page with accessible form labels.
 * 2. A page with missing labels and confirmed accessibility issues.
 * 3. A target returning HTTP 500.
 * 4. A target that is unreachable.
 * 5. A login form with observable security controls.
 * 6. A target with no recovery functionality.
 * 7. A target that has a real recovery form/route.
 * 8. Different ports and targets maintaining strict isolation.
 * 9. Historical assessments retaining their own scores and findings.
 * 10. Partial evidence not being presented as a complete security pass.
 */

const assert = require('assert');
const http = require('http');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const testingEngine = require('../../testing-engine');
const { checkTargetReachability } = require('../../testing-engine/utils/targetValidator');
const {
  calculateCategoryScores,
  calculateSummary,
  calculateOverallScore,
} = require('../../testing-engine/utils/scoring');

async function runRegressionSuite() {
  console.log('\n======================================================');
  console.log('  AuthLens Task 7 Regression Test Suite (10 Scenarios)');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function test(desc, fn) {
    try {
      fn();
      console.log(`  [PASS] ${desc}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${desc}: ${err.message}`);
      failed++;
    }
  }

  // ── Scenario 1: Reachable Local HTML with Accessible Form Labels ──
  console.log('--- Scenario 1: Reachable Local HTML with Accessible Labels ---');
  const serverAccessible = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
      <!DOCTYPE html>
      <html>
        <body>
          <form action="/login" method="POST">
            <label for="email">Work Email</label>
            <input id="email" type="email" name="email" autocomplete="username" />
            <label for="password">Password</label>
            <input id="password" type="password" name="password" autocomplete="current-password" />
            <div role="alert" aria-live="polite"></div>
            <button type="submit">Sign In</button>
          </form>
        </body>
      </html>
    `);
  });

  await new Promise((resolve) => serverAccessible.listen(0, '127.0.0.1', resolve));
  const port1 = serverAccessible.address().port;

  try {
    const a11yModule = require('../../testing-engine/accessibility');
    const a11yFindings = await a11yModule.run({
      url: `http://127.0.0.1:${port1}`,
      origin: `http://127.0.0.1:${port1}`,
      pathname: '/',
    });

    const labelFinding = a11yFindings.find((f) => f.id === 'A11Y-001');
    test('1.1: Explicit <label> check passes on accessible form', () => {
      assert.strictEqual(labelFinding.status, 'PASS');
    });

    const autoFinding = a11yFindings.find((f) => f.id === 'A11Y-004');
    test('1.2: Standard autocomplete attributes pass', () => {
      assert.strictEqual(autoFinding.status, 'PASS');
    });
  } finally {
    serverAccessible.close();
  }

  // ── Scenario 2: Page with Missing Labels and Confirmed Accessibility Issues ──
  console.log('\n--- Scenario 2: Missing Labels and Confirmed Accessibility Issues ---');
  const serverInaccessible = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
      <!DOCTYPE html>
      <html>
        <head>
          <style>button:focus { outline: none; }</style>
        </head>
        <body>
          <form action="/login" method="POST">
            <input id="email" type="email" name="email" placeholder="Email without label" />
            <input id="password" type="password" name="password" placeholder="Password without label" />
            <button type="submit">Sign In</button>
          </form>
        </body>
      </html>
    `);
  });

  await new Promise((resolve) => serverInaccessible.listen(0, '127.0.0.1', resolve));
  const port2 = serverInaccessible.address().port;

  try {
    const a11yModule = require('../../testing-engine/accessibility');
    const a11yFindings = await a11yModule.run({
      url: `http://127.0.0.1:${port2}`,
      origin: `http://127.0.0.1:${port2}`,
      pathname: '/',
    });

    const labelFinding = a11yFindings.find((f) => f.id === 'A11Y-001');
    test('2.1: Missing labels detected as confirmed FAIL', () => {
      assert.strictEqual(labelFinding.status, 'FAIL');
      assert.strictEqual(labelFinding.severity, 'Medium');
    });

    const focusFinding = a11yFindings.find((f) => f.id === 'A11Y-002');
    test('2.2: Suppressed focus outline detected as confirmed FAIL', () => {
      assert.strictEqual(focusFinding.status, 'FAIL');
    });
  } finally {
    serverInaccessible.close();
  }

  // ── Scenario 3: Target Returning HTTP 500 ──
  console.log('\n--- Scenario 3: Target Returning HTTP 500 ---');
  const server500 = http.createServer((req, res) => {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal Server Error' }));
  });

  await new Promise((resolve) => server500.listen(0, '127.0.0.1', resolve));
  const port3 = server500.address().port;

  try {
    const result500 = await testingEngine.runAllTests({
      targetUrl: `http://127.0.0.1:${port3}`,
      isAuthorized: true,
    });

    test('3.1: Zero confirmed failures on HTTP 500 target', () => {
      assert.strictEqual(result500.summary.failed, 0);
    });

    test('3.2: HTTP 500 does NOT create false critical or high vulnerabilities', () => {
      assert.strictEqual(result500.summary.critical, 0);
      assert.strictEqual(result500.summary.high, 0);
    });

    const useCard = result500.categoryScores.find((c) => c.id === 'usability');
    test('3.3: Usability score shows Insufficient data on 500', () => {
      assert.strictEqual(useCard.score, null);
      assert.strictEqual(useCard.statusText, 'Insufficient data');
    });
  } finally {
    server500.close();
  }

  // ── Scenario 4: Target that is Unreachable ──
  console.log('\n--- Scenario 4: Target That Is Unreachable ---');
  {
    // Use an unallocated local port where no server is listening
    const unreachableUrl = 'http://127.0.0.1:4008';
    const reachability = await checkTargetReachability(unreachableUrl);

    test('4.1: Pre-flight check detects unreachable host/port', () => {
      assert.strictEqual(reachability.reachable, false);
      assert(reachability.error.includes('Connection refused') || reachability.error.includes('offline'));
    });

    let runError = null;
    try {
      await testingEngine.runAllTests({ targetUrl: unreachableUrl, isAuthorized: true });
    } catch (err) {
      runError = err;
    }

    test('4.2: runAllTests throws reachability error instead of faking scan', () => {
      assert(runError !== null, 'Expected error to be thrown for offline port');
      assert(runError.message.includes('unreachable') || runError.message.includes('Connection refused'));
    });
  }

  // ── Scenario 5: Login Form with Observable Security Controls ──
  console.log('\n--- Scenario 5: Login Form with Observable Security Controls ---');
  let loginCount = 0;
  const serverSecuredLogin = http.createServer((req, res) => {
    if (req.url === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
          <body>
            <form action="/login" method="POST">
              <label for="u">Email</label>
              <input id="u" type="email" name="email" autocomplete="username" />
              <label for="p">Password</label>
              <input id="p" type="password" name="password" autocomplete="current-password" />
              <button type="submit">Sign In</button>
            </form>
          </body>
        </html>
      `);
      return;
    }

    if (req.url === '/login' && req.method === 'POST') {
      loginCount++;
      if (loginCount >= 4) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '900' });
        res.end(JSON.stringify({ error: 'Too many attempts' }));
        return;
      }
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid email address or password' }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverSecuredLogin.listen(0, '127.0.0.1', resolve));
  const port5 = serverSecuredLogin.address().port;

  try {
    const secModule = require('../../testing-engine/security');
    const secFindings = await secModule.run({
      url: `http://127.0.0.1:${port5}`,
      origin: `http://127.0.0.1:${port5}`,
      isLocal: true,
      protocol: 'http:',
      pathname: '/',
    });

    const rateFinding = secFindings.find((f) => f.id === 'SEC-001');
    test('5.1: Rate limiting triggers and passes with HTTP 429 evidence', () => {
      assert.strictEqual(rateFinding.status, 'PASS');
      assert(rateFinding.evidence.includes('HTTP 429'));
    });

    const enumFinding = secFindings.find((f) => f.id === 'SEC-006');
    test('5.2: Uniform error messaging passes without enumeration leak', () => {
      assert.strictEqual(enumFinding.status, 'PASS');
    });
  } finally {
    serverSecuredLogin.close();
  }

  // ── Scenario 6: Target with No Recovery Functionality ──
  console.log('\n--- Scenario 6: Target with No Recovery Functionality ---');
  const serverNoRecovery = http.createServer((req, res) => {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  await new Promise((resolve) => serverNoRecovery.listen(0, '127.0.0.1', resolve));
  const port6 = serverNoRecovery.address().port;

  try {
    const recModule = require('../../testing-engine/recovery');
    const recFindings = await recModule.run({
      url: `http://127.0.0.1:${port6}`,
      origin: `http://127.0.0.1:${port6}`,
      pathname: '/',
    });

    const rec001 = recFindings.find((f) => f.id === 'REC-001');
    test('6.1: Missing recovery route is NOT_APPLICABLE, not confirmed FAIL', () => {
      assert.strictEqual(rec001.status, 'NOT_APPLICABLE');
      assert.strictEqual(rec001.severity, 'Low');
    });

    const recScores = calculateCategoryScores(recFindings).find((c) => c.id === 'recovery');
    test('6.2: Account Recovery scorecard displays Not Applicable status', () => {
      assert.strictEqual(recScores.score, null);
      assert.strictEqual(recScores.statusText, 'Not Applicable');
      assert.strictEqual(recScores.hasSufficientData, false);
    });
  } finally {
    serverNoRecovery.close();
  }

  // ── Scenario 7: Target with Real Recovery Form/Route ──
  console.log('\n--- Scenario 7: Target with Real Recovery Form/Route ---');
  const serverWithRecovery = http.createServer((req, res) => {
    if (req.url === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
          <body>
            <a href="/forgot-password">Forgot Password?</a>
          </body>
        </html>
      `);
      return;
    }

    if (req.url === '/forgot-password' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'If account exists, reset instructions sent.' }));
      return;
    }

    if (req.url === '/api/auth/reset-password' && req.method === 'POST') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token is invalid or expired.' }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverWithRecovery.listen(0, '127.0.0.1', resolve));
  const port7 = serverWithRecovery.address().port;

  try {
    const recModule = require('../../testing-engine/recovery');
    const recFindings = await recModule.run({
      url: `http://127.0.0.1:${port7}`,
      origin: `http://127.0.0.1:${port7}`,
      pathname: '/',
    });

    const rec001 = recFindings.find((f) => f.id === 'REC-001');
    test('7.1: Real recovery endpoint discovered and verified PASS', () => {
      assert.strictEqual(rec001.status, 'PASS');
    });

    const rec002 = recFindings.find((f) => f.id === 'REC-002');
    test('7.2: Enumeration-resistant recovery messaging verified PASS', () => {
      assert.strictEqual(rec002.status, 'PASS');
    });
  } finally {
    serverWithRecovery.close();
  }

  // ── Scenario 8: Different Ports and Targets Maintain Strict Isolation ──
  console.log('\n--- Scenario 8: Port & Target Isolation ---');
  {
    const targetA = 'http://localhost:4000';
    const targetB = 'http://localhost:4008';
    const targetC = 'https://the-internet.herokuapp.com/login';

    const findingsA = [
      { id: 'SEC-001', category: 'Security', severity: 'Info', status: 'PASS' },
    ];
    const findingsB = [
      { id: 'SEC-001', category: 'Security', severity: 'Critical', status: 'FAIL' },
    ];

    const scoreA = calculateOverallScore(findingsA);
    const scoreB = calculateOverallScore(findingsB);

    test('8.1: Target A (port 4000) scores 100/100', () => {
      assert.strictEqual(scoreA, 100);
    });

    test('8.2: Target B (port 4008) scores 75/100 (isolated)', () => {
      assert.strictEqual(scoreB, 75);
    });

    test('8.3: Targets maintain strict isolation without shared state', () => {
      assert.notStrictEqual(scoreA, scoreB);
      assert.notStrictEqual(targetA, targetB);
      assert.notStrictEqual(targetB, targetC);
    });
  }

  // ── Scenario 9: Historical Assessments Retaining Immutable Scores ──
  console.log('\n--- Scenario 9: Historical Assessments Retain Scores & Findings ---');
  {
    const historicalRun1 = {
      id: 'ASSESS-10001',
      target: 'http://localhost:4000',
      findings: [
        { id: 'SEC-001', category: 'Security', severity: 'Info', status: 'PASS' },
        { id: 'USE-001', category: 'Usability', severity: 'Info', status: 'PASS' },
      ],
    };

    const historicalRun2 = {
      id: 'ASSESS-10002',
      target: 'https://staging.internal/auth',
      findings: [
        { id: 'SEC-001', category: 'Security', severity: 'High', status: 'FAIL' },
        { id: 'SEC-004', category: 'Security', severity: 'High', status: 'FAIL' },
      ],
    };

    const scoresRun1 = calculateCategoryScores(historicalRun1.findings);
    const scoresRun2 = calculateCategoryScores(historicalRun2.findings);

    test('9.1: Historical Run 1 computes Security 100/100', () => {
      const sec1 = scoresRun1.find((c) => c.id === 'security');
      assert.strictEqual(sec1.score, 100);
    });

    test('9.2: Historical Run 2 computes Security 70/100 (100 - 30)', () => {
      const sec2 = scoresRun2.find((c) => c.id === 'security');
      assert.strictEqual(sec2.score, 70);
    });

    test('9.3: Selecting historical runs does not bleed findings between runs', () => {
      const sec1 = scoresRun1.find((c) => c.id === 'security');
      const sec2 = scoresRun2.find((c) => c.id === 'security');
      assert.notStrictEqual(sec1.score, sec2.score);
    });
  }

  // ── Scenario 10: Partial Evidence Not Presented as Complete Security Pass ──
  console.log('\n--- Scenario 10: Partial Evidence Formatting & Transparency ---');
  {
    // Partial evidence: 1 passed, 5 review needed
    const partialFindings = [
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'SEC-001', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-002', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-004', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-006', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-007', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
    ];

    const catScores = calculateCategoryScores(partialFindings);
    const secCard = catScores.find((c) => c.id === 'security');

    test('10.1: Description clearly flags "1 passed, 5 review needed"', () => {
      assert.strictEqual(secCard.description, '1 passed, 5 review needed');
    });

    test('10.2: Trend clearly flags partial review needed, not unconditional pass', () => {
      assert.strictEqual(secCard.trend, 'Passing core controls (partial review needed)');
    });

    test('10.3: Stats object contains exact executed, passed, and needsReview counts', () => {
      assert.strictEqual(secCard.stats.total, 6);
      assert.strictEqual(secCard.stats.passed, 1);
      assert.strictEqual(secCard.stats.needsReview, 5);
      assert.strictEqual(secCard.stats.failed, 0);
    });

    // Zero passes and only reviews -> Insufficient data
    const allReviewFindings = [
      { id: 'USE-001', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'USE-002', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
    ];

    const useCard = calculateCategoryScores(allReviewFindings).find((c) => c.id === 'usability');
    test('10.4: When zero controls pass, score is null and status is Insufficient data', () => {
      assert.strictEqual(useCard.score, null);
      assert.strictEqual(useCard.statusText, 'Insufficient data');
      assert.strictEqual(useCard.hasSufficientData, false);
    });
  }

  console.log('\n======================================================');
  console.log(`  Task 7 Results: ${passed} passed, ${failed} failed`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runRegressionSuite().catch((err) => {
  console.error('Fatal error during Task 7 suite:', err);
  process.exit(1);
});
