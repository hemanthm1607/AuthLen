/**
 * tests/categoryScores.test.js — Automated Tests for Category Scorecards & Overview Engine
 * Verifies:
 * 1. Category scores dynamically reflect underlying assessment findings
 * 2. Unrelated targets do not share scores
 * 3. Insufficient data / Not Applicable status handling (no fake 0 or 100)
 * 4. Assessment history returns accurate category scores per assessment
 * 5. Scoring formula severity weights and invariants
 */

const assert = require('assert');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const db = require('../config/db');
const {
  calculateCategoryScores,
  calculateSummary,
  calculateOverallScore,
} = require('../../testing-engine/utils/scoring');

async function runTests() {
  console.log('\n======================================================');
  console.log('  AuthLens Category Scores & Dashboard Audit Tests');
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

  // ─── Test 1: Dynamic Score Calculation from Findings ────────────────────────
  console.log('--- Test 1: Dynamic Score Calculation from Real Findings ---');
  {
    // Scenario: Target like https://the-internet.herokuapp.com/login (3 High security findings, 2 A11y passes, Recovery not applicable)
    const findingsSample = [
      { id: 'SEC-001', category: 'Security', severity: 'High', status: 'FAIL' },
      { id: 'SEC-004', category: 'Security', severity: 'High', status: 'FAIL' },
      { id: 'SEC-007', category: 'Security', severity: 'High', status: 'FAIL' },
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'SEC-006', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-002', category: 'Security', severity: 'Low', status: 'NOT_APPLICABLE' },

      { id: 'USE-001', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'USE-002', category: 'Usability', severity: 'Low', status: 'NOT_APPLICABLE' },
      { id: 'USE-003', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'USE-005', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },

      { id: 'A11Y-001', category: 'Accessibility', severity: 'Info', status: 'PASS' },
      { id: 'A11Y-002', category: 'Accessibility', severity: 'Info', status: 'PASS' },
      { id: 'A11Y-003', category: 'Accessibility', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'A11Y-004', category: 'Accessibility', severity: 'Low', status: 'NEEDS_REVIEW' },

      { id: 'REC-001', category: 'Account Recovery', severity: 'Low', status: 'NOT_APPLICABLE' },
      { id: 'REC-002', category: 'Account Recovery', severity: 'Low', status: 'NOT_APPLICABLE' },
      { id: 'REC-003', category: 'Account Recovery', severity: 'Low', status: 'NOT_APPLICABLE' },
    ];

    const catScores = calculateCategoryScores(findingsSample);
    const overall = calculateOverallScore(findingsSample);
    const summary = calculateSummary(findingsSample);

    test('1.1: Overall score is 55/100 (100 - 3 * 15)', () => {
      assert.strictEqual(overall, 55);
    });

    test('1.2: Summary matches 3 High failures', () => {
      assert.strictEqual(summary.failed, 3);
      assert.strictEqual(summary.high, 3);
      assert.strictEqual(summary.critical, 0);
    });

    const sec = catScores.find((c) => c.id === 'security');
    test('1.3: Security category score reflects 3 High findings (55/100)', () => {
      assert.strictEqual(sec.score, 55);
      assert.strictEqual(sec.statusText, 'Needs Hardening');
      assert.strictEqual(sec.trend, 'High-risk vulnerabilities detected');
      assert.strictEqual(sec.hasSufficientData, true);
    });

    const use = catScores.find((c) => c.id === 'usability');
    test('1.4: Usability category shows Insufficient data when 0 pass and 0 fail', () => {
      assert.strictEqual(use.score, null);
      assert.strictEqual(use.statusText, 'Insufficient data');
      assert.strictEqual(use.trend, 'Controls require manual review');
      assert.strictEqual(use.hasSufficientData, false);
    });

    const a11y = catScores.find((c) => c.id === 'accessibility');
    test('1.5: Accessibility category shows 100/100 with passing core controls', () => {
      assert.strictEqual(a11y.score, 100);
      assert.strictEqual(a11y.statusText, 'Secure');
      assert.strictEqual(a11y.trend, 'Passing core controls (partial review needed)');
      assert.strictEqual(a11y.hasSufficientData, true);
    });

    const rec = catScores.find((c) => c.id === 'recovery');
    test('1.6: Account Recovery shows Not Applicable when target has no recovery endpoints', () => {
      assert.strictEqual(rec.score, null);
      assert.strictEqual(rec.statusText, 'Not Applicable');
      assert.strictEqual(rec.trend, 'Not applicable to target');
      assert.strictEqual(rec.hasSufficientData, false);
      assert.strictEqual(rec.isApplicable, false);
    });
  }

  // ─── Test 2: Generic HTTP 500 Endpoint ──────────────────────────────────────
  console.log('\n--- Test 2: Generic HTTP 500 Endpoint Handling ---');
  {
    // On HTTP 500: SEC-005 (HTTPS) passes; all other checks are NEEDS_REVIEW (server error)
    const http500Findings = [
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'SEC-001', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-004', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'SEC-006', category: 'Security', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'USE-001', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'USE-002', category: 'Usability', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'A11Y-001', category: 'Accessibility', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'A11Y-002', category: 'Accessibility', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'REC-001', category: 'Account Recovery', severity: 'Low', status: 'NEEDS_REVIEW' },
      { id: 'REC-002', category: 'Account Recovery', severity: 'Low', status: 'NEEDS_REVIEW' },
    ];

    const catScores = calculateCategoryScores(http500Findings);
    const overall = calculateOverallScore(http500Findings);
    const summary = calculateSummary(http500Findings);

    test('2.1: Zero confirmed failures on HTTP 500', () => {
      assert.strictEqual(summary.failed, 0);
      assert.strictEqual(overall, 100);
    });

    const use = catScores.find((c) => c.id === 'usability');
    test('2.2: Usability shows Insufficient data (not 100 or 0)', () => {
      assert.strictEqual(use.score, null);
      assert.strictEqual(use.statusText, 'Insufficient data');
    });

    const a11y = catScores.find((c) => c.id === 'accessibility');
    test('2.3: Accessibility shows Insufficient data (not 100 or 0)', () => {
      assert.strictEqual(a11y.score, null);
      assert.strictEqual(a11y.statusText, 'Insufficient data');
    });

    const rec = catScores.find((c) => c.id === 'recovery');
    test('2.4: Account Recovery shows Insufficient data (not 100 or 0)', () => {
      assert.strictEqual(rec.score, null);
      assert.strictEqual(rec.statusText, 'Insufficient data');
    });
  }

  // ─── Test 3: Clean Target With No Confirmed Failures ─────────────────────────
  console.log('\n--- Test 3: Clean Target With All Controls Passing ---');
  {
    const cleanFindings = [
      { id: 'SEC-001', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'SEC-004', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
      { id: 'USE-001', category: 'Usability', severity: 'Info', status: 'PASS' },
      { id: 'A11Y-001', category: 'Accessibility', severity: 'Info', status: 'PASS' },
      { id: 'REC-001', category: 'Account Recovery', severity: 'Info', status: 'PASS' },
    ];

    const catScores = calculateCategoryScores(cleanFindings);
    const overall = calculateOverallScore(cleanFindings);

    test('3.1: Overall score is 100/100', () => {
      assert.strictEqual(overall, 100);
    });

    test('3.2: All categories with passes score 100/100 and Secure', () => {
      catScores.forEach((c) => {
        assert.strictEqual(c.score, 100);
        assert.strictEqual(c.statusText, 'Secure');
        assert.strictEqual(c.trend, 'Passing core controls');
      });
    });
  }

  // ─── Test 4: Separate Targets Do Not Share Scores ────────────────────────────
  console.log('\n--- Test 4: Target Isolation (Distinct Scores per Target) ---');
  {
    const targetA_Findings = [
      { id: 'SEC-001', category: 'Security', severity: 'Critical', status: 'FAIL' },
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
    ];

    const targetB_Findings = [
      { id: 'SEC-001', category: 'Security', severity: 'Low', status: 'FAIL' },
      { id: 'SEC-005', category: 'Security', severity: 'Info', status: 'PASS' },
    ];

    const scoreA = calculateCategoryScores(targetA_Findings).find((c) => c.id === 'security');
    const scoreB = calculateCategoryScores(targetB_Findings).find((c) => c.id === 'security');

    test('4.1: Target A security score is 75 (100 - 25 Critical)', () => {
      assert.strictEqual(scoreA.score, 75);
      assert.strictEqual(scoreA.trend, 'Critical vulnerabilities present');
    });

    test('4.2: Target B security score is 97 (100 - 3 Low)', () => {
      assert.strictEqual(scoreB.score, 97);
      assert.strictEqual(scoreB.trend, 'Remediation required');
    });

    test('4.3: Separate targets have distinct scores and trends', () => {
      assert.notStrictEqual(scoreA.score, scoreB.score);
      assert.notStrictEqual(scoreA.trend, scoreB.trend);
    });
  }

  // ─── Test 5: Database Persistence & Historical Retrieval ────────────────────
  console.log('\n--- Test 5: Database Persistence & Assessment Detail Derivation ---');
  {
    const testUserId = '00000000-0000-0000-0000-000000000001';
    const testRunIdA = `ASSESS-TEST-A-${Date.now()}`;
    const testRunIdB = `ASSESS-TEST-B-${Date.now()}`;

    // Ensure mock user exists in DB
    await db.query(`
      INSERT INTO users (id, email, password_hash, full_name)
      VALUES ($1, 'cat_test_user@example.com', 'hash', 'Category Test User')
      ON CONFLICT (id) DO NOTHING;
    `, [testUserId]);

    // Insert Run A
    await db.query(`
      INSERT INTO assessments (id, user_id, target, overall_score, critical, high, medium, low, status)
      VALUES ($1, $2, 'https://site-a.example.com', 55, 0, 3, 0, 0, 'completed');
    `, [testRunIdA, testUserId]);

    await db.query(`
      INSERT INTO findings (id, assessment_id, user_id, title, category, severity, status)
      VALUES
        ('SEC-001', $1, $2, 'Rate Limiting', 'Security', 'High', 'FAIL'),
        ('SEC-004', $1, $2, 'Cookie Flags', 'Security', 'High', 'FAIL'),
        ('SEC-007', $1, $2, 'Logout Zombie', 'Security', 'High', 'FAIL'),
        ('A11Y-001', $1, $2, 'Labels', 'Accessibility', 'Info', 'PASS')
      ON CONFLICT (id, assessment_id) DO NOTHING;
    `, [testRunIdA, testUserId]);

    // Insert Run B
    await db.query(`
      INSERT INTO assessments (id, user_id, target, overall_score, critical, high, medium, low, status)
      VALUES ($1, $2, 'https://site-b.example.com', 92, 0, 0, 1, 0, 'completed');
    `, [testRunIdB, testUserId]);

    await db.query(`
      INSERT INTO findings (id, assessment_id, user_id, title, category, severity, status)
      VALUES
        ('USE-001', $1, $2, 'Password Masking', 'Usability', 'Medium', 'FAIL'),
        ('SEC-005', $1, $2, 'HTTPS', 'Security', 'Info', 'PASS')
      ON CONFLICT (id, assessment_id) DO NOTHING;
    `, [testRunIdB, testUserId]);

    // Fetch findings for Run A
    const resA = await db.query(
      'SELECT id, title, category, severity, status FROM findings WHERE assessment_id = $1',
      [testRunIdA]
    );
    const catScoresA = calculateCategoryScores(resA.rows);
    const secA = catScoresA.find((c) => c.id === 'security');

    test('5.1: Run A persisted findings compute Security score 55', () => {
      assert.strictEqual(secA.score, 55);
      assert.strictEqual(secA.statusText, 'Needs Hardening');
    });

    // Fetch findings for Run B
    const resB = await db.query(
      'SELECT id, title, category, severity, status FROM findings WHERE assessment_id = $1',
      [testRunIdB]
    );
    const catScoresB = calculateCategoryScores(resB.rows);
    const useB = catScoresB.find((c) => c.id === 'usability');
    const secB = catScoresB.find((c) => c.id === 'security');

    test('5.2: Run B persisted findings compute Usability score 92 (100 - 8 Medium)', () => {
      assert.strictEqual(useB.score, 92);
      assert.strictEqual(useB.statusText, 'Secure');
      assert.strictEqual(secB.score, 100);
    });

    // Cleanup test records
    await db.query('DELETE FROM findings WHERE assessment_id IN ($1, $2)', [testRunIdA, testRunIdB]);
    await db.query('DELETE FROM assessments WHERE id IN ($1, $2)', [testRunIdA, testRunIdB]);

    test('5.3: Assessment history isolates Run A and Run B completely', () => {
      assert.strictEqual(catScoresA[0].score, 55);
      assert.strictEqual(catScoresB[0].score, 100);
    });
  }

  // ─── Test 6: Severity Weights Invariant ──────────────────────────────────────
  console.log('\n--- Test 6: Severity Penalties Formula Invariant ---');
  {
    test('6.1: Critical deduction is 25', () => {
      const f = [{ id: 'SEC-001', category: 'Security', severity: 'Critical', status: 'FAIL' }];
      assert.strictEqual(calculateOverallScore(f), 75);
    });

    test('6.2: High deduction is 15', () => {
      const f = [{ id: 'SEC-001', category: 'Security', severity: 'High', status: 'FAIL' }];
      assert.strictEqual(calculateOverallScore(f), 85);
    });

    test('6.3: Medium deduction is 8', () => {
      const f = [{ id: 'SEC-001', category: 'Security', severity: 'Medium', status: 'FAIL' }];
      assert.strictEqual(calculateOverallScore(f), 92);
    });

    test('6.4: Low deduction is 3', () => {
      const f = [{ id: 'SEC-001', category: 'Security', severity: 'Low', status: 'FAIL' }];
      assert.strictEqual(calculateOverallScore(f), 97);
    });

    test('6.5: NEEDS_REVIEW and NOT_APPLICABLE do not penalize scores', () => {
      const f = [
        { id: 'SEC-001', category: 'Security', severity: 'Critical', status: 'NEEDS_REVIEW' },
        { id: 'SEC-002', category: 'Security', severity: 'High', status: 'NOT_APPLICABLE' },
      ];
      assert.strictEqual(calculateOverallScore(f), 100);
    });
  }

  console.log('\n======================================================');
  console.log(`  Tests Completed: ${passed} passed, ${failed} failed`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test execution failed:', err);
    process.exit(1);
  });
