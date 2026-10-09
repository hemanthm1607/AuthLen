/**
 * scoring.test.js — Frontend unit tests for scoring engine
 */
import assert from 'node:assert';
import {
  calculateCategoryScores,
  calculateOverallScore,
  calculateSummary,
} from './scoring.js';

console.log('\n--- Frontend Scoring Engine Tests ---');

// Test 1: Example from problem prompt
// Target: https://the-internet.herokuapp.com/login
// 3 High, 0 Critical, 0 Medium, 0 Low.
const theInternetFindings = [
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

const catScores = calculateCategoryScores(theInternetFindings);
const overall = calculateOverallScore(theInternetFindings);
const summary = calculateSummary(theInternetFindings);

assert.strictEqual(overall, 55, 'Overall score must be 55');
assert.strictEqual(summary.failed, 3, 'Failed findings must be 3');
assert.strictEqual(summary.high, 3, 'High severity count must be 3');

const sec = catScores.find((c) => c.id === 'security');
assert.strictEqual(sec.score, 55, 'Security score must be 55');
assert.strictEqual(sec.statusText, 'Needs Hardening');

const use = catScores.find((c) => c.id === 'usability');
assert.strictEqual(use.score, null, 'Usability score must be null (Insufficient data)');
assert.strictEqual(use.statusText, 'Insufficient data');

const a11y = catScores.find((c) => c.id === 'accessibility');
assert.strictEqual(a11y.score, 100, 'Accessibility score must be 100');
assert.strictEqual(a11y.statusText, 'Secure');

const rec = catScores.find((c) => c.id === 'recovery');
assert.strictEqual(rec.score, null, 'Recovery score must be null (Not Applicable)');
assert.strictEqual(rec.statusText, 'Not Applicable');

// Test 2: Empty / unassessed target
const emptyScores = calculateCategoryScores([]);
emptyScores.forEach((c) => {
  assert.strictEqual(c.score, null, `${c.id} score must be null when unassessed`);
  assert.strictEqual(c.statusText, 'Not evaluated');
});

console.log('✓ All frontend scoring engine assertions passed cleanly!\n');
