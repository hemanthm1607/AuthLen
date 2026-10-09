/**
 * testing-engine/accessibility/index.js — WCAG 2.1 AA Accessibility Evaluation Module
 * Evaluates semantic markup, ARIA roles, input labels, and keyboard navigability based on verified evidence.
 */
const { safeFetch } = require('../utils/targetValidator');

async function run(target) {
  const findings = [];
  const probe = await safeFetch(target.url, { timeout: 3000 });

  if (probe.status >= 500 || probe.failed || probe.timedOut) {
    const errorEvidence = `Target ${target.url} returned HTTP ${probe.status || (probe.timedOut ? 'timeout' : 'error')}. Accessibility controls cannot be verified on a server error.`;
    
    findings.push({
      id: 'A11Y-001',
      title: 'Explicit <label> association for credential fields',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: errorEvidence,
      risk: 'Accessibility controls unverified due to target error.',
      recommendation: 'Resolve target server error before auditing accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-002',
      title: 'Keyboard focus visibility and tab order integrity',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: errorEvidence,
      risk: 'Accessibility controls unverified due to target error.',
      recommendation: 'Resolve target server error before auditing accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-003',
      title: 'Accessible ARIA status regions for dynamic error messages',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: errorEvidence,
      risk: 'Accessibility controls unverified due to target error.',
      recommendation: 'Resolve target server error before auditing accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-004',
      title: 'Standard autocomplete attributes on authentication fields',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: errorEvidence,
      risk: 'Accessibility controls unverified due to target error.',
      recommendation: 'Resolve target server error before auditing accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    return findings;
  }

  const bodyText = probe.text || '';
  const lowerHtml = bodyText.toLowerCase();
  const isHtml = (probe.headers && probe.headers['content-type'] && probe.headers['content-type'].includes('text/html')) ||
    lowerHtml.includes('<html') || lowerHtml.includes('<!doctype html') || lowerHtml.includes('<body');
  const hasInputElements = lowerHtml.includes('<input') || lowerHtml.includes('<form');

  if (!isHtml || !hasInputElements) {
    const naEvidence = `Target response at ${target.url} does not contain an authentication form or credential input elements (<input>, <form>). Check is not applicable to non-UI or generic endpoints.`;

    findings.push({
      id: 'A11Y-001',
      title: 'Explicit <label> association for credential fields',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: naEvidence,
      risk: 'Non-UI or API endpoint without interactive credential inputs.',
      recommendation: 'Provide URL pointing directly to an interactive authentication view to evaluate UI accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-002',
      title: 'Keyboard focus visibility and tab order integrity',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: naEvidence,
      risk: 'Non-UI or API endpoint without interactive credential inputs.',
      recommendation: 'Provide URL pointing directly to an interactive authentication view to evaluate UI accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-003',
      title: 'Accessible ARIA status regions for dynamic error messages',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: naEvidence,
      risk: 'Non-UI or API endpoint without interactive credential inputs.',
      recommendation: 'Provide URL pointing directly to an interactive authentication view to evaluate UI accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'A11Y-004',
      title: 'Standard autocomplete attributes on authentication fields',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: naEvidence,
      risk: 'Non-UI or API endpoint without interactive credential inputs.',
      recommendation: 'Provide URL pointing directly to an interactive authentication view to evaluate UI accessibility.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    return findings;
  }

  // ── A11Y-001: Explicit Form Input Labels ──
  const hasLabels = lowerHtml.includes('<label') || lowerHtml.includes('aria-label') || lowerHtml.includes('aria-labelledby');
  if (hasLabels) {
    findings.push({
      id: 'A11Y-001',
      title: 'Explicit <label> association for credential fields',
      category: 'Accessibility',
      severity: 'Info',
      status: 'PASS',
      evidence: 'Inputs on auth interface utilize explicit <label> associations or aria-label pairings.',
      risk: 'Missing labels prevent screen readers from announcing field purpose to visually impaired users (WCAG 1.3.1, 4.1.2).',
      recommendation: 'Ensure every interactive form element has an explicit associated label or aria-label.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'A11Y-001',
      title: 'Missing <label> association for credential fields',
      category: 'Accessibility',
      severity: 'Medium',
      status: 'FAIL',
      evidence: 'Form input elements detected without associated <label> or aria-label attributes.',
      risk: 'Missing labels prevent screen readers from announcing field purpose to visually impaired users (WCAG 1.3.1, 4.1.2).',
      recommendation: 'Ensure every interactive form element has an explicit associated label or aria-label.',
      codeBefore: '<input type="email" placeholder="Email" />',
      codeAfter: '<label htmlFor="email">Work Email</label>\n<input id="email" type="email" />',
      isAutomated: true,
    });
  }

  // ── A11Y-002: Keyboard Navigation & Focus Visible ──
  const hasOutlineSuppression = /outline\s*:\s*(none|0)\b/i.test(bodyText) && !/focus-visible|:focus/i.test(bodyText);
  if (hasOutlineSuppression) {
    findings.push({
      id: 'A11Y-002',
      title: 'Focus visibility indicator suppression',
      category: 'Accessibility',
      severity: 'Medium',
      status: 'FAIL',
      evidence: 'Detected focus outline suppression (outline: none) without high-contrast focus replacement.',
      risk: 'Removing focus indicators traps or disorients keyboard-only users navigating without a pointer (WCAG 2.4.7).',
      recommendation: 'Never suppress focus outlines without providing high-contrast focus rings.',
      codeBefore: 'button:focus { outline: none; }',
      codeAfter: 'button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }',
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'A11Y-002',
      title: 'Keyboard focus visibility and tab order integrity',
      category: 'Accessibility',
      severity: 'Info',
      status: 'PASS',
      evidence: 'Interactive elements maintain visible focus indicators without global outline suppression.',
      risk: 'Removing focus indicators traps or disorients keyboard-only users navigating without a pointer (WCAG 2.4.7).',
      recommendation: 'Never suppress focus outlines without providing high-contrast focus rings.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── A11Y-003: ARIA Alert Regions for Validation Errors ──
  const hasAriaAlert = lowerHtml.includes('role="alert"') || lowerHtml.includes("role='alert'") || lowerHtml.includes('aria-live');
  if (hasAriaAlert) {
    findings.push({
      id: 'A11Y-003',
      title: 'Accessible ARIA status regions for dynamic error messages',
      category: 'Accessibility',
      severity: 'Info',
      status: 'PASS',
      evidence: 'Validation errors utilize role="alert" with aria-live status regions to announce errors immediately to assistive technologies.',
      risk: 'Silent visual error messages fail to notify users of screen readers when form validation rejects submission (WCAG 4.1.3).',
      recommendation: 'Render validation errors inside container elements marked with role="alert".',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'A11Y-003',
      title: 'Accessible ARIA status regions for dynamic error messages',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: 'No static role="alert" or aria-live containers detected in initial HTML markup. Dynamic client-side error containers should be verified.',
      risk: 'Silent visual error messages fail to notify users of screen readers when form validation rejects submission (WCAG 4.1.3).',
      recommendation: 'Render validation errors inside container elements marked with role="alert".',
      codeBefore: '<div className="error">{error}</div>',
      codeAfter: '<div className="error" role="alert" aria-live="assertive">{error}</div>',
      isAutomated: true,
    });
  }

  // ── A11Y-004: Standard Credential Autocomplete Attributes ──
  const hasAutocomplete = lowerHtml.includes('autocomplete="') || lowerHtml.includes("autocomplete='") || lowerHtml.includes('autocomplete=');
  if (hasAutocomplete) {
    findings.push({
      id: 'A11Y-004',
      title: 'Standard autocomplete attributes on authentication fields',
      category: 'Accessibility',
      severity: 'Info',
      status: 'PASS',
      evidence: 'Credential inputs declare standard autocomplete attributes in HTML markup.',
      risk: 'Missing autocomplete hinders assistive password manager auto-fill and cognitive accessibility for users with disabilities (WCAG 1.3.5).',
      recommendation: 'Specify autocomplete="username" and autocomplete="current-password" on credential fields.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'A11Y-004',
      title: 'Standard autocomplete attributes on authentication fields',
      category: 'Accessibility',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: 'Credential inputs did not declare standard autocomplete attributes in static HTML markup.',
      risk: 'Missing autocomplete hinders assistive password manager auto-fill and cognitive accessibility for users with disabilities (WCAG 1.3.5).',
      recommendation: 'Specify autocomplete="username" and autocomplete="current-password" on credential fields.',
      codeBefore: '<input type="password" />',
      codeAfter: '<input type="password" autoComplete="current-password" />',
      isAutomated: true,
    });
  }

  return findings;
}

module.exports = { run };
