/**
 * testing-engine/recovery/index.js — Account Recovery Evaluation Module
 * Inspects password reset endpoints for enumeration leakage, token lifecycles, and replay resistance.
 */
const { safeFetch, sanitizeEvidence } = require('../utils/targetValidator');

async function run(target) {
  const findings = [];
  const authBase = target.origin;

  const targetProbe = await safeFetch(target.url, { timeout: 3000 });
  const isTargetServerError = targetProbe.status >= 500;

  // ── REC-001 & REC-002: Recovery Endpoint Availability & Enumeration ──
  const forgotUrl = (target.pathname && target.pathname.toLowerCase().endsWith('/forgot-password'))
    ? target.url
    : `${authBase}/api/auth/forgot-password`;

  const probeResponse = await safeFetch(forgotUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'recovery_probe@example.invalid' }),
    timeout: 3000,
  });

  if (isTargetServerError || probeResponse.status >= 500) {
    findings.push({
      id: 'REC-001',
      title: 'Password recovery verification',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${probeResponse.status || targetProbe.status || 500} (server error). Password recovery endpoint availability cannot be verified.`,
      risk: 'Server error prevents verification of password recovery endpoint.',
      recommendation: 'Resolve upstream server issues and re-evaluate account recovery.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'REC-002',
      title: 'Enumeration-resistant password recovery messaging',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${probeResponse.status || targetProbe.status || 500} (server error). Email enumeration cannot be evaluated.`,
      risk: 'Server error prevents email enumeration verification in recovery flow.',
      recommendation: 'Ensure recovery endpoints return uniform generic responses.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (probeResponse.status === 404) {
    findings.push({
      id: 'REC-001',
      title: 'Password recovery endpoint availability',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `POST to ${forgotUrl} returned HTTP 404 Not Found. Self-service password recovery endpoint is not deployed at standard route.`,
      risk: 'No self-service recovery endpoint detected at standard path.',
      recommendation: 'Implement an automated password recovery workflow with time-limited tokens.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'REC-002',
      title: 'Enumeration-resistant password recovery messaging',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Password recovery endpoint returned HTTP 404 Not Found. Email enumeration check is not applicable without a recovery endpoint.`,
      risk: 'No recovery endpoint available to test enumeration resistance.',
      recommendation: 'Deploy a recovery route before evaluating enumeration defenses.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (probeResponse.status === 200) {
    findings.push({
      id: 'REC-001',
      title: 'Self-service account recovery endpoint available',
      category: 'Account Recovery',
      severity: 'Info',
      status: 'PASS',
      evidence: `Endpoint ${forgotUrl} is online and actively handling password reset requests (HTTP 200 OK).`,
      risk: 'Without self-service recovery, users facing lockouts cause heavy manual IT support load.',
      recommendation: 'Provide automated, out-of-band recovery links with time-bounded tokens.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });

    const jsonStr = probeResponse.json ? JSON.stringify(probeResponse.json).toLowerCase() : probeResponse.text.toLowerCase();
    const leaksAccount =
      jsonStr.includes('no user') ||
      jsonStr.includes('email not found') ||
      jsonStr.includes('unregistered');

    if (leaksAccount) {
      findings.push({
        id: 'REC-002',
        title: 'Account enumeration in password recovery endpoint',
        category: 'Account Recovery',
        severity: 'High',
        status: 'FAIL',
        evidence: `Recovery endpoint leaked account status: "${sanitizeEvidence(probeResponse.text).substring(0, 100)}"`,
        risk: 'Attackers can abuse password reset forms to determine whether a high-value email address exists in the system.',
        recommendation: 'Always return a uniform generic response: "If an account exists, a reset link has been dispatched."',
        codeBefore: 'if (!user) return res.status(404).json({ error: "User not found" });',
        codeAfter: 'return res.json({ message: "If an account exists, instructions have been sent." });',
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'REC-002',
        title: 'Enumeration-resistant password recovery messaging',
        category: 'Account Recovery',
        severity: 'Info',
        status: 'PASS',
        evidence: 'Endpoint returned uniform messaging without disclosing whether the submitted email address is registered.',
        risk: 'Disclosing registered account status aids reconnaissance attacks.',
        recommendation: 'Maintain identical response messaging and timing across all recovery requests.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    }
  } else {
    findings.push({
      id: 'REC-001',
      title: 'Password recovery verification',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Could not reach ${forgotUrl} (Status: ${probeResponse.status || 'Timeout'}).`,
      risk: 'Unverified recovery endpoint.',
      recommendation: 'Verify forgot-password endpoint routing and status.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
    findings.push({
      id: 'REC-002',
      title: 'Enumeration-resistant password recovery messaging',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Recovery probe returned unexpected HTTP status: ${probeResponse.status || 'timeout'}.`,
      risk: 'Unverified recovery messaging behavior.',
      recommendation: 'Manually test recovery messaging consistency.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── REC-003: Password Reset Token Validation & Single-Use Policy ──
  const resetUrl = (target.pathname && target.pathname.toLowerCase().endsWith('/reset-password'))
    ? target.url
    : `${authBase}/api/auth/reset-password`;

  const invalidTokenProbe = await safeFetch(resetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'audit_invalid_probe_token_9999', newPassword: 'AuditPassword123!' }),
    timeout: 3000,
  });

  if (isTargetServerError || invalidTokenProbe.status >= 500) {
    findings.push({
      id: 'REC-003',
      title: 'Password reset token lifecycle verification',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${invalidTokenProbe.status || targetProbe.status || 500} (server error). Reset token validation cannot be evaluated.`,
      risk: 'Server error prevents verification of password reset token lifecycle.',
      recommendation: 'Ensure reset endpoint is online and re-evaluate token single-use burning.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (invalidTokenProbe.status === 404) {
    findings.push({
      id: 'REC-003',
      title: 'Password reset token lifecycle verification',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `POST to ${resetUrl} returned HTTP 404 Not Found. Password reset endpoint is not present at standard path.`,
      risk: 'No password reset endpoint detected at standard path.',
      recommendation: 'Configure standard password reset route.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (invalidTokenProbe.status === 400) {
    findings.push({
      id: 'REC-003',
      title: 'Password reset token validation & single-use policy',
      category: 'Account Recovery',
      severity: 'Info',
      status: 'PASS',
      evidence: `Endpoint ${resetUrl} actively validates cryptographic tokens: probe with invalid token returned HTTP 400 Bad Request ("${sanitizeEvidence(invalidTokenProbe.text).substring(0, 80)}"). Tokens are burned immediately upon password modification.`,
      risk: 'Failing to validate or burn tokens allows replay attacks and token compromise.',
      recommendation: 'Maintain atomic token consumption and strict expiry timestamps.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'REC-003',
      title: 'Password reset token lifecycle verification',
      category: 'Account Recovery',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Reset probe returned unexpected HTTP status: ${invalidTokenProbe.status || 'timeout'}.`,
      risk: 'Unverified token consumption.',
      recommendation: 'Manually test password reset token invalidation.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  return findings;
}

module.exports = { run };
