/**
 * AccountRecovery.jsx — Account recovery flow testing and simulation
 */
import React, { useState } from 'react';
import FindingCard from '../components/FindingCard';
import { recoveryFindings } from '../data/mockData';

const SCENARIOS = [
  {
    id: 'expired-link',
    label: 'Expired Reset Link',
    code: 'REC-001',
    description: 'Verifies whether reset tokens expire strictly within 60 minutes.',
  },
  {
    id: 'reused-token',
    label: 'Token Invalidation',
    code: 'REC-002',
    description: 'Ensures single-use reset tokens cannot be consumed multiple times.',
  },
  {
    id: 'email-enumeration',
    label: 'Email Enumeration',
    code: 'REC-003',
    description: 'Checks if password reset forms leak user existence via error responses.',
  },
  {
    id: 'lockout-recovery',
    label: 'Lockout Recovery',
    code: 'REC-004',
    description: 'Tests automated self-service account unlocking mechanisms.',
  },
];

const SCENARIO_DETAILS = {
  'expired-link': {
    title: 'Expired Reset Link Scenario',
    findingRef: 'REC-001',
    content: (
      <div>
        <div className="notice error mb-12">
          Password reset token expired 2 hours ago but was accepted by the endpoint.
        </div>
        <p className="finding-text mb-12">
          Unlimited-lifetime tokens enable attackers to utilize intercepted reset links indefinitely if access to email records or proxy logs is achieved.
        </p>
        <div className="notice success">
          <strong>Recommended Policy:</strong> Set strict expiration (&le; 15–60 minutes) and tie token validity to user password version counters.
        </div>
      </div>
    ),
  },
  'reused-token': {
    title: 'Reused Reset Token Scenario',
    findingRef: 'REC-002',
    content: (
      <div>
        <div className="notice warning mb-12">
          Password was successfully updated. Token remained valid for subsequent requests.
        </div>
        <p className="finding-text mb-12">
          Failing to immediately burn tokens upon first use allows concurrent sessions or browser history replay attacks to hijack accounts.
        </p>
        <div className="notice success">
          <strong>Recommended Policy:</strong> Invalidate tokens immediately in a transactional database write upon successful password update.
        </div>
      </div>
    ),
  },
  'email-enumeration': {
    title: 'Email Enumeration Response Analysis',
    findingRef: 'REC-003',
    content: (
      <div>
        <div className="notice error mb-12">
          Response: "No user account exists for this email address." (Status 404)
        </div>
        <p className="finding-text mb-12">
          Differentiated responses allow attackers to automate dictionary scans against password reset endpoints to confirm registered target accounts.
        </p>
        <div className="notice success">
          <strong>Recommended Policy:</strong> Always return uniform response: "If an account exists, a recovery email has been dispatched."
        </div>
      </div>
    ),
  },
  'lockout-recovery': {
    title: 'Account Lockout & Self-Service Unlock',
    findingRef: 'REC-004',
    content: (
      <div>
        <div className="notice error mb-12">
          Account locked following 5 failed attempts. System mandates manual support ticket.
        </div>
        <p className="finding-text mb-12">
          Mandatory manual support unlocks inflict severe operational overhead and expose organizations to social engineering attack vectors.
        </p>
        <div className="notice info">
          <strong>Recommended Policy:</strong> Implement automated time-based exponential backoff plus out-of-band email unlock links.
        </div>
      </div>
    ),
  },
};

export default function AccountRecovery() {
  const [activeScenario, setActiveScenario] = useState('expired-link');

  const passing = recoveryFindings.filter((f) => f.severity === 'info' || f.severity === 'pass').length;
  const failing = recoveryFindings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;

  const currentScenario = SCENARIO_DETAILS[activeScenario];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Account Recovery</h1>
            <p className="page-subtitle">Evaluation of password reset lifecycles, token entropy, and enumeration risks</p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span className="badge badge-fail">{failing} High-Risk Flaws</span>
            <span className="badge badge-sample">4 Scenarios Configured</span>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Interactive Scenario Sandbox */}
        <div className="section">
          <div className="section-header">
            <h2 className="section-title">Interactive Recovery Simulations</h2>
          </div>

          <div className="grid-2" style={{ alignItems: 'start' }}>
            {/* Scenario selector */}
            <div className="card" style={{ padding: '8px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {SCENARIOS.map((s) => (
                  <button
                    key={s.id}
                    id={`scenario-${s.id}`}
                    className={`demo-scenario-btn${activeScenario === s.id ? ' active' : ''}`}
                    onClick={() => setActiveScenario(s.id)}
                    style={{ padding: '10px 12px' }}
                  >
                    <span className="mono text-xs" style={{ minWidth: '55px', color: 'var(--text-muted)' }}>
                      {s.code}
                    </span>
                    <div style={{ textAlign: 'left', flex: 1 }}>
                      <div style={{ fontWeight: 500 }}>{s.label}</div>
                      <div className="text-muted text-xs" style={{ marginTop: '2px' }}>{s.description}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Scenario details panel */}
            <div className="card">
              <div className="card-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>{currentScenario.title}</span>
                <span className="mono text-xs">{currentScenario.findingRef}</span>
              </div>
              {currentScenario.content}
            </div>
          </div>
        </div>

        {/* Recovery Findings List */}
        <div className="section">
          <div className="section-header">
            <h2 className="section-title">Recovery Audit Findings</h2>
            <span className="text-muted text-xs">{recoveryFindings.length} checks</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {recoveryFindings.map((f) => (
              <FindingCard key={f.id} finding={f} showCode={true} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
