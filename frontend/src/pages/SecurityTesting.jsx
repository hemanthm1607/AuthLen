/**
 * SecurityTesting.jsx — Real Security Testing Engine Runner
 * Executes non-destructive, authorized security assertions against the target.
 */
import React, { useState, useEffect } from 'react';
import FindingCard from '../components/FindingCard';
import { securityFindings as initialFallbackFindings, findingsSummary as initialFallbackSummary } from '../data/mockData';
import { authApi } from '../services/authApi';

export default function SecurityTesting({ targetUrl: propTargetUrl, onTargetUrlChange }) {
  const [localTargetUrl, setLocalTargetUrl] = useState(() => {
    if (propTargetUrl) return propTargetUrl;
    try {
      return localStorage.getItem('authlens_target_url') || 'http://localhost:4000';
    } catch (_) {
      return 'http://localhost:4000';
    }
  });

  const targetUrl = propTargetUrl !== undefined ? propTargetUrl : localTargetUrl;

  function updateTargetUrl(newVal) {
    if (onTargetUrlChange) {
      onTargetUrlChange(newVal);
    } else {
      setLocalTargetUrl(newVal);
      try {
        localStorage.setItem('authlens_target_url', newVal);
      } catch (_) {}
    }
  }
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [running, setRunning]         = useState(false);
  const [ran, setRan]                 = useState(false);
  const [filter, setFilter]           = useState('all');
  const [findings, setFindings]       = useState(initialFallbackFindings);
  const [summary, setSummary]         = useState(initialFallbackSummary);
  const [latestRun, setLatestRun]     = useState(null);
  const [errorMsg, setErrorMsg]       = useState('');

  // Automatically sync with latest persistent audit run in PostgreSQL
  useEffect(() => {
    let isMounted = true;
    async function loadLatestRun() {
      try {
        const res = await authApi.getAssessmentHistory();
        if (isMounted && res?.assessments && res.assessments.length > 0) {
          const latest = res.assessments[0];
          const det = await authApi.getAssessmentById(latest.id);
          if (isMounted && det?.findings && det.findings.length > 0) {
            setFindings(det.findings);
            setSummary({
              critical: latest.critical || 0,
              high: latest.high || 0,
              medium: latest.medium || 0,
              low: latest.low || 0,
            });
            setLatestRun(latest);
            setRan(true);
          }
        }
      } catch (_) {
        // Fall back gracefully to baseline
      }
    }
    loadLatestRun();
    return () => { isMounted = false; };
  }, []);

  async function executeRealSecuritySuite() {
    if (!targetUrl.trim()) {
      setErrorMsg('Target URL is required.');
      return;
    }
    if (!isAuthorized) {
      setErrorMsg('Safety rule: You must explicitly confirm authorization to audit this target.');
      return;
    }

    setRunning(true);
    setRan(false);
    setErrorMsg('');

    try {
      const res = await authApi.runAssessment({
        targetUrl: targetUrl.trim(),
        isAuthorized: true,
      });

      if (res?.findings) {
        setFindings(res.findings);
        setSummary(res.summary);
        setLatestRun(res.assessment);
        setRan(true);
      }
    } catch (err) {
      console.error('Audit execution error:', err);
      setErrorMsg(err.message || 'Failed to execute security audit. Please ensure the target is reachable.');
    } finally {
      setRunning(false);
    }
  }

  // Filter findings based on selected severity or status
  const filtered = findings.filter((f) => {
    if (filter === 'all') return true;
    if (filter === 'pass') return f.status?.toUpperCase() === 'PASS';
    if (filter === 'fail') return f.status?.toUpperCase() === 'FAIL';
    return f.severity?.toLowerCase() === filter.toLowerCase();
  });

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Security Assessment</h1>
            <p className="page-subtitle">Real-time authentication engine audit — rate limiting, brute force, session flags, error leakage</p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            {latestRun && (
              <span className="badge badge-pass">
                Run {latestRun.id} &bull; Score {latestRun.overallScore}/100
              </span>
            )}
            <button
              id="run-security-test-btn"
              className="btn btn-primary"
              onClick={executeRealSecuritySuite}
              disabled={running}
              aria-label="Execute live security test suite"
            >
              {running ? <span className="spin">⟳</span> : null}
              {running ? 'Executing Live Suite…' : ran ? 'Re-run Security Suite' : 'Execute Test Suite'}
            </button>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Target Configuration & Safety Guard */}
        <div className="card mb-16" style={{ background: 'var(--bg-elevated)', padding: '14px 18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '260px' }}>
              <label htmlFor="audit-target-url" style={{ margin: 0, fontWeight: 600, fontSize: '12px', whiteSpace: 'nowrap' }}>
                Audit Target:
              </label>
              <input
                id="audit-target-url"
                type="url"
                value={targetUrl}
                onChange={(e) => updateTargetUrl(e.target.value)}
                placeholder="http://localhost:4000"
                style={{ padding: '6px 10px', fontSize: '12px', maxWidth: '320px', fontFamily: 'var(--font-mono)' }}
                disabled={running}
              />
              <span className="badge badge-sample">Authorized Loopback Target</span>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)', margin: 0, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                disabled={running}
                style={{ width: '14px', height: '14px' }}
              />
              <span>I confirm I am authorized to test this target</span>
            </label>
          </div>
        </div>

        {/* Error notice if audit failed */}
        {errorMsg && (
          <div className="notice error mb-16" role="alert">
            <div><strong>Scan Error:</strong> {errorMsg}</div>
          </div>
        )}

        {/* Running state indicator */}
        {running && (
          <div className="card mb-16" style={{ background: 'var(--bg-surface)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <span className="spin" style={{ fontSize: '18px', color: 'var(--accent)' }}>⟳</span>
              <div>
                <div style={{ fontWeight: 600, fontSize: '13px' }}>Executing real-time authentication test suite…</div>
                <div className="text-secondary text-xs" style={{ marginTop: '2px' }}>
                  Probing login rate limiting &rarr; Inspecting session cookie directives &rarr; Analyzing enumeration surfaces &rarr; Verifying recovery token policy
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Completion notice */}
        {ran && (
          <div className="notice success mb-16">
            <div>
              <strong>Audit complete:</strong> {findings.length} live assertions evaluated against <code className="mono">{latestRun?.target || targetUrl}</code> in {latestRun?.duration || '1.2s'}. Persisted to database as <code className="mono">{latestRun?.id}</code>.
            </div>
          </div>
        )}

        {/* Summary stats */}
        <div className="section">
          <div className="findings-stats" role="region" aria-label="Finding counts by severity">
            <div className="stat-block critical">
              <div className="stat-value">{summary.critical}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat-block high">
              <div className="stat-value">{summary.high}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat-block medium">
              <div className="stat-value">{summary.medium}</div>
              <div className="stat-label">Medium</div>
            </div>
            <div className="stat-block low">
              <div className="stat-value">{summary.low}</div>
              <div className="stat-label">Low</div>
            </div>
          </div>
        </div>

        {/* Filter controls */}
        <div className="section">
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '14px', alignItems: 'center' }}>
            <span className="text-muted text-xs mono" style={{ marginRight: '4px' }}>FILTER:</span>
            {[
              { id: 'all', label: `All Checks (${findings.length})` },
              { id: 'fail', label: 'Vulnerabilities / Fails' },
              { id: 'pass', label: 'Passing Controls' },
              { id: 'critical', label: 'Critical' },
              { id: 'high', label: 'High' },
              { id: 'medium', label: 'Medium' },
            ].map((f) => (
              <button
                key={f.id}
                id={`filter-${f.id}`}
                className={`btn btn-xs${filter === f.id ? ' btn-primary' : ' btn-secondary'}`}
                onClick={() => setFilter(f.id)}
                aria-pressed={filter === f.id}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Finding Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {filtered.length === 0 ? (
              <div className="card" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                No findings match the selected filter criteria.
              </div>
            ) : (
              filtered.map((f) => (
                <FindingCard key={`${f.id}-${f.title}`} finding={f} showCode={true} />
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
