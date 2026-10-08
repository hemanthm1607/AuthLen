/**
 * Dashboard.jsx — Overview page with scores, findings summary, and activity
 * Displays live scores from PostgreSQL assessment runs with fallback to baseline.
 */
import React, { useState, useEffect } from 'react';
import ScoreCard from '../components/ScoreCard';
import { dashboardScores as fallbackScores, findingsSummary as fallbackSummary, recentActivity as fallbackActivity } from '../data/mockData';
import { authApi } from '../services/authApi';

function getPostureMeta(score) {
  if (score >= 90) return { grade: 'A', status: 'Exceptional', badgeClass: 'badge-pass' };
  if (score >= 80) return { grade: 'B+', status: 'Secure', badgeClass: 'badge-pass' };
  if (score >= 70) return { grade: 'B', status: 'Adequate', badgeClass: 'badge-sample' };
  if (score >= 60) return { grade: 'C', status: 'Needs Hardening', badgeClass: 'badge-fail' };
  if (score >= 50) return { grade: 'D', status: 'Elevated Risk', badgeClass: 'badge-fail' };
  return { grade: 'F', status: 'Critical Risk', badgeClass: 'badge-fail' };
}

export default function Dashboard({ onNavigate }) {
  const [scores, setScores]           = useState(fallbackScores);
  const [summary, setSummary]         = useState(fallbackSummary);
  const [latestRun, setLatestRun]     = useState(null);
  const [historyRuns, setHistoryRuns] = useState([]);
  const [isLoading, setIsLoading]     = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function loadLatestMetrics() {
      try {
        const res = await authApi.getAssessmentHistory();
        if (isMounted && res?.assessments && res.assessments.length > 0) {
          setHistoryRuns(res.assessments);
          const latest = res.assessments[0];
          setLatestRun(latest);
          setSummary({
            critical: latest.critical || 0,
            high: latest.high || 0,
            medium: latest.medium || 0,
            low: latest.low || 0,
          });
        }
      } catch (err) {
        // Fall back gracefully
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    loadLatestMetrics();
    return () => { isMounted = false; };
  }, []);

  const total =
    summary.critical +
    summary.high +
    summary.medium +
    summary.low;

  const overallScore = latestRun
    ? latestRun.overallScore
    : Math.round(scores.reduce((acc, s) => acc + s.score, 0) / scores.length);

  const posture = getPostureMeta(overallScore);

  // Derive real recent events from PostgreSQL runs or fall back to baseline
  const activityItems = historyRuns.length > 0
    ? historyRuns.slice(0, 5).map((run) => {
        const isGood = run.overallScore >= 80;
        const isMid = run.overallScore >= 60;
        return {
          id: run.id,
          title: `Security Audit ${run.id}: ${run.target || 'http://localhost:4000'}`,
          desc: `Score: ${run.overallScore}/100 • Critical: ${run.critical || 0}, High: ${run.high || 0}, Medium: ${run.medium || 0}, Low: ${run.low || 0}`,
          time: run.date ? new Date(run.date).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Recorded',
          dot: isGood ? 'green' : isMid ? 'blue' : 'amber',
        };
      })
    : fallbackActivity;

  function handleDomainClick(domainId) {
    if (!onNavigate) return;
    if (domainId === 'security') onNavigate('security');
    else if (domainId === 'usability' || domainId === 'accessibility') onNavigate('usability');
    else if (domainId === 'recovery') onNavigate('recovery');
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-subtitle">
              Authentication security posture — {latestRun ? latestRun.target : 'http://localhost:4000 (Target)'}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span className="badge badge-sample">
              {latestRun ? `Run ${latestRun.id}` : 'Engine Initialized'}
            </span>
            <span className={`badge ${posture.badgeClass}`}>
              <span className={`status-dot ${overallScore >= 70 ? 'green' : 'amber'}`} style={{ marginRight: '4px' }}></span>
              Grade {posture.grade} &bull; {posture.status}
            </span>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Overall score hero */}
        <div className="section">
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '24px' }}>
              <div>
                <div className="card-title" style={{ marginBottom: '6px' }}>
                  Overall Security Posture
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                  <span style={{ fontSize: '48px', fontWeight: 800, letterSpacing: '-0.03em', color: 'var(--text-primary)', lineHeight: 1 }}>
                    {overallScore}
                  </span>
                  <span style={{ fontSize: '18px', color: 'var(--text-muted)', fontWeight: 500 }}>/100</span>
                  <span className={`badge ${posture.badgeClass}`} style={{ marginLeft: '6px', fontSize: '11px' }}>
                    Grade {posture.grade}
                  </span>
                </div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '8px', fontSize: '12px' }}>
                  {latestRun
                    ? `Aggregated from persistent audit run ${latestRun.id} • Target: ${latestRun.target || 'http://localhost:4000'}`
                    : `Aggregated from ${total} active verification checks across 4 evaluation domains`}
                </div>

                {/* Quick Action Navigation Buttons */}
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '16px' }}>
                  <button
                    id="quick-start-audit-btn"
                    className="btn btn-primary btn-sm"
                    onClick={() => onNavigate && onNavigate('security')}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z"/>
                      <path d="M6 8l1.5 1.5L10 6.5"/>
                    </svg>
                    Run Security Audit
                  </button>
                  <button
                    id="quick-ai-remediation-btn"
                    className="btn btn-secondary btn-sm"
                    onClick={() => onNavigate && onNavigate('ai')}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <path d="M8 2v12M2 8h12M4.5 4.5l7 7M11.5 4.5l-7 7"/>
                    </svg>
                    AI Recommendations
                  </button>
                  <button
                    id="quick-history-btn"
                    className="btn btn-secondary btn-sm"
                    onClick={() => onNavigate && onNavigate('history')}
                  >
                    Audit Ledger ({historyRuns.length})
                  </button>
                </div>
              </div>

              {/* Findings Stats Counter */}
              <div className="findings-stats" style={{ minWidth: '320px' }}>
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
          </div>
        </div>

        {/* Category scores */}
        <div className="section">
          <div className="section-header">
            <h2 className="section-title">Evaluation Domains</h2>
            <span className="text-muted text-xs">Select any domain to inspect findings & re-test</span>
          </div>
          <div className="grid-4">
            {scores.map((s) => (
              <ScoreCard
                key={s.id}
                id={s.id}
                label={s.label}
                score={s.score}
                max={s.max}
                trend={s.trend}
                onClick={() => handleDomainClick(s.id)}
              />
            ))}
          </div>
        </div>

        {/* Recent activity & Workflow */}
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Audit Ledger & Activity</h2>
              <span className="text-muted text-xs">PostgreSQL Active Runs</span>
            </div>
            <div className="card" style={{ padding: '4px 18px' }}>
              <div className="activity-list">
                {activityItems.map((item) => (
                  <div className="activity-item" key={item.id}>
                    <div className={`activity-dot ${item.dot}`} aria-hidden="true" />
                    <div className="activity-content">
                      <div className="activity-title">{item.title}</div>
                      <div className="activity-desc">{item.desc}</div>
                      <div className="activity-time">{item.time}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Workflow card */}
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Audit Lifecycle</h2>
              <span className="text-muted text-xs">Continuous Verification Pipeline</span>
            </div>
            <div className="card">
              {[
                { step: '01', label: 'TEST', desc: 'Automated test suite probes login, reset, and session endpoints.' },
                { step: '02', label: 'DETECT', desc: 'Identifies security vulnerabilities, accessibility flaws, and UX friction.' },
                { step: '03', label: 'EXPLAIN', desc: 'Contextualizes each finding with root cause analysis and impact severity.' },
                { step: '04', label: 'FIX', desc: 'Provides actionable, framework-specific code remediations via Gemini.' },
                { step: '05', label: 'RE-TEST', desc: 'Re-runs verification suite to confirm complete resolution.' },
              ].map((w) => (
                <div key={w.step} style={{ display: 'flex', gap: '12px', marginBottom: '14px', alignItems: 'flex-start' }}>
                  <div
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: 'var(--r-sm)',
                      background: 'var(--bg-elevated)',
                      border: '1px solid var(--border-strong)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '11px',
                      fontWeight: 600,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent)',
                      flexShrink: 0,
                    }}
                  >
                    {w.step}
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '1px' }}>
                      {w.label}
                    </div>
                    <div className="text-secondary text-xs">{w.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
