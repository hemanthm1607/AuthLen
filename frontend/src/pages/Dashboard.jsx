/**
 * Dashboard.jsx — Overview page with scores, findings summary, and activity
 * Displays live scores from PostgreSQL assessment runs with fallback to baseline.
 */
import React, { useState, useEffect } from 'react';
import ScoreCard from '../components/ScoreCard';
import { dashboardScores as fallbackScores, findingsSummary as fallbackSummary, recentActivity } from '../data/mockData';
import { authApi } from '../services/authApi';

export default function Dashboard() {
  const [scores, setScores]       = useState(fallbackScores);
  const [summary, setSummary]     = useState(fallbackSummary);
  const [latestRun, setLatestRun] = useState(null);

  useEffect(() => {
    async function loadLatestMetrics() {
      try {
        const res = await authApi.getAssessmentHistory();
        if (res?.assessments && res.assessments.length > 0) {
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
      }
    }
    loadLatestMetrics();
  }, []);

  const total =
    summary.critical +
    summary.high +
    summary.medium +
    summary.low;

  const overallScore = latestRun
    ? latestRun.overallScore
    : Math.round(scores.reduce((acc, s) => acc + s.score, 0) / scores.length);

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-subtitle">Authentication security overview — {latestRun ? latestRun.target : 'Demo Auth Site v2.1'}</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="badge badge-sample">
              {latestRun ? `Run ${latestRun.id}` : 'Baseline Profile'}
            </span>
            <span className="badge badge-pass">
              <span className="status-dot green" style={{ marginRight: '4px' }}></span>
              Environment Ready
            </span>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Overall score hero */}
        <div className="section">
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px' }}>
              <div>
                <div className="card-title" style={{ marginBottom: '6px' }}>
                  Overall Security Posture
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                  <span style={{ fontSize: '44px', fontWeight: 700, letterSpacing: '-0.03em', color: 'var(--text-primary)', lineHeight: 1 }}>
                    {overallScore}
                  </span>
                  <span style={{ fontSize: '18px', color: 'var(--text-muted)', fontWeight: 400 }}>/100</span>
                </div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '8px', fontSize: '12px' }}>
                  {latestRun
                    ? `Aggregated from persistent audit ${latestRun.id} &bull; Audited target: ${latestRun.target}`
                    : `Aggregated from ${total} checks across 4 evaluation domains &bull; Audited target: demo.authlens.local`}
                </div>
              </div>

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
              />
            ))}
          </div>
        </div>

        {/* Recent activity & Workflow */}
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Recent Activity</h2>
              <span className="text-muted text-xs">Simulated live feed</span>
            </div>
            <div className="card" style={{ padding: '4px 18px' }}>
              <div className="activity-list">
                {recentActivity.map((item) => (
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
            </div>
            <div className="card">
              {[
                { step: '01', label: 'TEST', desc: 'Automated test suite probes login, reset, and session endpoints.' },
                { step: '02', label: 'DETECT', desc: 'Identifies security vulnerabilities, accessibility flaws, and UX friction.' },
                { step: '03', label: 'EXPLAIN', desc: 'Contextualizes each finding with root cause analysis and impact severity.' },
                { step: '04', label: 'FIX', desc: 'Provides actionable, framework-specific code remediations.' },
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
