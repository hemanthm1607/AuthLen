import React, { useState, useEffect, useCallback } from 'react';
import ScoreCard from '../components/ScoreCard';
import { recentActivity as fallbackActivity } from '../data/mockData';
import { calculateCategoryScores, calculateSummary } from '../utils/scoring';
import { authApi } from '../services/authApi';

function getPostureMeta(score) {
  if (typeof score !== 'number' || isNaN(score)) {
    return { grade: '—', status: 'Pending Audit', badgeClass: 'badge-sample' };
  }
  if (score >= 90) return { grade: 'A', status: 'Exceptional', badgeClass: 'badge-pass' };
  if (score >= 80) return { grade: 'B+', status: 'Secure', badgeClass: 'badge-pass' };
  if (score >= 70) return { grade: 'B', status: 'Adequate', badgeClass: 'badge-sample' };
  if (score >= 60) return { grade: 'C', status: 'Needs Hardening', badgeClass: 'badge-fail' };
  if (score >= 50) return { grade: 'D', status: 'Elevated Risk', badgeClass: 'badge-fail' };
  return { grade: 'F', status: 'Critical Risk', badgeClass: 'badge-fail' };
}

const INITIAL_SCORES = calculateCategoryScores([]);
const INITIAL_SUMMARY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
};

export default function Dashboard({ onNavigate, targetUrl: propTargetUrl }) {
  const [scores, setScores]           = useState(INITIAL_SCORES);
  const [summary, setSummary]         = useState(INITIAL_SUMMARY);
  const [selectedRun, setSelectedRun] = useState(null);
  const [historyRuns, setHistoryRuns] = useState([]);
  const [isLoading, setIsLoading]     = useState(true);

  // Active target URL: prop, or persistent storage, defaulting to http://localhost:4000
  const activeTargetUrl = propTargetUrl || (() => {
    try {
      return localStorage.getItem('authlens_target_url') || 'http://localhost:4000';
    } catch (_) {
      return 'http://localhost:4000';
    }
  })();

  // Load a specific run and its findings/category scores
  const loadRunDetail = useCallback(async (run) => {
    if (!run) return;
    try {
      const res = await authApi.getAssessmentById(run.id);
      if (res?.assessment) {
        setSelectedRun(res.assessment);
        if (res.summary) {
          setSummary(res.summary);
        } else {
          setSummary({
            critical: res.assessment.critical || 0,
            high: res.assessment.high || 0,
            medium: res.assessment.medium || 0,
            low: res.assessment.low || 0,
          });
        }
        if (res.categoryScores && Array.isArray(res.categoryScores)) {
          setScores(res.categoryScores);
        } else if (res.findings && Array.isArray(res.findings)) {
          setScores(calculateCategoryScores(res.findings));
        } else if (run.categoryScores) {
          setScores(run.categoryScores);
        }
        return;
      }
    } catch (_) {
      // If drill-down fetch fails, fall back to run metadata
    }

    // Fallback to top-level run metadata if available
    setSelectedRun(run);
    setSummary({
      critical: run.critical || 0,
      high: run.high || 0,
      medium: run.medium || 0,
      low: run.low || 0,
    });
    if (run.categoryScores && Array.isArray(run.categoryScores)) {
      setScores(run.categoryScores);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;
    async function loadLatestMetrics() {
      setIsLoading(true);
      try {
        const res = await authApi.getAssessmentHistory();
        if (isMounted && res?.assessments && res.assessments.length > 0) {
          setHistoryRuns(res.assessments);
          // Prefer run matching activeTargetUrl, otherwise latest run
          const matchingRun = res.assessments.find((r) => r.target === activeTargetUrl);
          const initialRun = matchingRun || res.assessments[0];
          await loadRunDetail(initialRun);
        }
      } catch (err) {
        // Fall back gracefully
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    loadLatestMetrics();
    return () => { isMounted = false; };
  }, [activeTargetUrl, loadRunDetail]);

  const total =
    summary.critical +
    summary.high +
    summary.medium +
    summary.low;

  const overallScore = selectedRun ? selectedRun.overallScore : 100;
  const posture = getPostureMeta(overallScore);

  function handleSelectRun(runId) {
    const targetRun = historyRuns.find((r) => r.id === runId);
    if (targetRun) {
      loadRunDetail(targetRun);
    }
  }

  // Derive real recent events from PostgreSQL runs or fall back to baseline
  const activityItems = historyRuns.length > 0
    ? historyRuns.slice(0, 5).map((run) => {
        const isGood = run.overallScore >= 80;
        const isMid = run.overallScore >= 60;
        return {
          id: run.id,
          title: `Security Audit ${run.id}: ${run.target || activeTargetUrl}`,
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
            <h1 className="page-title">Security Overview</h1>
            <p className="page-subtitle">
              Authentication security posture &bull; Target: <code className="mono">{activeTargetUrl}</code>
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span className="badge badge-sample">
              {selectedRun ? `Run ${selectedRun.id}` : 'Engine Initialized'}
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
          <div className="card overview-hero-card">
            <div className="overview-hero-layout">
              <div className="overview-hero-main">
                <div className="overview-hero-header">
                  <div className="card-title" style={{ marginBottom: 0 }}>
                    Overall Security Posture
                  </div>
                  <span className={`badge ${posture.badgeClass}`} style={{ fontSize: '11px' }}>
                    Grade {posture.grade} &bull; {posture.status}
                  </span>
                </div>

                <div className="overview-score-row">
                  <span className="overview-score-value">
                    {overallScore}
                  </span>
                  <span className="overview-score-max">/100</span>
                </div>

                <div className="overview-score-bar-wrap" role="progressbar" aria-valuenow={overallScore} aria-valuemin={0} aria-valuemax={100} aria-label={`Overall Security Score: ${overallScore}/100`}>
                  <div
                    className={`overview-score-bar ${overallScore >= 80 ? 'good-score' : overallScore >= 60 ? 'mid-score' : 'low-score'}`}
                    style={{ width: `${overallScore}%` }}
                  />
                </div>

                <div className="overview-meta-text">
                  {selectedRun
                    ? `Aggregated from persistent audit run ${selectedRun.id} • Target: ${selectedRun.target} • Active Configured Target: ${activeTargetUrl}`
                    : `No persistent assessment runs recorded yet. Active Target: ${activeTargetUrl}`}
                </div>

                {/* Quick Action Navigation Buttons */}
                <div className="overview-actions-row">
                  <button
                    id="quick-start-audit-btn"
                    className="btn btn-primary btn-sm"
                    onClick={() => onNavigate && onNavigate('security')}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z"/>
                      <path d="M6 8l1.5 1.5L10 6.5"/>
                    </svg>
                    Run Security Assessment
                  </button>
                  <button
                    id="quick-ai-remediation-btn"
                    className="btn btn-secondary btn-sm"
                    onClick={() => onNavigate && onNavigate('ai')}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <path d="M8 2v12M2 8h12M4.5 4.5l7 7M11.5 4.5l-7 7"/>
                    </svg>
                    AI Security Advisor
                  </button>
                  <button
                    id="quick-history-btn"
                    className="btn btn-secondary btn-sm"
                    onClick={() => onNavigate && onNavigate('history')}
                  >
                    Assessment Reports ({historyRuns.length})
                  </button>
                </div>
              </div>

              {/* Findings Stats Counter Matrix */}
              <div className="findings-stats-wrapper">
                <div className="findings-stats-header">
                  <span className="findings-stats-title">Active Security Findings</span>
                  <span className="findings-stats-count">{total} Total</span>
                </div>
                <div className="findings-stats">
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
        </div>

        {/* Category scores */}
        <div className="section">
          <div className="section-header" style={{ flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <h2 className="section-title">Assessment Scorecard</h2>
              <span className="text-muted text-xs">
                Domain breakdown for <code className="mono">{selectedRun?.id || 'Latest'}</code> ({selectedRun?.target || activeTargetUrl})
              </span>
            </div>
            {historyRuns.length > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <label htmlFor="assessment-run-select" className="text-muted text-xs mono" style={{ margin: 0 }}>
                  INSPECT RUN:
                </label>
                <select
                  id="assessment-run-select"
                  value={selectedRun?.id || ''}
                  onChange={(e) => handleSelectRun(e.target.value)}
                  className="btn btn-secondary btn-xs"
                  style={{ padding: '3px 8px', fontSize: '11px', fontFamily: 'var(--font-mono)', cursor: 'pointer' }}
                >
                  {historyRuns.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id} — {r.target} ({r.overallScore}/100)
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
          <div className="grid-4">
            {scores.map((s) => (
              <ScoreCard
                key={s.id}
                id={s.id}
                label={s.label}
                score={s.score}
                max={s.max}
                statusText={s.statusText}
                trend={s.trend}
                description={s.description}
                onClick={() => handleDomainClick(s.id)}
              />
            ))}
          </div>
        </div>

        {/* Recent activity & Workflow */}
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Security Findings & Activity</h2>
              <span className="text-muted text-xs">PostgreSQL Active Runs</span>
            </div>
            <div className="card" style={{ padding: '6px 16px' }}>
              <div className="activity-list">
                {activityItems.map((item) => (
                  <div
                    className="activity-item"
                    key={item.id}
                    style={{ cursor: historyRuns.some((r) => r.id === item.id) ? 'pointer' : undefined }}
                    onClick={() => {
                      if (historyRuns.some((r) => r.id === item.id)) {
                        handleSelectRun(item.id);
                      }
                    }}
                    title={historyRuns.some((r) => r.id === item.id) ? `Click to inspect Run ${item.id} scorecard` : undefined}
                  >
                    <div className={`activity-dot ${item.dot}`} aria-hidden="true" />
                    <div className="activity-content">
                      <div className="activity-header-row">
                        <span className="activity-title">{item.title}</span>
                        <span className="activity-time-badge">{item.time}</span>
                      </div>
                      <div className="activity-desc">{item.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Workflow card */}
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Assessment Workflow</h2>
              <span className="text-muted text-xs">Continuous Verification Pipeline</span>
            </div>
            <div className="card workflow-card">
              <div className="workflow-timeline">
                {[
                  { step: '01', stage: 'TEST', desc: 'Automated test suite probes login, reset, and session endpoints.' },
                  { step: '02', stage: 'DETECT', desc: 'Identifies security vulnerabilities, accessibility flaws, and UX friction.' },
                  { step: '03', stage: 'EXPLAIN', desc: 'Contextualizes each finding with root cause analysis and impact severity.' },
                  { step: '04', stage: 'FIX', desc: 'Provides actionable, framework-specific code remediations via Gemini.' },
                  { step: '05', stage: 'RE-TEST', desc: 'Re-runs verification suite to confirm complete resolution.' },
                ].map((w, idx) => (
                  <div className="workflow-item" key={w.step}>
                    <div className="workflow-node">
                      <span className="workflow-step-num">{w.step}</span>
                      {idx < 4 && <div className="workflow-line" aria-hidden="true" />}
                    </div>
                    <div className="workflow-content">
                      <div className="workflow-stage-title">{w.stage}</div>
                      <div className="workflow-desc">{w.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
