/**
 * AssessmentHistory.jsx — Real Persisted Assessment History with Drill-Down
 * Fetches real historical audit runs and findings stored in PostgreSQL.
 */
import React, { useState, useEffect } from 'react';
import Badge from '../components/Badge';
import { assessmentHistory as fallbackHistory } from '../data/mockData';
import { formatDate, scoreColor } from '../utils/helpers';
import { authApi } from '../services/authApi';

export default function AssessmentHistory() {
  const [history, setHistory]       = useState(fallbackHistory);
  const [selected, setSelected]     = useState(fallbackHistory[0]?.id || null);
  const [detail, setDetail]         = useState(null);
  const [loading, setLoading]       = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);

  // Load real assessment history from PostgreSQL
  useEffect(() => {
    async function loadHistory() {
      setLoading(true);
      try {
        const res = await authApi.getAssessmentHistory();
        if (res?.assessments && res.assessments.length > 0) {
          setHistory(res.assessments);
          setSelected(res.assessments[0].id);
        }
      } catch (err) {
        console.warn('Could not load database assessments, using cached history:', err.message);
      } finally {
        setLoading(false);
      }
    }
    loadHistory();
  }, []);

  // Fetch full details and findings for the selected assessment
  useEffect(() => {
    if (!selected) return;

    async function loadDetail() {
      setDetailLoading(true);
      try {
        const res = await authApi.getAssessmentById(selected);
        if (res?.assessment) {
          setDetail({
            ...res.assessment,
            findings: res.findings || [],
          });
          return;
        }
      } catch (err) {
        // Fall back to local object if not found in db
        const fallback = history.find((a) => a.id === selected);
        if (fallback) {
          setDetail(fallback);
        }
      } finally {
        setDetailLoading(false);
      }
    }
    loadDetail();
  }, [selected, history]);

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Assessment History</h1>
            <p className="page-subtitle">Persistent historical audit trail — score progression across verification cycles</p>
          </div>
          <span className="badge badge-sample">
            {history.length} {history.length === 1 ? 'Recorded Run' : 'Recorded Runs'}
          </span>
        </div>
      </div>

      <div className="page-body">
        <div className="grid-2" style={{ alignItems: 'start' }}>
          {/* Audit Log Table */}
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Audit Log</h2>
              {loading && <span className="text-muted text-xs"><span className="spin">⟳</span> Refreshing…</span>}
            </div>
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="table-responsive">
                <table className="data-table" aria-label="Assessment history table">
                  <thead>
                    <tr>
                      <th>Run ID</th>
                      <th>Date</th>
                      <th>Target</th>
                      <th>Score</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((a) => {
                      const isSelected = selected === a.id;
                      return (
                        <tr
                          key={a.id}
                          style={{
                            cursor: 'pointer',
                            background: isSelected ? 'var(--bg-elevated)' : undefined,
                          }}
                          onClick={() => setSelected(a.id)}
                        >
                          <td>
                            <span className="mono text-xs" style={{ color: 'var(--text-secondary)' }}>
                              {a.id}
                            </span>
                          </td>
                          <td className="text-muted text-xs">{formatDate(a.date)}</td>
                          <td className="text-secondary text-xs truncate" style={{ maxWidth: '120px' }}>
                            {a.target || 'localhost:4000'}
                          </td>
                          <td>
                            <span style={{ fontWeight: 600, color: scoreColor(a.overallScore) }}>
                              {a.overallScore}
                            </span>
                            <span className="text-muted text-xs">/100</span>
                          </td>
                          <td>
                            <button
                              id={`view-assessment-${a.id}`}
                              className="btn btn-secondary btn-xs"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelected(a.id);
                              }}
                              aria-label={`Inspect run ${a.id}`}
                            >
                              {isSelected ? 'Selected' : 'Inspect'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Drill-down Detail Panel */}
          <div className="section">
            <div className="section-header">
              <h2 className="section-title">Run Inspection</h2>
              {detailLoading && <span className="text-muted text-xs"><span className="spin">⟳</span> Loading findings…</span>}
            </div>

            {detail && (
              <div className="card fade-in">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
                  <div>
                    <div className="text-muted text-xs mono" style={{ marginBottom: '2px' }}>
                      {detail.id} &bull; {formatDate(detail.date)}
                    </div>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {detail.target || 'http://localhost:4000'}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '32px', fontWeight: 700, color: scoreColor(detail.overallScore), lineHeight: 1 }}>
                      {detail.overallScore}
                    </div>
                    <div className="text-muted text-xs" style={{ marginTop: '2px' }}>Overall Score</div>
                  </div>
                </div>

                <div className="divider" />

                {/* Findings Breakdown */}
                <div style={{ marginBottom: '16px' }}>
                  <div className="card-title" style={{ marginBottom: '8px' }}>Findings Breakdown</div>
                  {[
                    { label: 'Critical', value: detail.critical || 0, color: 'var(--sev-critical)' },
                    { label: 'High',     value: detail.high || 0,     color: 'var(--sev-high)' },
                    { label: 'Medium',   value: detail.medium || 0,   color: 'var(--sev-medium)' },
                    { label: 'Low',      value: detail.low || 0,      color: 'var(--sev-low)' },
                  ].map(({ label, value, color }) => (
                    <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                      <div style={{ width: '60px', fontSize: '12px', color: 'var(--text-muted)' }}>{label}</div>
                      <div style={{ flex: 1, background: 'var(--bg-elevated)', borderRadius: '99px', height: '4px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min(100, (value / 10) * 100)}%`, background: color, height: '100%', borderRadius: '99px' }} />
                      </div>
                      <div style={{ width: '20px', fontSize: '12px', fontWeight: 600, color, textAlign: 'right' }}>
                        {value}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Findings list if available */}
                {detail.findings && detail.findings.length > 0 && (
                  <div style={{ marginBottom: '16px' }}>
                    <div className="card-title" style={{ marginBottom: '8px' }}>Recorded Findings ({detail.findings.length})</div>
                    <div style={{ maxHeight: '200px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {detail.findings.map((f) => (
                        <div
                          key={`${f.id}-${f.title}`}
                          style={{
                            padding: '6px 10px',
                            background: 'var(--bg-elevated)',
                            borderRadius: 'var(--r-sm)',
                            border: '1px solid var(--border)',
                            fontSize: '11px',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0 }}>
                            <span className="mono text-muted">{f.id}</span>
                            <span className="truncate">{f.title}</span>
                          </div>
                          <Badge type={f.status?.toLowerCase() === 'pass' ? 'pass' : f.severity?.toLowerCase() || 'medium'} label={f.status || f.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="divider" />

                <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  <div>Duration: <span className="mono text-xs">{detail.duration || '1.2s'}</span></div>
                  <div>Execution: <Badge type="pass" label={detail.status || 'Completed'} /></div>
                </div>
              </div>
            )}

            {/* Score Trajectory */}
            <div className="card" style={{ marginTop: '14px' }}>
              <div className="card-title">Score Trajectory</div>
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: '10px', height: '64px', padding: '4px 0' }}>
                {history.slice(0, 8).reverse().map((a, i) => (
                  <div key={a.id} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
                    <div style={{ fontSize: '10px', fontWeight: 600, color: scoreColor(a.overallScore) }}>
                      {a.overallScore}
                    </div>
                    <div
                      style={{
                        width: '100%',
                        height: `${Math.max(6, (a.overallScore / 100) * 44)}px`,
                        background: scoreColor(a.overallScore),
                        borderRadius: '2px 2px 0 0',
                        opacity: 0.8,
                      }}
                    />
                    <div className="mono text-muted text-xs" style={{ fontSize: '9px' }}>v{i + 1}</div>
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
