/**
 * AIRecommendations.jsx — Real AI-Assisted Remediation Synthesis
 * Analyzes persisted assessment findings to generate contextual,
 * developer-reviewed code patches and verification steps.
 */
import React, { useState, useEffect } from 'react';
import Badge from '../components/Badge';
import { authApi } from '../services/authApi';

export default function AIRecommendations() {
  const [assessments, setAssessments] = useState([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('');
  const [providerStatus, setProviderStatus] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [activeTab, setActiveTab] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);
  const [reviews, setReviews] = useState({}); // { [findingId]: 'APPROVED' | 'REJECTED' }
  const [copiedId, setCopiedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metadata, setMetadata] = useState(null);

  // Load provider status and historical assessments
  useEffect(() => {
    let isMounted = true;

    async function loadData() {
      try {
        const [statusRes, histRes] = await Promise.all([
          authApi.getAiStatus().catch(() => ({ configured: false, message: 'Could not connect to AI service.' })),
          authApi.getAssessmentHistory().catch(() => ({ assessments: [] })),
        ]);

        if (!isMounted) return;

        setProviderStatus(statusRes);
        const list = histRes.assessments || [];
        setAssessments(list);

        if (list.length > 0) {
          setSelectedAssessmentId(list[0].id);
        }
      } catch (err) {
        if (isMounted) setError(err.message || 'Failed to initialize AI Security Advisor.');
      } finally {
        if (isMounted) setInitialLoading(false);
      }
    }

    loadData();
    return () => { isMounted = false; };
  }, []);

  async function handleGenerate(forceMock = false) {
    if (!selectedAssessmentId) {
      setError('Please select an assessment to analyze.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const options = forceMock ? { forceAdapter: 'mock' } : {};
      const res = await authApi.generateAiRecommendations(selectedAssessmentId, options);
      setRecommendations(res.recommendations || []);
      setMetadata({
        provider: res.provider,
        model: res.model,
        generatedAt: res.generatedAt,
        totalAnalyzed: res.totalAnalyzed,
        assessment: res.assessment,
      });

      // Expand the first recommendation if available
      if (res.recommendations && res.recommendations.length > 0) {
        setExpandedId(res.recommendations[0].findingId);
      }
    } catch (err) {
      setError(err.message || 'Failed to generate recommendations from AI provider.');
    } finally {
      setLoading(false);
    }
  }

  function handleCopy(text, id) {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  function handleReview(findingId, status) {
    setReviews((prev) => ({
      ...prev,
      [findingId]: prev[findingId] === status ? null : status,
    }));
  }

  // Filter recommendations by severity tab
  const filteredRecs = recommendations.filter((r) => {
    if (activeTab === 'ALL') return true;
    const originalSev = r.confidenceLevel || 'Medium';
    return originalSev.toUpperCase() === activeTab;
  });

  return (
    <div className="fade-in">
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">AI Security Advisor</h1>
            <p className="page-subtitle">Contextual vulnerability breakdowns, framework patches, and verification guidance</p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {providerStatus?.configured ? (
              <span className="badge badge-pass">
                <span className="status-dot green" style={{ marginRight: '5px' }}></span>
                Engine: {providerStatus.provider?.toUpperCase()} &bull; {providerStatus.model}
              </span>
            ) : (
              <span className="badge badge-sample">
                <span className="status-dot amber" style={{ marginRight: '5px' }}></span>
                Provider Unconfigured
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Provider Advisory if unconfigured */}
        {providerStatus && !providerStatus.configured && (
          <div className="section">
            <div className="card" style={{ borderColor: 'rgba(210, 153, 34, 0.4)', background: 'var(--bg-elevated)' }}>
              <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
                <span style={{ fontSize: '20px' }}>⚠️</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, color: 'var(--sev-medium)', marginBottom: '4px' }}>
                    AI Model Provider Not Configured
                  </div>
                  <div className="text-secondary text-sm" style={{ lineHeight: 1.6, marginBottom: '10px' }}>
                    {providerStatus.message}
                  </div>
                  <div style={{ background: 'var(--bg-elevated)', padding: '10px 14px', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)', fontFamily: 'monospace', fontSize: '12px', color: 'var(--accent)' }}>
                    GEMINI_API_KEY=your_gemini_api_key_here
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', gap: '10px' }}>
                    <button
                      id="btn-simulate-ai"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleGenerate(true)}
                      disabled={loading || assessments.length === 0}
                    >
                      <span>Simulate AI Pipeline (Dev Test Adapter)</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Assessment Selector & Generator Control */}
        <div className="section">
          <div className="card">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ flex: 1, minWidth: '280px' }}>
                <label className="text-xs text-muted mb-1" style={{ display: 'block', fontWeight: 600 }}>
                  Select Completed Assessment to Analyze:
                </label>
                {initialLoading ? (
                  <div className="text-muted text-sm">Loading assessment records…</div>
                ) : assessments.length === 0 ? (
                  <div className="text-muted text-sm">
                    No historical assessments found. Run an assessment in <strong>Security Assessment</strong> first.
                  </div>
                ) : (
                  <select
                    id="select-assessment"
                    className="auth-input"
                    value={selectedAssessmentId}
                    onChange={(e) => setSelectedAssessmentId(e.target.value)}
                    style={{ padding: '8px 12px', fontSize: '13px' }}
                    disabled={loading}
                  >
                    {assessments.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.id} — {a.target} (Score: {a.overallScore}/100) — {new Date(a.date).toLocaleDateString()}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div>
                <button
                  id="btn-generate-ai"
                  className="btn btn-primary"
                  onClick={() => handleGenerate(false)}
                  disabled={loading || assessments.length === 0}
                  style={{ height: '40px', padding: '0 20px', fontWeight: 600 }}
                >
                  {loading ? (
                    <>
                      <span className="spin">⟳</span>
                      <span>Synthesizing Recommendations…</span>
                    </>
                  ) : (
                    <span>Generate AI Security Advisory</span>
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="notice error mt-16" role="alert">
                <div>{error}</div>
              </div>
            )}
          </div>
        </div>

        {/* Results Metadata & Statistics */}
        {metadata && (
          <div className="section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
              <div className="text-sm">
                <strong>Analyzed {metadata.totalAnalyzed} findings</strong> from assessment <code className="mono">{metadata.assessment?.id}</code> ({metadata.assessment?.target})
              </div>
              <div className="text-xs text-muted">
                Engine: <code className="mono">{metadata.provider?.toUpperCase()}</code> ({metadata.model})
              </div>
            </div>

            {/* Severity Tabs */}
            <div className="tab-group" style={{ marginBottom: '14px' }}>
              {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((tab) => (
                <button
                  key={tab}
                  className={`tab-btn${activeTab === tab ? ' active' : ''}`}
                  onClick={() => setActiveTab(tab)}
                >
                  {tab === 'ALL' ? `All (${recommendations.length})` : tab}
                </button>
              ))}
            </div>

            {/* Recommendations List */}
            {filteredRecs.length === 0 ? (
              <div className="card text-center" style={{ padding: '32px' }}>
                <div className="text-secondary text-sm">No recommendations match the selected filter.</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {filteredRecs.map((rec) => {
                  const isExpanded = expandedId === rec.findingId;
                  const reviewStatus = reviews[rec.findingId];

                  return (
                    <div key={rec.findingId} className="ai-card" style={{ borderLeft: rec.confidenceLevel === 'High' ? '3px solid var(--accent)' : '3px solid var(--border)' }}>
                      <div className="ai-card-header">
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }}>
                            <span className="mono text-muted text-xs" style={{ fontWeight: 600 }}>{rec.findingId}</span>
                            <span className={`badge ${rec.confidenceLevel === 'High' ? 'badge-pass' : 'badge-sample'}`}>
                              Confidence: {rec.confidenceLevel}
                            </span>
                            {rec.affectedComponents?.map((comp, idx) => (
                              <span key={idx} className="mono text-xs text-muted" style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: 'var(--r-sm)' }}>
                                {comp}
                              </span>
                            ))}
                            {reviewStatus && (
                              <span className={`badge ${reviewStatus === 'APPROVED' ? 'badge-pass' : 'badge-fail'}`}>
                                {reviewStatus === 'APPROVED' ? 'Approved for Implementation' : 'Rejected'}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {rec.problemSummary}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <button
                            id={`btn-expand-${rec.findingId}`}
                            className="btn btn-secondary btn-xs"
                            onClick={() => setExpandedId(isExpanded ? null : rec.findingId)}
                            aria-expanded={isExpanded}
                          >
                            {isExpanded ? 'Collapse' : 'Inspect Patch'}
                          </button>
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="ai-card-body fade-in">
                          {/* Why It Matters */}
                          <div className="mb-14">
                            <div className="text-xs text-muted mb-1" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                              Technical Impact & Risk
                            </div>
                            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                              {rec.whyItMatters}
                            </div>
                          </div>

                          {/* Recommended Fix */}
                          <div className="mb-14">
                            <div className="text-xs text-muted mb-1" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                              Remediation Strategy
                            </div>
                            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                              {rec.recommendedFix}
                            </div>
                          </div>

                          {/* Code Patch */}
                          {rec.codePatch && (rec.codePatch.after || rec.codePatch.before) && (
                            <div className="mb-14">
                              <div className="code-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span>
                                  Target Component: <code className="mono text-xs">{rec.codePatch.file || 'Configuration'}</code>
                                </span>
                                <button
                                  className="btn btn-secondary btn-xs"
                                  onClick={() => handleCopy(rec.codePatch.after || rec.codePatch.before, rec.findingId)}
                                  style={{ padding: '2px 8px', fontSize: '11px' }}
                                >
                                  {copiedId === rec.findingId ? '✓ Copied!' : 'Copy Code Patch'}
                                </button>
                              </div>
                              <pre className="code-block attached" style={{ maxHeight: '280px', overflowY: 'auto' }}>
                                {rec.codePatch.after || rec.codePatch.before}
                              </pre>
                            </div>
                          )}

                          {/* Side Effects & Considerations */}
                          {rec.potentialSideEffects && (
                            <div className="mb-14" style={{ background: 'var(--bg-elevated)', padding: '10px 14px', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
                              <div className="text-xs" style={{ fontWeight: 600, color: 'var(--sev-medium)', marginBottom: '3px' }}>
                                Deployment Considerations & Side Effects:
                              </div>
                              <div className="text-xs text-secondary" style={{ lineHeight: 1.5 }}>
                                {rec.potentialSideEffects}
                              </div>
                            </div>
                          )}

                          {/* Verification Steps */}
                          {rec.verificationSteps && rec.verificationSteps.length > 0 && (
                            <div className="mb-16">
                              <div className="text-xs text-muted mb-2" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                Verification & Test Instructions
                              </div>
                              <ul style={{ paddingLeft: '18px', margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                {rec.verificationSteps.map((step, sIdx) => (
                                  <li key={sIdx}>{step}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Engineer Review & Approval Actions */}
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '12px', borderTop: '1px solid var(--border)', flexWrap: 'wrap', gap: '10px' }}>
                            <div className="text-xs text-muted">
                              Developer Review: {rec.manualReviewRequired ? 'Required prior to rollout' : 'Standard review'}
                            </div>

                            <div style={{ display: 'flex', gap: '8px' }}>
                              <button
                                className={`btn btn-xs ${reviewStatus === 'REJECTED' ? 'btn-danger' : 'btn-secondary'}`}
                                onClick={() => handleReview(rec.findingId, 'REJECTED')}
                              >
                                {reviewStatus === 'REJECTED' ? '✕ Marked as Rejected' : 'Reject Suggestion'}
                              </button>
                              <button
                                className={`btn btn-xs ${reviewStatus === 'APPROVED' ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => handleReview(rec.findingId, 'APPROVED')}
                              >
                                {reviewStatus === 'APPROVED' ? '✓ Approved for Implementation' : 'Approve Proposed Fix'}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Safety Disclaimer */}
        <div className="section mt-24">
          <div className="text-center text-xs text-muted" style={{ lineHeight: 1.5 }}>
            🛡️ <strong>Security Notice:</strong> AuthLens AI suggestions are synthesized for context and must be verified by software engineers before deployment. Patches are never automatically applied to code repositories without human authorization.
          </div>
        </div>
      </div>
    </div>
  );
}
