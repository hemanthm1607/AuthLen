/**
 * AIRecommendations.jsx — AI-Powered Security Remediation & Patch Review
 * =========================================================================
 * Professional, User-Controlled AI Code Remediation Workflow:
 * SCAN -> DETECT -> ANALYSE -> PROPOSE PATCH -> REVIEW -> EXPLICIT APPROVAL
 * -> APPLY WITH BACKUP -> ALLOWLISTED VERIFICATION -> AUDIT HISTORY
 */
import React, { useState, useEffect } from 'react';
import { authApi } from '../services/authApi';
import { formatAiAdvisorError } from '../utils/helpers';

export default function AIRecommendations() {
  const [assessments, setAssessments] = useState([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('');
  const [providerStatus, setProviderStatus] = useState(null);
  const [projectStatus, setProjectStatus] = useState(null);
  const [remediations, setRemediations] = useState([]);
  const [activeTab, setActiveTab] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Modal / Confirmations
  const [approvalModalRemediation, setApprovalModalRemediation] = useState(null);
  const [rejectModalRemediation, setRejectModalRemediation] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [verificationResultModal, setVerificationResultModal] = useState(null);

  // Load provider status, project environment, and assessments on mount
  useEffect(() => {
    let isMounted = true;

    async function loadData() {
      try {
        const [statusRes, projRes, histRes] = await Promise.all([
          authApi.getAiStatus().catch(() => ({ configured: false, message: 'Could not connect to AI service.' })),
          authApi.getProjectRemediationStatus().catch(() => ({ sourceAccessAvailable: false })),
          authApi.getAssessmentHistory().catch(() => ({ assessments: [] })),
        ]);

        if (!isMounted) return;

        setProviderStatus(statusRes);
        setProjectStatus(projRes);
        const list = histRes.assessments || [];
        setAssessments(list);

        if (list.length > 0) {
          const firstId = list[0].id;
          setSelectedAssessmentId(firstId);
          loadRemediations(firstId);
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

  async function loadRemediations(assessmentId) {
    if (!assessmentId) return;
    try {
      const res = await authApi.getRemediations(assessmentId);
      setRemediations(res.remediations || []);
      if (res.remediations && res.remediations.length > 0 && !expandedId) {
        setExpandedId(res.remediations[0].id);
      }
    } catch (_) {
      setRemediations([]);
    }
  }

  function handleAssessmentChange(e) {
    const newId = e.target.value;
    setSelectedAssessmentId(newId);
    loadRemediations(newId);
  }

  // Synthesize and persist proposed patches
  async function handleGenerate(forceMock = false) {
    // Prevent duplicate button clicks while already running
    if (loading) return;

    if (!selectedAssessmentId) {
      setError('Please select an assessment to analyze.');
      return;
    }

    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      // 1. Generate via AI service
      const options = forceMock ? { forceAdapter: 'mock' } : {};
      const aiRes = await authApi.generateAiRecommendations(selectedAssessmentId, options);

      // 2. Persist remediations in database workflow
      const persistRes = await authApi.generateRemediations(selectedAssessmentId, options);
      setRemediations(persistRes.remediations || []);

      if (persistRes.remediations && persistRes.remediations.length > 0) {
        setExpandedId(persistRes.remediations[0].id);
        const applicableCount = persistRes.remediations.filter(r => r.is_applicable || r.isApplicable).length;
        const isNonGemini = persistRes.provider === 'mock' || persistRes.provider === 'deterministic-fallback' || aiRes?.provider === 'mock';
        const providerNotice = isNonGemini ? ' [Non-Gemini Fallback]' : '';
        setSuccessMsg(
          applicableCount > 0
            ? `Generated ${persistRes.remediations.length} proposed remediation patches (${applicableCount} with verified source code ready for review)${providerNotice}.`
            : `Generated ${persistRes.remediations.length} recommendations${providerNotice}. Connect local source project to generate applicable source patches.`
        );
      } else {
        setSuccessMsg('No critical or high severity vulnerabilities found requiring code remediation.');
      }
    } catch (err) {
      setError(formatAiAdvisorError(err));
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

  // Explicit User Approval
  async function handleApprove(rem) {
    const isApplicable = rem.is_applicable !== false && rem.isApplicable !== false;
    const codeBefore = rem.code_before || rem.codeBefore;
    const codeAfter = rem.code_after || rem.codeAfter;

    if (!isApplicable || !codeBefore || !codeAfter) {
      setError('Cannot approve patch: This finding does not have verified local source code context.');
      return;
    }

    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await authApi.approveRemediation(rem.id);
      setApprovalModalRemediation(null);
      setSuccessMsg(`Patch #${rem.id} approved for application by authenticated user.`);
      setRemediations((prev) =>
        prev.map((r) => (r.id === rem.id ? { ...r, ...res.remediation, status: 'APPROVED' } : r))
      );
    } catch (err) {
      setError(`Approval failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Explicit User Rejection
  async function handleReject(rem) {
    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await authApi.rejectRemediation(rem.id, rejectionReason);
      setRejectModalRemediation(null);
      setRejectionReason('');
      setSuccessMsg(`Patch #${rem.id} marked as rejected.`);
      setRemediations((prev) =>
        prev.map((r) => (r.id === rem.id ? { ...r, ...res.remediation, status: 'REJECTED' } : r))
      );
    } catch (err) {
      setError(`Rejection failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Apply Patch to Local Source
  async function handleApply(rem) {
    if (rem.status !== 'APPROVED') {
      setError('Cannot apply patch: Explicit user approval is mandatory before any source modifications.');
      return;
    }

    const isApplicable = rem.is_applicable !== false && rem.isApplicable !== false;
    const codeBefore = rem.code_before || rem.codeBefore;
    const codeAfter = rem.code_after || rem.codeAfter;

    if (!isApplicable || !codeBefore || !codeAfter) {
      setError('Cannot apply patch: This remediation does not have verified source code context.');
      return;
    }

    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await authApi.applyRemediation(rem.id);
      setSuccessMsg(`Patch #${rem.id} applied successfully! Backup checkpoint created: ${res.backupId || 'Created'}`);
      setRemediations((prev) =>
        prev.map((r) => (r.id === rem.id ? { ...r, ...res.remediation, status: 'APPLIED', backup_id: res.backupId } : r))
      );
    } catch (err) {
      if (err.data && err.data.code === 'STALE_FILE_MISMATCH') {
        setError(`Cannot apply patch: ${err.message}`);
      } else {
        setError(`Failed to apply patch: ${err.message}`);
      }
    } finally {
      setActionLoadingId(null);
    }
  }

  // Run Automated Verification
  async function handleVerify(rem) {
    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);

    try {
      const verifyCmd = rem.verification_command || rem.verificationCommand || 'npm test';
      const res = await authApi.verifyRemediation(rem.id, verifyCmd);
      setVerificationResultModal(res);
      setRemediations((prev) =>
        prev.map((r) => (r.id === rem.id ? { ...r, ...res.remediation } : r))
      );
      if (res.status === 'VERIFIED') {
        setSuccessMsg(`Verification succeeded for Patch #${rem.id}! Security improvement confirmed.`);
      } else {
        setError(`Verification failed for Patch #${rem.id}. Review test output below or trigger rollback.`);
      }
    } catch (err) {
      setError(`Verification execution error: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Rollback to Pre-Patch State
  async function handleRollback(rem) {
    if (!window.confirm(`Are you sure you want to rollback Patch #${rem.id}? This will restore the original file from the backup checkpoint.`)) {
      return;
    }

    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await authApi.rollbackRemediation(rem.id);
      setSuccessMsg(`Patch #${rem.id} safely rolled back. Target file restored from backup.`);
      setRemediations((prev) =>
        prev.map((r) => (r.id === rem.id ? { ...r, ...res.remediation, status: 'ROLLED_BACK' } : r))
      );
    } catch (err) {
      setError(`Rollback failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Filter remediations by severity tab
  const filteredRemediations = remediations.filter((r) => {
    if (activeTab === 'ALL') return true;
    const sev = r.severity || r.confidence_level || r.confidenceLevel || 'MEDIUM';
    return String(sev).toUpperCase() === activeTab;
  });

  function renderStatusBadge(status) {
    switch (status) {
      case 'PATCH_GENERATED':
      case 'AWAITING_APPROVAL':
        return <span className="badge badge-sample"><span className="status-dot amber" style={{ marginRight: '5px' }}></span>Awaiting User Approval</span>;
      case 'AWAITING_SOURCE_CONTEXT':
        return <span className="badge badge-sample" style={{ background: '#F8FAFC', color: '#64748B', borderColor: '#E2E8F0' }}><span className="status-dot amber" style={{ marginRight: '5px' }}></span>Source Context Required</span>;
      case 'APPROVED':
        return <span className="badge badge-pass" style={{ background: '#EFF6FF', color: '#1D4ED8', borderColor: '#BFDBFE' }}><span className="status-dot blue" style={{ marginRight: '5px' }}></span>Approved</span>;
      case 'APPLIED':
        return <span className="badge" style={{ background: '#F0FDF4', color: '#15803D', borderColor: '#BBF7D0' }}><span className="status-dot green" style={{ marginRight: '5px' }}></span>Applied (Unverified)</span>;
      case 'VERIFIED':
        return <span className="badge badge-pass"><span className="status-dot green" style={{ marginRight: '5px' }}></span>Verified Secure</span>;
      case 'VERIFICATION_FAILED':
        return <span className="badge badge-fail"><span className="status-dot red" style={{ marginRight: '5px' }}></span>Verification Failed</span>;
      case 'REJECTED':
        return <span className="badge badge-fail"><span className="status-dot red" style={{ marginRight: '5px' }}></span>Rejected</span>;
      case 'ROLLED_BACK':
        return <span className="badge" style={{ background: '#F1F5F9', color: '#64748B', borderColor: '#CBD5E1' }}>Rolled Back</span>;
      default:
        return <span className="badge badge-sample">{status}</span>;
    }
  }

  return (
    <div className="fade-in">
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">AI Security Advisor & Code Remediation</h1>
            <p className="page-subtitle">
              User-approved, automated code patches with atomic backups, allowlisted verification, and audit tracking
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {projectStatus?.sourceAccessAvailable ? (
              <span className="badge badge-pass" title="Authorized source repository connected">
                <span className="status-dot green" style={{ marginRight: '5px' }}></span>
                Source Repository Connected
              </span>
            ) : (
              <span className="badge badge-sample" title="Running in remote assessment mode">
                <span className="status-dot amber" style={{ marginRight: '5px' }}></span>
                Remote Assessment Mode
              </span>
            )}
            {providerStatus?.configured && (
              <span className="badge badge-pass">
                Engine: {providerStatus.provider?.toUpperCase()} &bull; {providerStatus.model}
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Assessment Selector & Generator Control */}
        <div className="section">
          <div className="card">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ flex: 1, minWidth: '280px' }}>
                <label className="text-xs text-muted mb-1" style={{ display: 'block', fontWeight: 600 }}>
                  Select Assessment to Remediate:
                </label>
                {initialLoading ? (
                  <div className="text-muted text-sm">Loading assessment records…</div>
                ) : assessments.length === 0 ? (
                  <div className="text-muted text-sm">
                    No assessments found. Run an assessment in <strong>Security Assessment</strong> first.
                  </div>
                ) : (
                  <select
                    id="select-assessment"
                    className="auth-input"
                    value={selectedAssessmentId}
                    onChange={handleAssessmentChange}
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
                      <span>Synthesizing Remediation Patches…</span>
                    </>
                  ) : (
                    <span>Generate Remediation Workflow</span>
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="notice error mt-16" role="alert">
                <div>{error}</div>
              </div>
            )}

            {successMsg && (
              <div className="notice success mt-16" role="alert">
                <div>{successMsg}</div>
              </div>
            )}
          </div>
        </div>

        {/* Severity Tabs */}
        {remediations.length > 0 && (
          <div className="section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <div className="tab-group">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((tab) => (
                  <button
                    key={tab}
                    className={`tab-btn${activeTab === tab ? ' active' : ''}`}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab === 'ALL' ? `All Patches (${remediations.length})` : tab}
                  </button>
                ))}
              </div>

              <div className="text-xs text-muted">
                Showing {filteredRemediations.length} of {remediations.length} proposed patches
              </div>
            </div>

            {/* Remediations List */}
            {filteredRemediations.length === 0 ? (
              <div className="card text-center" style={{ padding: '32px' }}>
                <div className="text-secondary text-sm">No remediation patches match the selected severity filter.</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {filteredRemediations.map((rem) => {
                  const isExpanded = expandedId === rem.id;
                  const isActionLoading = actionLoadingId === rem.id;
                  const targetFilePath = rem.target_file || rem.targetFile || rem.file_path;
                  const codeBefore = rem.code_before || rem.codeBefore;
                  const codeAfter = rem.code_after || rem.codeAfter;
                  const isApplicable = (rem.is_applicable !== false && rem.isApplicable !== false) && Boolean(codeBefore && codeAfter);
                  const findingId = rem.finding_id || rem.findingId;
                  const title = rem.vulnerability_title || rem.problem_summary || rem.problemSummary || `Remediation for Finding ${findingId}`;
                  const severity = rem.severity || rem.confidence_level || rem.confidenceLevel || 'MEDIUM';

                  return (
                    <div key={rem.id} className="ai-card" style={{ borderLeft: severity === 'HIGH' || severity === 'CRITICAL' ? '4px solid #DC2626' : '4px solid #2563EB' }}>
                      <div className="ai-card-header" style={{ padding: '16px 20px' }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
                            <span className="mono text-muted text-xs" style={{ fontWeight: 600 }}>#{rem.id}</span>
                            <span className="mono text-muted text-xs">Finding: {findingId}</span>
                            <span className={`badge ${severity === 'HIGH' || severity === 'CRITICAL' ? 'badge-fail' : 'badge-sample'}`}>
                              {severity}
                            </span>
                            {renderStatusBadge(rem.status)}
                            {targetFilePath && targetFilePath !== 'SOURCE_UNAVAILABLE' && (
                              <span className="mono text-xs text-muted" style={{ background: '#F1F5F9', padding: '2px 8px', borderRadius: '4px', border: '1px solid #E2E8F0' }}>
                                📁 {targetFilePath}
                              </span>
                            )}
                          </div>

                          <div style={{ fontSize: '16px', fontWeight: 600, color: '#0F172A' }}>
                            {title}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <button
                            id={`btn-expand-${rem.id}`}
                            className="btn btn-secondary btn-sm"
                            onClick={() => setExpandedId(isExpanded ? null : rem.id)}
                            aria-expanded={isExpanded}
                          >
                            {isExpanded ? 'Hide Details' : 'Review Patch'}
                          </button>
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="ai-card-body fade-in" style={{ padding: '0 20px 20px 20px', borderTop: '1px solid #E2E8F0' }}>
                          {/* Problem Explanation */}
                          <div className="mb-14 mt-16">
                            <div className="text-xs text-muted mb-1" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                              Vulnerability Analysis & Technical Impact
                            </div>
                            <div style={{ fontSize: '13px', color: '#334155', lineHeight: '1.6' }}>
                              {rem.problem_explanation || rem.problem_summary || rem.problemSummary || 'No vulnerability description recorded.'}
                            </div>
                          </div>

                          {/* Technical Rationale */}
                          {(rem.technical_rationale || rem.recommended_fix || rem.recommendedFix) && (
                            <div className="mb-14">
                              <div className="text-xs text-muted mb-1" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                Remediation Strategy & Guidance
                              </div>
                              <div style={{ fontSize: '13px', color: '#334155', lineHeight: '1.6' }}>
                                {rem.technical_rationale || rem.recommended_fix || rem.recommendedFix}
                              </div>
                            </div>
                          )}

                          {/* Code Patch Diff or Source Context Unavailable Notice */}
                          {isApplicable && codeBefore && codeAfter ? (
                            <div className="mb-16">
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                  Verified Code Patch Diff ({targetFilePath})
                                </div>
                                <button
                                  className="btn btn-secondary btn-xs"
                                  onClick={() => handleCopy(codeAfter, rem.id)}
                                  style={{ padding: '2px 8px', fontSize: '11px' }}
                                >
                                  {copiedId === rem.id ? '✓ Copied!' : 'Copy Fix'}
                                </button>
                              </div>

                              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                                {/* Before Block */}
                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 600, color: '#DC2626', background: '#FEF2F2', padding: '6px 10px', borderTopLeftRadius: '6px', borderTopRightRadius: '6px', border: '1px solid #FECACA', borderBottom: 'none' }}>
                                    - Original Code (Verified from Disk)
                                  </div>
                                  <pre style={{ margin: 0, padding: '10px 12px', background: '#FFF5F5', border: '1px solid #FECACA', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', color: '#991B1B', fontFamily: 'monospace', fontSize: '12px', lineHeight: 1.5, maxHeight: '240px', overflowY: 'auto' }}>
                                    {codeBefore}
                                  </pre>
                                </div>

                                {/* After Block */}
                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: 600, color: '#16A34A', background: '#F0FDF4', padding: '6px 10px', borderTopLeftRadius: '6px', borderTopRightRadius: '6px', border: '1px solid #BBF7D0', borderBottom: 'none' }}>
                                    + Proposed Replacement Patch
                                  </div>
                                  <pre style={{ margin: 0, padding: '10px 12px', background: '#F0FDF4', border: '1px solid #BBF7D0', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', color: '#166534', fontFamily: 'monospace', fontSize: '12px', lineHeight: 1.5, maxHeight: '240px', overflowY: 'auto' }}>
                                    {codeAfter}
                                  </pre>
                                </div>
                              </div>
                            </div>
                          ) : (
                            <div className="mb-16" style={{ background: '#F8FAFC', padding: '14px 16px', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
                              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                                <span style={{ fontSize: '18px' }}>ℹ️</span>
                                <div>
                                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#0F172A', marginBottom: '4px' }}>
                                    Source Context Unavailable for Automated Patching
                                  </div>
                                  <div className="text-xs text-secondary" style={{ lineHeight: 1.6 }}>
                                    This vulnerability was identified via HTTP dynamic security testing (DAST). No verified source file in the authorized project was located for automated patch application. Connect an authorized local project directory to inspect source code and generate applicable patches.
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Side Effects / Risks */}
                          {(rem.side_effects || rem.potential_side_effects || rem.potentialSideEffects) && (
                            <div className="mb-14" style={{ background: '#FFFBEB', padding: '10px 14px', borderRadius: '6px', border: '1px solid #FDE68A' }}>
                              <div className="text-xs" style={{ fontWeight: 600, color: '#D97706', marginBottom: '3px' }}>
                                ⚠️ Potential Side Effects & Considerations:
                              </div>
                              <div className="text-xs text-secondary" style={{ lineHeight: 1.5 }}>
                                {rem.side_effects || rem.potential_side_effects || rem.potentialSideEffects}
                              </div>
                            </div>
                          )}

                          {/* Verification Plan */}
                          <div className="mb-16">
                            <div className="text-xs text-muted mb-1" style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                              Allowlisted Verification Command
                            </div>
                            <div style={{ background: '#F8FAFC', padding: '8px 12px', borderRadius: '6px', border: '1px solid #E2E8F0', fontFamily: 'monospace', fontSize: '12px', color: '#0F172A' }}>
                              $ {rem.verification_command || rem.verificationCommand || 'npm test'}
                            </div>
                          </div>

                          {/* Action Toolbar */}
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '14px', borderTop: '1px solid #E2E8F0', flexWrap: 'wrap', gap: '10px' }}>
                            <div className="text-xs text-muted">
                              Audit State: <strong>{rem.status}</strong> {rem.approved_at && `(Approved: ${new Date(rem.approved_at).toLocaleTimeString()})`}
                            </div>

                            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                              {/* Step 1: Approval Actions */}
                              {(rem.status === 'PATCH_GENERATED' || rem.status === 'AWAITING_APPROVAL' || rem.status === 'AWAITING_SOURCE_CONTEXT') && (
                                <>
                                  <button
                                    id={`btn-reject-${rem.id}`}
                                    className="btn btn-secondary btn-sm"
                                    onClick={() => setRejectModalRemediation(rem)}
                                    disabled={isActionLoading}
                                  >
                                    ✕ Reject Suggestion
                                  </button>
                                  <button
                                    id={`btn-approve-${rem.id}`}
                                    className="btn btn-primary btn-sm"
                                    onClick={() => setApprovalModalRemediation(rem)}
                                    disabled={isActionLoading || !isApplicable}
                                    title={!isApplicable ? 'Source code context required before approving patch' : ''}
                                  >
                                    ✓ Approve Patch
                                  </button>
                                </>
                              )}

                              {/* Step 2: Apply Patch */}
                              {rem.status === 'APPROVED' && (
                                <>
                                  <button
                                    id={`btn-apply-${rem.id}`}
                                    className="btn btn-primary btn-sm"
                                    onClick={() => handleApply(rem)}
                                    disabled={isActionLoading || !isApplicable}
                                    title={!isApplicable ? 'Source code context required before applying patch' : ''}
                                  >
                                    {isActionLoading ? 'Applying...' : '🚀 Apply Approved Patch to Source'}
                                  </button>
                                </>
                              )}

                              {/* Step 3: Run Verification */}
                              {(rem.status === 'APPLIED' || rem.status === 'VERIFICATION_FAILED') && (
                                <>
                                  <button
                                    id={`btn-verify-${rem.id}`}
                                    className="btn btn-primary btn-sm"
                                    onClick={() => handleVerify(rem)}
                                    disabled={isActionLoading}
                                  >
                                    {isActionLoading ? 'Running Tests...' : '🧪 Run Automated Verification'}
                                  </button>
                                  <button
                                    id={`btn-rollback-${rem.id}`}
                                    className="btn btn-secondary btn-sm"
                                    onClick={() => handleRollback(rem)}
                                    disabled={isActionLoading}
                                  >
                                    ⏪ Rollback to Backup
                                  </button>
                                </>
                              )}

                              {/* Step 4: Post-Verification */}
                              {rem.status === 'VERIFIED' && (
                                <>
                                  <span className="badge badge-pass" style={{ alignSelf: 'center', padding: '6px 12px' }}>
                                    ✓ Verification Confirmed Clean
                                  </span>
                                  <button
                                    id={`btn-rollback-${rem.id}`}
                                    className="btn btn-secondary btn-xs"
                                    onClick={() => handleRollback(rem)}
                                    disabled={isActionLoading}
                                  >
                                    Rollback Checkpoint
                                  </button>
                                </>
                              )}
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

        {/* Modal: Explicit Approval Confirmation */}
        {approvalModalRemediation && (
          <div className="modal-backdrop fade-in" style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="card" style={{ maxWidth: '540px', width: '90%', padding: '24px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#0F172A', marginBottom: '8px' }}>
                Confirm Explicit Patch Approval
              </h3>
              <p className="text-secondary text-sm" style={{ lineHeight: 1.6, marginBottom: '16px' }}>
                You are about to authorize code remediation for <strong>Patch #{approvalModalRemediation.id}</strong> targeting:
                <br />
                <code className="mono" style={{ background: '#F1F5F9', padding: '2px 6px', borderRadius: '4px' }}>
                  {approvalModalRemediation.target_file || approvalModalRemediation.targetFile || approvalModalRemediation.file_path}
                </code>
              </p>

              <div style={{ background: '#FEF3C7', border: '1px solid #FCD34D', borderRadius: '6px', padding: '12px', fontSize: '12px', color: '#92400E', marginBottom: '20px' }}>
                🛡️ <strong>Safety Guarantee:</strong> An automatic pre-patch backup checkpoint with SHA-256 integrity hashing will be created before any changes are written. Only allowlisted verification commands can be executed.
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setApprovalModalRemediation(null)}
                >
                  Cancel
                </button>
                <button
                  id="btn-confirm-approval"
                  className="btn btn-primary btn-sm"
                  onClick={() => handleApprove(approvalModalRemediation)}
                >
                  Confirm & Authorize Patch
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Rejection Reason */}
        {rejectModalRemediation && (
          <div className="modal-backdrop fade-in" style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="card" style={{ maxWidth: '480px', width: '90%', padding: '24px' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#0F172A', marginBottom: '8px' }}>
                Reject Remediation Suggestion
              </h3>
              <p className="text-secondary text-sm" style={{ marginBottom: '14px' }}>
                Specify an optional reason for audit records:
              </p>
              <textarea
                className="auth-input"
                rows="3"
                placeholder="e.g., False positive, alternative implementation in progress, etc."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                style={{ width: '100%', marginBottom: '16px', fontSize: '13px' }}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setRejectModalRemediation(null)}
                >
                  Cancel
                </button>
                <button
                  id="btn-confirm-rejection"
                  className="btn btn-danger btn-sm"
                  onClick={() => handleReject(rejectModalRemediation)}
                >
                  Reject Suggestion
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Verification Command Output */}
        {verificationResultModal && (
          <div className="modal-backdrop fade-in" style={{ position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="card" style={{ maxWidth: '680px', width: '90%', padding: '24px', maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#0F172A', margin: 0 }}>
                  Automated Verification Output
                </h3>
                {renderStatusBadge(verificationResultModal.status)}
              </div>

              <div className="text-secondary text-xs mb-8">
                Command: <code className="mono">{verificationResultModal.verificationResult?.command || 'npm test'}</code> &bull; Duration: {verificationResultModal.verificationResult?.durationMs || 0}ms
              </div>

              <pre style={{ flex: 1, overflowY: 'auto', background: '#0F172A', color: '#E2E8F0', padding: '14px', borderRadius: '6px', fontSize: '12px', fontFamily: 'monospace', maxHeight: '360px', margin: '0 0 16px 0' }}>
                {verificationResultModal.verificationResult?.output || verificationResultModal.error || 'No output recorded.'}
              </pre>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => setVerificationResultModal(null)}
                >
                  Close Terminal
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Safety Disclaimer Footer */}
        <div className="section mt-24">
          <div className="text-center text-xs text-muted" style={{ lineHeight: 1.5 }}>
            🛡️ <strong>Zero-Trust Remediation Policy:</strong> AuthLens never alters project code automatically. Explicit, authenticated user authorization is mandatory before every patch application. Automatic backup checkpoints enable one-click rollbacks at any time.
          </div>
        </div>
      </div>
    </div>
  );
}
