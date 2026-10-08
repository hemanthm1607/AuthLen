/**
 * ApprovedFindings.jsx — Dedicated Testing Team Approved Findings Queue
 * =========================================================================
 * Provides a dedicated, action-oriented workspace for testing and security
 * engineers to review approved findings and execute the necessary fixes.
 *
 * Enforces:
 * - Default queue displays ONLY explicitly approved statuses: APPROVED or PLAN_APPROVED.
 * - Excludes REVIEW_REQUIRED, MANUAL_REMEDIATION_REQUIRED, APPLIED, and VERIFIED from default view.
 * - Distinct badges and guidance:
 *     • APPROVED: concrete, validated code patch approved — awaiting application to source.
 *     • PLAN_APPROVED: remediation plan approved — requires manual developer implementation or source mapping.
 * - Never claims a vulnerability is resolved merely because it has been approved.
 * - Real PostgreSQL persistence scoped to authenticated user/tenant.
 */
import React, { useState, useEffect, useMemo } from 'react';
import { authApi } from '../services/authApi';

export default function ApprovedFindings({ onNavigate }) {
  const [remediations, setRemediations] = useState([]);
  const [assessments, setAssessments] = useState([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('');
  const [statusFilter, setStatusFilter] = useState('ACTIVE_APPROVED');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedIds, setExpandedIds] = useState(new Set());
  const [loading, setLoading] = useState(true);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [verificationModal, setVerificationModal] = useState(null);

  // Fetch assessments and approved remediations on mount
  useEffect(() => {
    let isMounted = true;

    async function loadInitialData() {
      setLoading(true);
      setError(null);
      try {
        const [assessmentsRes, remediationsRes] = await Promise.all([
          authApi.getAssessmentHistory().catch(() => ({ assessments: [] })),
          authApi.getRemediations().catch(() => ({ remediations: [] })),
        ]);

        if (!isMounted) return;

        setAssessments(assessmentsRes.assessments || []);
        const list = remediationsRes.remediations || [];
        setRemediations(list);

        // Auto-expand first item if available
        const activeApproved = list.filter(
          (r) => r.status === 'APPROVED' || r.status === 'PLAN_APPROVED'
        );
        if (activeApproved.length > 0) {
          setExpandedIds(new Set([activeApproved[0].id]));
        }
      } catch (err) {
        if (isMounted) setError(err.message || 'Failed to load approved findings queue.');
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadInitialData();
    return () => { isMounted = false; };
  }, []);

  // Reload data on demand or when selected assessment changes
  async function refreshData(assessmentId = selectedAssessmentId) {
    setLoading(true);
    setError(null);
    try {
      const res = await authApi.getRemediations(assessmentId || null);
      setRemediations(res.remediations || []);
    } catch (err) {
      setError(err.message || 'Failed to refresh approved findings.');
    } finally {
      setLoading(false);
    }
  }

  function handleAssessmentChange(e) {
    const val = e.target.value;
    setSelectedAssessmentId(val);
    refreshData(val);
  }

  function toggleExpand(id) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function handleCopy(text, id) {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  // Apply approved concrete patch to source file
  async function handleApplyPatch(rem) {
    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await authApi.applyRemediation(rem.id);
      setSuccessMsg(
        res.message ||
          `Patch #${rem.id} successfully written to disk. Backup snapshot #${res.backupId || 'auto'} created.`
      );
      // Update local record status
      setRemediations((prev) =>
        prev.map((r) =>
          r.id === rem.id
            ? {
                ...r,
                ...(res.remediation || {}),
                status: 'APPLIED',
                applied_at: new Date().toISOString(),
                backup_id: res.backupId || r.backup_id,
              }
            : r
        )
      );
    } catch (err) {
      const msg = err.data?.error || err.message || 'Patch application failed.';
      setError(`Apply Patch Error: ${msg}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Run automated verification for applied patch
  async function handleVerifyPatch(rem) {
    setActionLoadingId(rem.id);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await authApi.verifyRemediation(rem.id, 'npm test');
      setVerificationModal({
        remId: rem.id,
        findingId: rem.finding_id || rem.findingId,
        output: res.verificationOutput || res.output || 'Verification test suite passed.',
        status: res.status || (res.remediation?.status) || 'VERIFIED',
      });
      setSuccessMsg(
        res.message || `Automated verification completed for #${rem.id}. Status: ${res.status || 'VERIFIED'}`
      );
      setRemediations((prev) =>
        prev.map((r) =>
          r.id === rem.id
            ? {
                ...r,
                ...(res.remediation || {}),
                status: res.status || 'VERIFIED',
                verified_at: new Date().toISOString(),
              }
            : r
        )
      );
    } catch (err) {
      const msg = err.data?.error || err.message || 'Verification execution failed.';
      setError(`Verification Error: ${msg}`);
    } finally {
      setActionLoadingId(null);
    }
  }

  // Filter and search logic
  const filteredFindings = useMemo(() => {
    return remediations.filter((rem) => {
      const status = (rem.status || '').toUpperCase();
      const severity = (rem.confidence_level || rem.confidenceLevel || rem.severity || 'MEDIUM').toUpperCase();
      const remId = (rem.id || '').toLowerCase();
      const findingId = (rem.finding_id || rem.findingId || '').toLowerCase();
      const title = (rem.problem_summary || rem.vulnerabilityTitle || rem.problemSummary || '').toLowerCase();
      const file = (rem.target_file || rem.targetFile || '').toLowerCase();

      // Status filter
      if (statusFilter === 'ACTIVE_APPROVED') {
        // Default approved queue: strictly APPROVED or PLAN_APPROVED
        if (status !== 'APPROVED' && status !== 'PLAN_APPROVED') return false;
      } else if (statusFilter === 'APPROVED') {
        if (status !== 'APPROVED') return false;
      } else if (statusFilter === 'PLAN_APPROVED') {
        if (status !== 'PLAN_APPROVED') return false;
      } else if (statusFilter === 'APPLIED') {
        if (status !== 'APPLIED') return false;
      } else if (statusFilter === 'VERIFIED') {
        if (status !== 'VERIFIED') return false;
      } else if (statusFilter === 'ALL_APPROVED_HISTORY') {
        // Excludes unapproved/rejected records
        if (!['APPROVED', 'PLAN_APPROVED', 'APPLIED', 'VERIFIED'].includes(status)) return false;
      }

      // Severity filter
      if (severityFilter !== 'ALL' && severity !== severityFilter) {
        return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesQuery =
          remId.includes(q) ||
          findingId.includes(q) ||
          title.includes(q) ||
          file.includes(q);
        if (!matchesQuery) return false;
      }

      return true;
    });
  }, [remediations, statusFilter, severityFilter, searchQuery]);

  // Statistics counts
  const stats = useMemo(() => {
    const totalApproved = remediations.filter((r) => r.status === 'APPROVED').length;
    const totalPlanApproved = remediations.filter((r) => r.status === 'PLAN_APPROVED').length;
    const totalApplied = remediations.filter((r) => r.status === 'APPLIED').length;
    const totalVerified = remediations.filter((r) => r.status === 'VERIFIED').length;
    return {
      activeQueueCount: totalApproved + totalPlanApproved,
      approvedCount: totalApproved,
      planApprovedCount: totalPlanApproved,
      appliedCount: totalApplied,
      verifiedCount: totalVerified,
    };
  }, [remediations]);

  function getSeverityBadgeStyle(sev) {
    const s = (sev || 'MEDIUM').toUpperCase();
    if (s === 'CRITICAL') {
      return { background: '#FEF2F2', color: '#DC2626', borderColor: '#FECACA' };
    }
    if (s === 'HIGH') {
      return { background: '#FFF7ED', color: '#EA580C', borderColor: '#FED7AA' };
    }
    if (s === 'LOW') {
      return { background: '#EFF6FF', color: '#2563EB', borderColor: '#BFDBFE' };
    }
    return { background: '#FFFBEB', color: '#D97706', borderColor: '#FDE68A' };
  }

  function renderStatusBadge(status) {
    const s = (status || '').toUpperCase();
    if (s === 'APPROVED') {
      return (
        <span
          className="badge"
          style={{
            background: '#F0FDF4',
            color: '#166534',
            borderColor: '#BBF7D0',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 12, height: 12 }}>
            <circle cx="8" cy="8" r="7" stroke="#16A34A" />
            <path d="M5 8.2l2 2 4-4" stroke="#16A34A" />
          </svg>
          APPROVED (Concrete Patch)
        </span>
      );
    }
    if (s === 'PLAN_APPROVED') {
      return (
        <span
          className="badge"
          style={{
            background: '#F0FDFA',
            color: '#0F766E',
            borderColor: '#99F6E4',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 12, height: 12 }}>
            <rect x="3" y="2" width="10" height="12" rx="1.5" stroke="#0D9488" />
            <path d="M6 6h4M6 9h4M6 12h2" stroke="#0D9488" />
          </svg>
          PLAN_APPROVED (Remediation Plan)
        </span>
      );
    }
    if (s === 'APPLIED') {
      return (
        <span
          className="badge"
          style={{
            background: '#EFF6FF',
            color: '#1E40AF',
            borderColor: '#BFDBFE',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 12, height: 12 }}>
            <path d="M3 13l4-4 2 2 4-7" stroke="#2563EB" />
          </svg>
          APPLIED (Awaiting Verification)
        </span>
      );
    }
    if (s === 'VERIFIED') {
      return (
        <span
          className="badge"
          style={{
            background: '#ECFDF5',
            color: '#065F46',
            borderColor: '#A7F3D0',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 12, height: 12 }}>
            <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z" stroke="#059669" />
          </svg>
          VERIFIED (Fix Validated)
        </span>
      );
    }
    return <span className="badge badge-sample">{status}</span>;
  }

  return (
    <div className="audit-page fade-in" style={{ paddingBottom: '60px' }}>
      {/* ── Top Header ── */}
      <div className="section-header" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: '#F0FDF4',
                  border: '1px solid #BBF7D0',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#16A34A',
                }}
              >
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" style={{ width: 18, height: 18 }}>
                  <circle cx="8" cy="8" r="6.5" />
                  <path d="M5 8.2l2 2 4-4" />
                </svg>
              </div>
              <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: '#0F172A' }}>
                Approved Findings Queue
              </h1>
            </div>
            <p className="text-secondary text-sm" style={{ marginTop: '4px' }}>
              Dedicated implementation queue for testing and remediation teams. Review approved security findings and apply validated fixes.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => refreshData()}
              disabled={loading}
              title="Refresh queue from PostgreSQL database"
            >
              {loading ? 'Refreshing…' : '↻ Refresh Queue'}
            </button>
            {onNavigate && (
              <button
                className="btn btn-primary btn-sm"
                onClick={() => onNavigate('ai')}
                title="Go to AI Security Advisor to analyze findings and approve recommendations"
              >
                AI Security Advisor →
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Testing Team Disclaimer & Safety Policy Banner ── */}
      <div
        style={{
          background: '#F8FAFC',
          border: '1px solid #E2E8F0',
          borderLeft: '4px solid #2563EB',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
        }}
      >
        <span style={{ fontSize: '18px', lineHeight: 1 }}>🛡️</span>
        <div style={{ fontSize: '12px', color: '#334155', lineHeight: 1.5 }}>
          <strong style={{ color: '#0F172A' }}>Testing Team Remediation Standard:</strong>{' '}
          Approval certifies that a patch or remediation strategy has been reviewed by an authorized engineer.
          <strong> Approval alone does not resolve a vulnerability.</strong> A finding remains active until the patch is applied to source and verified against automated security test suites.
        </div>
      </div>

      {/* ── Status KPI Metric Cards ── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
          marginBottom: '20px',
        }}
      >
        <div
          className="metric-card"
          onClick={() => setStatusFilter('ACTIVE_APPROVED')}
          style={{
            cursor: 'pointer',
            padding: '14px 16px',
            background: statusFilter === 'ACTIVE_APPROVED' ? '#F0FDF4' : '#FFFFFF',
            borderColor: statusFilter === 'ACTIVE_APPROVED' ? '#86EFAC' : '#E2E8F0',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
            Active Approved Queue
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#166534', marginTop: '4px' }}>
            {stats.activeQueueCount}
          </div>
          <div className="text-xs text-secondary" style={{ marginTop: '2px' }}>
            Awaiting fix or implementation
          </div>
        </div>

        <div
          className="metric-card"
          onClick={() => setStatusFilter('APPROVED')}
          style={{
            cursor: 'pointer',
            padding: '14px 16px',
            background: statusFilter === 'APPROVED' ? '#F0FDF4' : '#FFFFFF',
            borderColor: statusFilter === 'APPROVED' ? '#86EFAC' : '#E2E8F0',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
            Concrete Code Approved
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#15803D', marginTop: '4px' }}>
            {stats.approvedCount}
          </div>
          <div className="text-xs text-secondary" style={{ marginTop: '2px' }}>
            Patch ready for 1-click apply
          </div>
        </div>

        <div
          className="metric-card"
          onClick={() => setStatusFilter('PLAN_APPROVED')}
          style={{
            cursor: 'pointer',
            padding: '14px 16px',
            background: statusFilter === 'PLAN_APPROVED' ? '#F0FDFA' : '#FFFFFF',
            borderColor: statusFilter === 'PLAN_APPROVED' ? '#99F6E4' : '#E2E8F0',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
            Remediation Plan Approved
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#0F766E', marginTop: '4px' }}>
            {stats.planApprovedCount}
          </div>
          <div className="text-xs text-secondary" style={{ marginTop: '2px' }}>
            Requires manual code edit
          </div>
        </div>

        <div
          className="metric-card"
          onClick={() => setStatusFilter('APPLIED')}
          style={{
            cursor: 'pointer',
            padding: '14px 16px',
            background: statusFilter === 'APPLIED' ? '#EFF6FF' : '#FFFFFF',
            borderColor: statusFilter === 'APPLIED' ? '#93C5FD' : '#E2E8F0',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
            Applied Patches
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#1D4ED8', marginTop: '4px' }}>
            {stats.appliedCount}
          </div>
          <div className="text-xs text-secondary" style={{ marginTop: '2px' }}>
            Written to disk; verify next
          </div>
        </div>

        <div
          className="metric-card"
          onClick={() => setStatusFilter('VERIFIED')}
          style={{
            cursor: 'pointer',
            padding: '14px 16px',
            background: statusFilter === 'VERIFIED' ? '#ECFDF5' : '#FFFFFF',
            borderColor: statusFilter === 'VERIFIED' ? '#A7F3D0' : '#E2E8F0',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="text-xs text-muted" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
            Verified Secure
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#047857', marginTop: '4px' }}>
            {stats.verifiedCount}
          </div>
          <div className="text-xs text-secondary" style={{ marginTop: '2px' }}>
            Verification suite passed
          </div>
        </div>
      </div>

      {/* ── Filtering and Search Toolbar ── */}
      <div
        className="card"
        style={{
          padding: '14px 16px',
          marginBottom: '20px',
          display: 'flex',
          flexWrap: 'wrap',
          gap: '12px',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center', flex: 1, minWidth: '300px' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', flex: '1 1 240px', minWidth: '200px' }}>
            <input
              type="text"
              id="search-approved-findings"
              className="input-field"
              placeholder="Search Finding ID, Remediation ID, Title, File…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                paddingLeft: '32px',
                fontSize: '13px',
                height: '36px',
                borderRadius: '6px',
              }}
            />
            <span
              style={{
                position: 'absolute',
                left: '10px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#94A3B8',
                pointerEvents: 'none',
              }}
            >
              🔍
            </span>
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                style={{
                  position: 'absolute',
                  right: '8px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: '#94A3B8',
                  cursor: 'pointer',
                  fontSize: '12px',
                }}
              >
                ✕
              </button>
            )}
          </div>

          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="filter-status" className="text-xs text-muted" style={{ fontWeight: 600 }}>
              Status:
            </label>
            <select
              id="filter-status"
              className="select-field"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ fontSize: '13px', height: '36px', borderRadius: '6px', padding: '0 8px' }}
            >
              <option value="ACTIVE_APPROVED">Active Queue (APPROVED & PLAN_APPROVED)</option>
              <option value="APPROVED">APPROVED (Concrete Code Patches)</option>
              <option value="PLAN_APPROVED">PLAN_APPROVED (Remediation Plans)</option>
              <option value="APPLIED">APPLIED (Awaiting Verification)</option>
              <option value="VERIFIED">VERIFIED (Verification Passed)</option>
              <option value="ALL_APPROVED_HISTORY">All Remediation History (Approved/Applied/Verified)</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="filter-severity" className="text-xs text-muted" style={{ fontWeight: 600 }}>
              Severity:
            </label>
            <select
              id="filter-severity"
              className="select-field"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{ fontSize: '13px', height: '36px', borderRadius: '6px', padding: '0 8px' }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {/* Assessment Scope Filter */}
        {assessments.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="filter-assessment" className="text-xs text-muted" style={{ fontWeight: 600 }}>
              Assessment:
            </label>
            <select
              id="filter-assessment"
              className="select-field"
              value={selectedAssessmentId}
              onChange={handleAssessmentChange}
              style={{ fontSize: '13px', height: '36px', borderRadius: '6px', maxWidth: '200px' }}
            >
              <option value="">All Assessments</option>
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} — {a.assessment_type || 'Security'}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* ── Alerts & Status Feedback ── */}
      {error && (
        <div
          className="alert alert-danger fade-in"
          style={{
            marginBottom: '16px',
            padding: '12px 16px',
            borderRadius: '6px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div>
            <strong>Error:</strong> {error}
          </div>
          <button
            onClick={() => setError(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '16px' }}
          >
            ✕
          </button>
        </div>
      )}

      {successMsg && (
        <div
          className="alert alert-success fade-in"
          style={{
            marginBottom: '16px',
            padding: '12px 16px',
            borderRadius: '6px',
            background: '#F0FDF4',
            color: '#166534',
            border: '1px solid #BBF7D0',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div>
            <strong>Success:</strong> {successMsg}
          </div>
          <button
            onClick={() => setSuccessMsg(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '16px' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* ── Loading Skeleton / State ── */}
      {loading && (
        <div className="card" style={{ padding: '40px', textAlign: 'center' }}>
          <div className="spin" style={{ fontSize: '28px', color: '#2563EB', marginBottom: '12px' }}>
            ⟳
          </div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#0F172A' }}>
            Loading approved findings queue…
          </div>
          <div className="text-xs text-muted" style={{ marginTop: '4px' }}>
            Querying PostgreSQL remediation ledger scoped to authenticated tenant
          </div>
        </div>
      )}

      {/* ── Empty State ── */}
      {!loading && filteredFindings.length === 0 && (
        <div
          className="card fade-in"
          style={{
            padding: '48px 24px',
            textAlign: 'center',
            background: '#FFFFFF',
            border: '1px dashed #CBD5E1',
            borderRadius: '12px',
          }}
        >
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: '#F8FAFC',
              border: '1px solid #E2E8F0',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '24px',
              color: '#94A3B8',
              marginBottom: '16px',
            }}
          >
            ✓
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#0F172A', marginBottom: '8px' }}>
            No Approved Findings Found
          </h3>
          <p className="text-secondary text-sm" style={{ maxWidth: '480px', margin: '0 auto 20px auto', lineHeight: 1.5 }}>
            {statusFilter === 'ACTIVE_APPROVED'
              ? 'There are currently no findings with APPROVED or PLAN_APPROVED status awaiting action. Findings in REVIEW_REQUIRED or MANUAL_REMEDIATION_REQUIRED must be reviewed and approved first.'
              : 'No remediation records matched the selected status and severity filter criteria.'}
          </p>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
            {statusFilter !== 'ACTIVE_APPROVED' && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  setStatusFilter('ACTIVE_APPROVED');
                  setSeverityFilter('ALL');
                  setSearchQuery('');
                }}
              >
                Reset Filters
              </button>
            )}
            {onNavigate && (
              <button className="btn btn-primary btn-sm" onClick={() => onNavigate('ai')}>
                Go to AI Security Advisor to Review Findings →
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── Findings List ── */}
      {!loading && filteredFindings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="text-xs text-muted" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>
              Showing <strong>{filteredFindings.length}</strong> approved {filteredFindings.length === 1 ? 'finding' : 'findings'}
            </span>
            <button
              className="btn btn-secondary btn-xs"
              onClick={() => {
                if (expandedIds.size === filteredFindings.length) {
                  setExpandedIds(new Set());
                } else {
                  setExpandedIds(new Set(filteredFindings.map((f) => f.id)));
                }
              }}
              style={{ fontSize: '11px', padding: '3px 8px' }}
            >
              {expandedIds.size === filteredFindings.length ? 'Collapse All' : 'Expand All Details'}
            </button>
          </div>

          {filteredFindings.map((rem) => {
            const isExpanded = expandedIds.has(rem.id);
            const severity = (rem.confidence_level || rem.confidenceLevel || rem.severity || 'Medium').toUpperCase();
            const sevStyle = getSeverityBadgeStyle(severity);
            const isActionLoading = actionLoadingId === rem.id;
            const hasSource = Boolean(
              (rem.is_applicable || rem.isApplicable) &&
                rem.target_file &&
                rem.target_file !== 'SOURCE_UNAVAILABLE'
            );
            const codeBefore = rem.code_before || rem.codeBefore;
            const codeAfter = rem.code_after || rem.codeAfter;
            const hasDiff = Boolean(codeBefore && codeAfter);
            const approver = rem.approver_name || rem.approverName || rem.approver_email || rem.approverEmail || rem.approver || 'Authenticated Engineer';
            const approvedTime = rem.approved_at || rem.approvedAt;

            return (
              <div
                key={rem.id}
                id={`card-approved-${rem.id}`}
                className="card fade-in"
                style={{
                  background: '#FFFFFF',
                  borderRadius: '10px',
                  border: isExpanded ? '1px solid #CBD5E1' : '1px solid #E2E8F0',
                  boxShadow: isExpanded ? 'var(--shadow-md)' : 'var(--shadow-xs)',
                  overflow: 'hidden',
                  transition: 'border-color 0.2s, box-shadow 0.2s',
                }}
              >
                {/* ── Card Header ── */}
                <div
                  style={{
                    padding: '16px 20px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    flexWrap: 'wrap',
                    gap: '12px',
                    cursor: 'pointer',
                    background: isExpanded ? '#F8FAFC' : '#FFFFFF',
                  }}
                  onClick={() => toggleExpand(rem.id)}
                >
                  <div style={{ flex: '1 1 500px', minWidth: '280px' }}>
                    {/* Meta Row: IDs, Severity, Status, Source */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', marginBottom: '8px' }}>
                      <span className="mono text-xs" style={{ fontWeight: 700, color: '#2563EB', background: '#EFF6FF', padding: '2px 8px', borderRadius: '4px', border: '1px solid #BFDBFE' }}>
                        {rem.finding_id || rem.findingId || 'FINDING'}
                      </span>
                      <span className="mono text-xs text-muted" style={{ background: '#F1F5F9', padding: '2px 8px', borderRadius: '4px', border: '1px solid #E2E8F0' }}>
                        {rem.id}
                      </span>
                      <span
                        className="badge"
                        style={{ ...sevStyle, fontSize: '11px', fontWeight: 700 }}
                      >
                        {severity}
                      </span>
                      {renderStatusBadge(rem.status)}

                      {/* Source verification status pill */}
                      {hasSource ? (
                        <span
                          className="badge"
                          style={{
                            background: '#F0FDF4',
                            color: '#15803D',
                            borderColor: '#BBF7D0',
                            fontSize: '11px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <span className="status-dot green" style={{ width: '6px', height: '6px' }}></span>
                          Source Verified: <code>{rem.target_file || rem.targetFile}</code>
                        </span>
                      ) : (
                        <span
                          className="badge"
                          style={{
                            background: '#F8FAFC',
                            color: '#64748B',
                            borderColor: '#CBD5E1',
                            fontSize: '11px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <span className="status-dot amber" style={{ width: '6px', height: '6px' }}></span>
                          Source Context Unavailable (DAST / Cloud)
                        </span>
                      )}
                    </div>

                    {/* Title */}
                    <div style={{ fontSize: '15px', fontWeight: 600, color: '#0F172A', lineHeight: 1.4 }}>
                      {rem.problem_summary || rem.vulnerabilityTitle || rem.problemSummary || 'Security Vulnerability'}
                    </div>

                    {/* Approver & Timestamp line */}
                    <div className="text-xs text-muted" style={{ marginTop: '6px', display: 'flex', flexWrap: 'wrap', gap: '14px' }}>
                      <span>
                        👤 Approved by: <strong>{approver}</strong>
                      </span>
                      {approvedTime && (
                        <span>
                          🕒 Approved at: <strong>{new Date(approvedTime).toLocaleString()}</strong>
                        </span>
                      )}
                      {rem.applied_at && (
                        <span style={{ color: '#2563EB' }}>
                          🚀 Applied at: <strong>{new Date(rem.applied_at).toLocaleString()}</strong>
                        </span>
                      )}
                      {rem.verified_at && (
                        <span style={{ color: '#059669' }}>
                          🛡️ Verified at: <strong>{new Date(rem.verified_at).toLocaleString()}</strong>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Top Right Action & Expand Trigger */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <button
                      id={`btn-toggle-details-${rem.id}`}
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpand(rem.id);
                      }}
                      aria-expanded={isExpanded}
                      style={{ fontSize: '12px' }}
                    >
                      {isExpanded ? 'Hide Details ▲' : 'Open Finding Details ▼'}
                    </button>
                  </div>
                </div>

                {/* ── Testing Team Next Action Callout (Always prominent) ── */}
                <div
                  style={{
                    padding: '12px 20px',
                    borderTop: '1px solid #E2E8F0',
                    background:
                      rem.status === 'APPROVED'
                        ? '#F0FDF4'
                        : rem.status === 'PLAN_APPROVED'
                        ? '#F0FDFA'
                        : rem.status === 'APPLIED'
                        ? '#EFF6FF'
                        : rem.status === 'VERIFIED'
                        ? '#ECFDF5'
                        : '#F8FAFC',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: '1 1 360px' }}>
                    <span style={{ fontSize: '18px' }}>
                      {rem.status === 'APPROVED'
                        ? '🚀'
                        : rem.status === 'PLAN_APPROVED'
                        ? '📋'
                        : rem.status === 'APPLIED'
                        ? '🧪'
                        : rem.status === 'VERIFIED'
                        ? '🛡️'
                        : 'ℹ️'}
                    </span>
                    <div style={{ fontSize: '12px', lineHeight: 1.4 }}>
                      {rem.status === 'APPROVED' && (
                        <>
                          <strong style={{ color: '#166534' }}>Action Needed: Concrete Patch Approved.</strong>
                          <span style={{ color: '#14532D', marginLeft: '6px' }}>
                            A concrete syntax-validated patch is awaiting application to{' '}
                            <code>{rem.target_file || rem.targetFile}</code>. Click below to apply.
                          </span>
                        </>
                      )}
                      {rem.status === 'PLAN_APPROVED' && (
                        <>
                          <strong style={{ color: '#0F766E' }}>Action Needed: Remediation Plan Approved.</strong>
                          <span style={{ color: '#115E59', marginLeft: '6px' }}>
                            Remediation strategy approved. Requires manual developer implementation or mapping of local source file.
                          </span>
                        </>
                      )}
                      {rem.status === 'APPLIED' && (
                        <>
                          <strong style={{ color: '#1E40AF' }}>Action Needed: Patch Applied to Source.</strong>
                          <span style={{ color: '#1E3A8A', marginLeft: '6px' }}>
                            Code change written to disk with backup #{rem.backup_id || 'saved'}. Run automated verification to confirm fix.
                          </span>
                        </>
                      )}
                      {rem.status === 'VERIFIED' && (
                        <>
                          <strong style={{ color: '#065F46' }}>Remediation Complete.</strong>
                          <span style={{ color: '#064E3B', marginLeft: '6px' }}>
                            Automated test suite confirmed vulnerability mitigation. Fix is verified.
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Immediate Action Buttons */}
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {rem.status === 'APPROVED' && (
                      <button
                        id={`btn-apply-approved-${rem.id}`}
                        className="btn btn-primary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleApplyPatch(rem);
                        }}
                        disabled={isActionLoading || !hasSource}
                        style={{
                          background: '#16A34A',
                          borderColor: '#16A34A',
                          fontSize: '12px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}
                      >
                        {isActionLoading ? 'Applying Patch…' : '🚀 Apply Approved Patch to Source'}
                      </button>
                    )}

                    {rem.status === 'PLAN_APPROVED' && (
                      <button
                        id={`btn-plan-disabled-${rem.id}`}
                        className="btn btn-secondary btn-sm"
                        disabled={true}
                        title="Automatic patch application disabled: local source file mapping required for this finding"
                        style={{
                          opacity: 0.7,
                          cursor: 'not-allowed',
                          fontSize: '12px',
                          background: '#F1F5F9',
                          color: '#64748B',
                          borderColor: '#CBD5E1',
                        }}
                      >
                        🔒 Apply Disabled (Manual Plan Required)
                      </button>
                    )}

                    {rem.status === 'APPLIED' && (
                      <button
                        id={`btn-verify-${rem.id}`}
                        className="btn btn-primary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleVerifyPatch(rem);
                        }}
                        disabled={isActionLoading}
                        style={{
                          background: '#2563EB',
                          borderColor: '#2563EB',
                          fontSize: '12px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}
                      >
                        {isActionLoading ? 'Running Tests…' : '🧪 Run Automated Verification'}
                      </button>
                    )}

                    {rem.status === 'VERIFIED' && (
                      <span
                        className="badge"
                        style={{ background: '#ECFDF5', color: '#065F46', borderColor: '#A7F3D0', padding: '6px 12px' }}
                      >
                        ✓ Verified Fixed
                      </span>
                    )}
                  </div>
                </div>

                {/* ── Expanded Full Finding Details ── */}
                {isExpanded && (
                  <div style={{ padding: '20px', borderTop: '1px solid #E2E8F0', background: '#FFFFFF' }}>
                    {/* Vulnerability Description and Technical Impact */}
                    <div style={{ marginBottom: '18px' }}>
                      <div
                        className="text-xs text-muted"
                        style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}
                      >
                        Vulnerability Description & Technical Impact
                      </div>
                      <div
                        style={{
                          fontSize: '13px',
                          color: '#334155',
                          lineHeight: 1.6,
                          background: '#F8FAFC',
                          padding: '12px 14px',
                          borderRadius: '6px',
                          border: '1px solid #E2E8F0',
                        }}
                      >
                        {rem.problem_explanation || rem.problem_summary || rem.problemSummary || 'No detailed vulnerability description recorded.'}
                      </div>
                    </div>

                    {/* Approved Remediation Strategy */}
                    <div style={{ marginBottom: '18px' }}>
                      <div
                        className="text-xs text-muted"
                        style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}
                      >
                        Approved Remediation Strategy & Implementation Guidance
                      </div>
                      <div
                        style={{
                          fontSize: '13px',
                          color: '#0F172A',
                          lineHeight: 1.6,
                          background: '#F0FDFA',
                          padding: '12px 14px',
                          borderRadius: '6px',
                          border: '1px solid #CCFBF1',
                        }}
                      >
                        {rem.technical_rationale || rem.recommended_fix || rem.recommendedFix || 'Apply recommended secure coding controls.'}
                      </div>
                    </div>

                    {/* Code Diff (When code_before and code_after are present) */}
                    {hasDiff ? (
                      <div style={{ marginBottom: '18px' }}>
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '6px',
                          }}
                        >
                          <div
                            className="text-xs text-muted"
                            style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}
                          >
                            Suggested Fix Code Diff — Target: <code>{rem.target_file || rem.targetFile}</code>
                          </div>
                          <button
                            className="btn btn-secondary btn-xs"
                            onClick={() => handleCopy(codeAfter, rem.id)}
                            style={{ padding: '2px 8px', fontSize: '11px' }}
                          >
                            {copiedId === rem.id ? '✓ Copied Fix!' : 'Copy Fix Snippet'}
                          </button>
                        </div>

                        <div
                          style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                            gap: '12px',
                          }}
                        >
                          {/* Before Code Block */}
                          <div>
                            <div
                              style={{
                                fontSize: '11px',
                                fontWeight: 600,
                                color: '#DC2626',
                                background: '#FEF2F2',
                                padding: '6px 12px',
                                borderTopLeftRadius: '6px',
                                borderTopRightRadius: '6px',
                                border: '1px solid #FECACA',
                                borderBottom: 'none',
                                display: 'flex',
                                justifyContent: 'space-between',
                              }}
                            >
                              <span>- Existing Insecure Code</span>
                              <span>Original</span>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                padding: '12px',
                                background: '#FFF5F5',
                                border: '1px solid #FECACA',
                                borderBottomLeftRadius: '6px',
                                borderBottomRightRadius: '6px',
                                color: '#991B1B',
                                fontFamily: 'var(--font-mono, monospace)',
                                fontSize: '12px',
                                lineHeight: 1.5,
                                maxHeight: '260px',
                                overflowY: 'auto',
                              }}
                            >
                              {codeBefore}
                            </pre>
                          </div>

                          {/* After Code Block */}
                          <div>
                            <div
                              style={{
                                fontSize: '11px',
                                fontWeight: 600,
                                color: '#16A34A',
                                background: '#F0FDF4',
                                padding: '6px 12px',
                                borderTopLeftRadius: '6px',
                                borderTopRightRadius: '6px',
                                border: '1px solid #BBF7D0',
                                borderBottom: 'none',
                                display: 'flex',
                                justifyContent: 'space-between',
                              }}
                            >
                              <span>+ Approved Replacement Patch</span>
                              <span>Remediated</span>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                padding: '12px',
                                background: '#F0FDF4',
                                border: '1px solid #BBF7D0',
                                borderBottomLeftRadius: '6px',
                                borderBottomRightRadius: '6px',
                                color: '#166534',
                                fontFamily: 'var(--font-mono, monospace)',
                                fontSize: '12px',
                                lineHeight: 1.5,
                                maxHeight: '260px',
                                overflowY: 'auto',
                              }}
                            >
                              {codeAfter}
                            </pre>
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Notice for findings without source context diff */
                      <div
                        style={{
                          marginBottom: '18px',
                          background: '#F8FAFC',
                          border: '1px solid #E2E8F0',
                          borderRadius: '6px',
                          padding: '12px 14px',
                        }}
                      >
                        <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '4px' }}>
                          ℹ️ No Concrete Code Diff Linked
                        </div>
                        <div className="text-xs text-secondary" style={{ lineHeight: 1.5 }}>
                          This finding was identified without mapped source code on the filesystem. Use the approved remediation guidance above to implement the security patch in the relevant endpoint or controller.
                        </div>
                      </div>
                    )}

                    {/* Potential Side Effects */}
                    {(rem.potential_side_effects || rem.side_effects || rem.potentialSideEffects) && (
                      <div
                        style={{
                          marginBottom: '18px',
                          background: '#FFFBEB',
                          border: '1px solid #FDE68A',
                          borderRadius: '6px',
                          padding: '10px 14px',
                        }}
                      >
                        <div style={{ fontSize: '12px', fontWeight: 600, color: '#B45309', marginBottom: '4px' }}>
                          ⚠️ Potential Side Effects & Implementation Risks:
                        </div>
                        <div className="text-xs" style={{ color: '#78350F', lineHeight: 1.5 }}>
                          {rem.potential_side_effects || rem.side_effects || rem.potentialSideEffects}
                        </div>
                      </div>
                    )}

                    {/* Verification Instructions & Commands */}
                    <div style={{ marginBottom: '16px' }}>
                      <div
                        className="text-xs text-muted"
                        style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}
                      >
                        Verification Instructions & Allowlisted Test Suite
                      </div>
                      <div
                        style={{
                          background: '#0F172A',
                          color: '#F8FAFC',
                          padding: '10px 14px',
                          borderRadius: '6px',
                          fontFamily: 'var(--font-mono, monospace)',
                          fontSize: '12px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <span>$ {rem.verification_command || rem.verificationCommand || 'npm test'}</span>
                        <span style={{ fontSize: '11px', color: '#94A3B8' }}>Allowlisted Verification Command</span>
                      </div>
                      {Array.isArray(rem.verification_steps) && rem.verification_steps.length > 0 && (
                        <ul style={{ margin: '8px 0 0 16px', padding: 0, fontSize: '12px', color: '#475569' }}>
                          {rem.verification_steps.map((step, idx) => (
                            <li key={idx} style={{ marginBottom: '4px' }}>
                              {step}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* Audit Ledger Metadata Footer */}
                    <div
                      style={{
                        paddingTop: '12px',
                        borderTop: '1px solid #E2E8F0',
                        display: 'flex',
                        flexWrap: 'wrap',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: '11px',
                        color: '#64748B',
                        gap: '8px',
                      }}
                    >
                      <div>
                        Assessment: <strong>{rem.assessment_id || rem.assessmentId}</strong> • Patch Version: <strong>v{rem.patch_version || 1}</strong>
                        {rem.backup_id && (
                          <span> • Backup Snapshot: <code>{rem.backup_id}</code></span>
                        )}
                        {rem.file_fingerprint && (
                          <span> • SHA-256: <code>{rem.file_fingerprint.substring(0, 12)}…</code></span>
                        )}
                      </div>
                      <div style={{ color: '#0F172A', fontWeight: 600 }}>
                        Audit Status: {rem.status}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Verification Output Modal ── */}
      {verificationModal && (
        <div
          className="modal-backdrop fade-in"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '20px',
          }}
          onClick={() => setVerificationModal(null)}
        >
          <div
            className="modal-card"
            style={{
              background: '#FFFFFF',
              borderRadius: '12px',
              maxWidth: '680px',
              width: '100%',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '20px' }}>🧪</span>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#0F172A' }}>
                  Verification Results — #{verificationModal.remId}
                </h3>
              </div>
              <button
                onClick={() => setVerificationModal(null)}
                style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#94A3B8' }}
              >
                ✕
              </button>
            </div>

            <div style={{ marginBottom: '14px', display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="text-xs text-muted">Finding: {verificationModal.findingId}</span>
              {renderStatusBadge(verificationModal.status)}
            </div>

            <div className="text-xs text-muted" style={{ fontWeight: 600, marginBottom: '6px' }}>
              Command Execution Log:
            </div>
            <pre
              style={{
                background: '#0F172A',
                color: '#34D399',
                padding: '14px',
                borderRadius: '8px',
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: '12px',
                lineHeight: 1.5,
                maxHeight: '300px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                margin: '0 0 18px 0',
              }}
            >
              {verificationModal.output}
            </pre>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary btn-sm" onClick={() => setVerificationModal(null)}>
                Close Results
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
