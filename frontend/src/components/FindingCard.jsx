/**
 * FindingCard.jsx — Collapsible finding card with status, evidence, and remediation code
 */
import React, { useState } from 'react';
import Badge from './Badge';

export default function FindingCard({ finding, showCode = false }) {
  const [open, setOpen] = useState(false);
  const [fixed, setFixed] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);

  const {
    id, title, severity, category,
    risk, recommendation,
    codeBefore, codeAfter,
    impact, improvement,
    description,
    status, evidence, isAutomated,
  } = finding;

  const riskText        = risk || description || '';
  const recommendText   = recommendation || improvement || '';

  function handleFix(e) {
    e.stopPropagation();
    setFixed(true);
  }

  function handleCopyPatch(e) {
    e.stopPropagation();
    if (codeAfter) {
      navigator.clipboard.writeText(codeAfter).then(() => {
        setCopiedPatch(true);
        setTimeout(() => setCopiedPatch(false), 2000);
      }).catch(() => {});
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      setOpen((o) => !o);
    }
  }

  // Determine status badge
  const displayStatus = status ? status.toUpperCase() : null;
  const isPass = displayStatus === 'PASS';
  const isReview = displayStatus === 'NEEDS_REVIEW' || displayStatus === 'NEEDS REVIEW';

  return (
    <div className="finding-card fade-in" id={`finding-${id}`}>
      {/* Header — always visible, clickable to expand */}
      <div
        className="finding-card-header"
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
        aria-controls={`finding-body-${id}`}
        tabIndex={0}
        onKeyDown={handleKeyDown}
      >
        <span className="finding-id">{id}</span>
        <span className="finding-card-title">{title}</span>
        <div className="finding-card-meta">
          {displayStatus && (
            <Badge
              type={isPass ? 'pass' : isReview ? 'medium' : severity?.toLowerCase() || 'critical'}
              label={isPass ? 'PASS' : isReview ? 'NEEDS REVIEW' : `${severity?.toUpperCase() || 'FAIL'}`}
            />
          )}
          {!displayStatus && (
            <Badge type={fixed ? 'pass' : severity} label={fixed ? 'Fixed (Demo)' : undefined} />
          )}
          {category && (
            <span className="text-muted text-xs" style={{ whiteSpace: 'nowrap' }}>{category}</span>
          )}
          <span className={`chevron${open ? ' open' : ''}`} aria-hidden="true">▼</span>
        </div>
      </div>

      {/* Expandable body */}
      <div
        id={`finding-body-${id}`}
        className={`finding-card-body${open ? ' expanded' : ' collapsed'}`}
      >
        {evidence && (
          <div className="finding-section">
            <div className="finding-section-label">Observed Test Evidence</div>
            <div className="code-block" style={{ margin: 0, padding: '8px 12px', fontSize: '12px', background: 'var(--bg-elevated)' }}>
              {evidence}
            </div>
            {isAutomated !== undefined && (
              <div className="text-muted text-xs" style={{ marginTop: '6px' }}>
                Mode: {isAutomated ? 'Automated Verification' : 'Requires Manual Inspection'}
              </div>
            )}
          </div>
        )}

        {riskText && (
          <div className="finding-section">
            <div className="finding-section-label">Risk & Impact</div>
            <p className="finding-text">{riskText}</p>
          </div>
        )}

        {recommendText && (
          <div className="finding-section">
            <div className="finding-section-label">Recommended Remediation</div>
            <p className="finding-text">{recommendText}</p>
          </div>
        )}

        {showCode && codeBefore && (
          <div className="finding-section">
            <div className="before-after">
              <div className="before-after-panel before">
                <div className="before-after-label">Vulnerable Implementation</div>
                <pre className="code-block">{codeBefore}</pre>
              </div>
              <div className="before-after-panel after">
                <div className="before-after-label" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>Remediated Implementation</span>
                  <button
                    type="button"
                    className="btn btn-secondary btn-xs"
                    onClick={handleCopyPatch}
                    aria-label="Copy remediated code patch"
                    style={{ fontSize: '11px', padding: '2px 8px', height: '22px' }}
                  >
                    {copiedPatch ? '✓ Copied' : 'Copy Patch'}
                  </button>
                </div>
                <pre className="code-block">{codeAfter}</pre>
              </div>
            </div>
          </div>
        )}

        {!fixed && severity !== 'info' && severity !== 'Info' && (
          <div className="finding-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <button
                id={`fix-btn-${id}`}
                className="btn btn-secondary btn-sm"
                onClick={handleFix}
                aria-label={`Mark ${id} as resolved in session`}
              >
                Apply Session Remediation
              </button>
              <span className="text-muted text-xs">
                Simulates applying the suggested patch pattern to current evaluation state.
              </span>
            </div>
          </div>
        )}

        {fixed && (
          <div className="finding-section">
            <div className="notice success">
              Remediation applied to current session. Re-execute the test suite to verify mitigation.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
