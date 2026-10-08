/**
 * UsabilityAccessibility.jsx — Usability and WCAG accessibility checks
 */
import React, { useState } from 'react';
import FindingCard from '../components/FindingCard';
import { usabilityFindings } from '../data/mockData';

const CATEGORY_TABS = ['All', 'Usability', 'Accessibility'];

export default function UsabilityAccessibility() {
  const [tab, setTab] = useState('All');

  const filtered = tab === 'All'
    ? usabilityFindings
    : usabilityFindings.filter((f) => f.category === tab);

  const usabilityCount     = usabilityFindings.filter((f) => f.category === 'Usability').length;
  const accessibilityCount = usabilityFindings.filter((f) => f.category === 'Accessibility').length;
  const highCount          = usabilityFindings.filter((f) => f.severity === 'high').length;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Accessibility Assessment</h1>
            <p className="page-subtitle">Form design heuristics and WCAG 2.1 AA accessibility compliance audit</p>
          </div>
          <span className="badge badge-sample">WCAG 2.1 AA Target</span>
        </div>
      </div>

      <div className="page-body">
        {/* Metric Cards */}
        <div className="section">
          <div className="grid-3">
            <div className="card" style={{ padding: '16px' }}>
              <div className="card-title">Usability Issues</div>
              <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {usabilityCount}
              </div>
              <div className="text-muted text-xs" style={{ marginTop: '6px' }}>
                Password toggle, autofocus, error messages
              </div>
            </div>

            <div className="card" style={{ padding: '16px' }}>
              <div className="card-title">Accessibility Flaws</div>
              <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {accessibilityCount}
              </div>
              <div className="text-muted text-xs" style={{ marginTop: '6px' }}>
                Screen reader labels, focus order, contrast
              </div>
            </div>

            <div className="card" style={{ padding: '16px' }}>
              <div className="card-title">High Priority</div>
              <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--sev-high)', lineHeight: 1 }}>
                {highCount}
              </div>
              <div className="text-muted text-xs" style={{ marginTop: '6px' }}>
                Require remediation for AA compliance
              </div>
            </div>
          </div>
        </div>

        {/* WCAG Reference Panel */}
        <div className="section">
          <div className="card">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ flex: 1, minWidth: '240px' }}>
                <div className="card-title" style={{ marginBottom: '4px' }}>
                  Compliance Baseline: WCAG 2.1 Level AA
                </div>
                <div className="text-secondary text-sm">
                  Evaluates auth flows for non-text contrast, keyboard trap avoidance, aria-live status regions, and descriptive error indicators.
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {['Perceivable', 'Operable', 'Understandable', 'Robust'].map((p) => (
                  <span key={p} className="badge badge-demo" style={{ padding: '4px 8px' }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Category Tabs & Findings */}
        <div className="section">
          <div style={{ display: 'flex', gap: '6px', marginBottom: '14px' }}>
            {CATEGORY_TABS.map((t) => (
              <button
                key={t}
                id={`ua-tab-${t.toLowerCase()}`}
                className={`btn btn-xs${tab === t ? ' btn-primary' : ' btn-secondary'}`}
                onClick={() => setTab(t)}
                aria-pressed={tab === t}
              >
                {t}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {filtered.map((f) => (
              <FindingCard key={f.id} finding={f} showCode={false} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
