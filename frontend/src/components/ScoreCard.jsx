/**
 * ScoreCard.jsx — Enterprise Score display card with progress indicator, category tags, and trends
 */
import React from 'react';

const CategoryIcons = {
  security: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z"/>
      <path d="M6 8l1.5 1.5L10 6.5"/>
    </svg>
  ),
  usability: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M5.5 9.5s.8 1.5 2.5 1.5 2.5-1.5"/>
      <circle cx="6" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
      <circle cx="10" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
    </svg>
  ),
  accessibility: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="3.5" r="1.5"/>
      <path d="M3 7h10M8 7v7M5.5 14h5"/>
    </svg>
  ),
  recovery: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2.5 8A5.5 5.5 0 1114 8"/>
      <path d="M2.5 5v3h3"/>
    </svg>
  ),
};

const CategoryThemes = {
  security:      { iconBg: '#EFF6FF', iconBorder: '#BFDBFE', iconColor: '#2563EB' },
  usability:     { iconBg: '#F0F9FF', iconBorder: '#BAE6FD', iconColor: '#0284C7' },
  accessibility: { iconBg: '#FAF5FF', iconBorder: '#E9D5FF', iconColor: '#9333EA' },
  recovery:      { iconBg: '#FFFBEB', iconBorder: '#FDE68A', iconColor: '#D97706' },
};

export default function ScoreCard({ id, label, score, max = 100, trend, description, onClick, statusText }) {
  const isNumericScore = typeof score === 'number' && !isNaN(score);
  const pct = isNumericScore ? Math.max(0, Math.min(100, Math.round((score / max) * 100))) : 0;

  // Determine display status label and badge class
  let statusLabel = statusText;
  let statusClass = 'badge-sample';

  if (statusText) {
    if (statusText === 'Not Applicable') {
      statusClass = 'badge-na';
    } else if (statusText === 'Insufficient data') {
      statusClass = 'badge-sample';
    } else if (statusText === 'Secure' || statusText === 'Passing') {
      statusClass = 'badge-pass';
    } else if (statusText === 'Adequate') {
      statusClass = 'badge-sample';
    } else if (statusText === 'Needs Hardening' || statusText === 'Needs Review' || statusText === 'Critical Risk') {
      statusClass = 'badge-fail';
    }
  } else if (isNumericScore) {
    statusLabel = pct >= 80 ? 'Secure' : pct >= 60 ? 'Adequate' : 'Needs Review';
    statusClass = pct >= 80 ? 'badge-pass' : pct >= 60 ? 'badge-sample' : 'badge-fail';
  } else {
    statusLabel = 'Insufficient data';
    statusClass = 'badge-sample';
  }

  const barClass = !isNumericScore
    ? 'na-score'
    : pct >= 80 ? 'good-score' : pct >= 60 ? 'mid-score' : 'low-score';

  const theme = id && CategoryThemes[id] ? CategoryThemes[id] : {
    iconBg: '#F1F5F9',
    iconBorder: '#CBD5E1',
    iconColor: '#2563EB',
  };

  const icon = id && CategoryIcons[id] ? CategoryIcons[id] : (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M8 5v3l2 2"/>
    </svg>
  );

  return (
    <div
      className={`score-card${onClick ? ' score-card-interactive' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}
      aria-label={`${label} domain scorecard: ${isNumericScore ? `${score} out of ${max}` : statusLabel}. Status: ${statusLabel}`}
    >
      <div className="score-card-top">
        <div
          className="score-icon"
          aria-hidden="true"
          style={{
            background: theme.iconBg,
            borderColor: theme.iconBorder,
            color: theme.iconColor,
          }}
        >
          {icon}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '3px' }}>
          <div className="score-value" aria-hidden="true">
            {isNumericScore ? score : '—'}{isNumericScore ? <span className="score-max">/{max}</span> : ''}
          </div>
          <span className={`badge ${statusClass}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
            {statusLabel}
          </span>
        </div>
      </div>

      <div className="score-info-block">
        <div className="score-label">{label}</div>
        {description && (
          <div className="score-desc" title={description}>
            {description}
          </div>
        )}
      </div>

      <div className="score-metric-section">
        <div
          className="score-bar-wrap"
          role="progressbar"
          aria-valuenow={isNumericScore ? score : 0}
          aria-valuemin={0}
          aria-valuemax={max}
          aria-label={`${label} progress: ${isNumericScore ? `${score}/${max}` : statusLabel}`}
        >
          <div className={`score-bar ${barClass}`} style={{ width: isNumericScore ? `${pct}%` : '0%' }} />
        </div>
      </div>

      <div className="score-card-footer">
        <div className="score-trend">
          <span className="score-trend-indicator" aria-hidden="true">
            {isNumericScore ? (pct >= 60 ? '↑' : '⚠') : 'ℹ'}
          </span>
          {trend || 'Evaluated against baseline'}
        </div>
      </div>
    </div>
  );
}
