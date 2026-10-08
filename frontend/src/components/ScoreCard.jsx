/**
 * ScoreCard.jsx — Score display card with bar and monochrome SVG icon
 */
import React from 'react';

const CategoryIcons = {
  security: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z"/>
    </svg>
  ),
  usability: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M5.5 9.5s.8 1.5 2.5 1.5 2.5-1.5 2.5-1.5"/>
      <circle cx="6" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
      <circle cx="10" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
    </svg>
  ),
  accessibility: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="3.5" r="1.5"/>
      <path d="M3 7h10M8 7v7M5.5 14h5"/>
    </svg>
  ),
  recovery: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2.5 8A5.5 5.5 0 1114 8"/>
      <path d="M2.5 5v3h3"/>
    </svg>
  ),
};

export default function ScoreCard({ id, label, score, max = 100, trend }) {
  const pct = Math.round((score / max) * 100);
  const barClass = pct >= 80 ? 'good-score' : pct >= 60 ? 'mid-score' : 'low-score';
  const icon = id && CategoryIcons[id] ? CategoryIcons[id] : (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M8 5v3l2 2"/>
    </svg>
  );

  return (
    <div className="score-card">
      <div className="score-card-top">
        <div className="score-icon" aria-hidden="true">{icon}</div>
        <div style={{ textAlign: 'right' }}>
          <div className="score-value" aria-label={`${score} out of ${max}`}>
            {score}<span className="score-max">/{max}</span>
          </div>
        </div>
      </div>
      <div>
        <div className="score-label">{label}</div>
        <div
          className="score-bar-wrap"
          role="progressbar"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={max}
          aria-label={`${label} score: ${score}/${max}`}
        >
          <div className={`score-bar ${barClass}`} style={{ width: `${pct}%` }} />
        </div>
      </div>
      <div className="score-trend">{trend}</div>
    </div>
  );
}
