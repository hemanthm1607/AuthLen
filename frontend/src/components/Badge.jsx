/**
 * Badge.jsx — Severity / status badge
 */
import React from 'react';
import { capitalize } from '../utils/helpers';

const DOTS = {
  critical: '●',
  high:     '●',
  medium:   '●',
  low:      '●',
  info:     '●',
  pass:     '✓',
  fail:     '✕',
  demo:     '◈',
};

export default function Badge({ type, label }) {
  const t = type?.toLowerCase() ?? 'info';
  const displayLabel = label ?? capitalize(t);
  const dot = DOTS[t] ?? '●';
  return (
    <span className={`badge badge-${t}`} aria-label={`Severity: ${displayLabel}`}>
      <span aria-hidden="true">{dot}</span>
      {displayLabel}
    </span>
  );
}
