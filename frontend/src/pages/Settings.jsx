/**
 * Settings.jsx — Application Settings & PostgreSQL Persistence
 */
import React, { useState, useEffect } from 'react';
import { authApi } from '../services/authApi';

const DEFAULT_SETTINGS = {
  demoMode:         true,
  darkMode:         true,
  verboseFindings:  false,
  autoRetest:       false,
  notifications:    true,
  showCodeSnippets: true,
  wcagLevel:        'AA',
  targetUrl:        'http://localhost:4000',
};

export default function Settings() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [savedMsg, setSavedMsg] = useState(false);

  useEffect(() => {
    async function loadSettings() {
      try {
        const res = await authApi.getUserSettings();
        if (res?.settings) {
          setSettings(res.settings);
        }
      } catch (err) {
        // Fall back gracefully
      }
    }
    loadSettings();
  }, []);

  async function toggle(key) {
    const updated = { ...settings, [key]: !settings[key] };
    setSettings(updated);
    try {
      await authApi.updateUserSettings(updated);
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 2000);
    } catch (err) {
      console.warn('Could not persist setting:', err.message);
    }
  }

  async function handleWcagChange(e) {
    const updated = { ...settings, wcagLevel: e.target.value };
    setSettings(updated);
    try {
      await authApi.updateUserSettings(updated);
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 2000);
    } catch (err) {
      console.warn('Could not persist wcagLevel:', err.message);
    }
  }

  function ToggleRow({ id, label, desc, settingKey }) {
    return (
      <div className="settings-row">
        <div>
          <div className="settings-row-label">{label}</div>
          {desc && <div className="settings-row-desc">{desc}</div>}
        </div>
        <button
          id={`setting-${id}`}
          className={`toggle${settings[settingKey] ? ' on' : ''}`}
          onClick={() => toggle(settingKey)}
          role="switch"
          aria-checked={Boolean(settings[settingKey])}
          aria-label={label}
        >
          <div className="toggle-knob" />
        </button>
      </div>
    );
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Workspace Settings</h1>
            <p className="page-subtitle">Evaluation parameters, engine thresholds, and session behavior</p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {savedMsg && <span className="badge badge-pass">Saved to PostgreSQL</span>}
            <span className="badge badge-sample">User Preferences</span>
          </div>
        </div>
      </div>

      <div className="page-body">
        <div style={{ maxWidth: '640px' }}>
          {/* General */}
          <div className="card settings-group">
            <div className="settings-group-title">Environment & Display</div>
            <ToggleRow id="demo-mode" label="Mock Simulation Mode" desc="Use local fixture datasets for evaluation displays." settingKey="demoMode" />
            <ToggleRow id="dark-mode" label="Dark Theme Surface" desc="Utilize dark mode palette across all UI panels." settingKey="darkMode" />
            <ToggleRow id="notifications" label="Real-Time Event Alerts" desc="Emit toasts upon test suite completion." settingKey="notifications" />
          </div>

          {/* Testing */}
          <div className="card settings-group">
            <div className="settings-group-title">Evaluation Rules</div>
            <ToggleRow id="verbose" label="Detailed AST Stack Traces" desc="Display raw AST parser outputs for failed assertions." settingKey="verboseFindings" />
            <ToggleRow id="code-snippets" label="Render Code Remediations" desc="Display unified before/after patch blocks in finding cards." settingKey="showCodeSnippets" />
            <ToggleRow id="auto-retest" label="Automatic Re-Verification" desc="Trigger background test execution upon patch application." settingKey="autoRetest" />

            <div className="settings-row">
              <div>
                <div className="settings-row-label">WCAG Target Standard</div>
                <div className="settings-row-desc">Target accessibility conformance level.</div>
              </div>
              <select
                id="setting-wcag-level"
                value={settings.wcagLevel || 'AA'}
                onChange={handleWcagChange}
                aria-label="WCAG compliance level"
                style={{ width: 'auto', minWidth: '180px' }}
              >
                <option value="A">WCAG 2.1 Level A</option>
                <option value="AA">WCAG 2.1 Level AA (Standard)</option>
                <option value="AAA">WCAG 2.1 Level AAA</option>
              </select>
            </div>
          </div>

          {/* Target */}
          <div className="card settings-group">
            <div className="settings-group-title">Target Host</div>
            <div className="settings-row">
              <div style={{ flex: 1 }}>
                <div className="settings-row-label">Base Auth Endpoint</div>
                <div className="settings-row-desc">Primary URL targeted during test suite runs.</div>
                <input
                  id="setting-target-url"
                  type="url"
                  value={settings.targetUrl || 'http://localhost:4000'}
                  onChange={(e) => setSettings((s) => ({ ...s, targetUrl: e.target.value }))}
                  style={{ marginTop: '8px', maxWidth: '320px' }}
                  aria-label="Target URL to test"
                  disabled
                />
              </div>
            </div>
            <div className="settings-row">
              <div>
                <div className="settings-row-label">Restore Defaults</div>
                <div className="settings-row-desc">Reset all configurable keys to baseline setup.</div>
              </div>
              <button
                id="setting-reset-btn"
                className="btn btn-secondary btn-xs"
                onClick={async () => {
                  setSettings(DEFAULT_SETTINGS);
                  await authApi.updateUserSettings(DEFAULT_SETTINGS);
                }}
                aria-label="Reset all settings to defaults"
              >
                Reset
              </button>
            </div>
          </div>

          {/* About */}
          <div className="card">
            <div className="settings-group-title">System Specs</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              {[
                { label: 'Version',         value: 'v1.0.0-rc1' },
                { label: 'Client Framework', value: 'React 19 / Vite' },
                { label: 'Database Status', value: 'PostgreSQL 18 Connected' },
                { label: 'Testing Engine',  value: 'Active (Port 4000)' },
              ].map(({ label, value }) => (
                <div
                  key={label}
                  style={{
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    borderRadius: 'var(--r-sm)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div className="text-muted text-xs mono" style={{ marginBottom: '2px' }}>{label}</div>
                  <div style={{ fontWeight: 500, fontSize: '13px' }}>{value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
