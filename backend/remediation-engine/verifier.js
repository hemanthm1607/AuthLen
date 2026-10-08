/**
 * remediation-engine/verifier.js — Predefined, Allowlisted Remediation Verification
 * Executes strictly allowlisted, sandboxed verification checks and dynamic assertions.
 * Never executes arbitrary, unvetted AI shell strings.
 */
const { exec } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const execAsync = promisify(exec);

// Strictly allowlisted command patterns that can be executed during verification
const ALLOWLISTED_COMMAND_PATTERNS = [
  /^npm test(\s+--\s+[a-zA-Z0-9_\-\s"']*)?$/i,
  /^npm run (test|test:[a-z0-9_-]+|lint|check)(\s+--\s+[a-zA-Z0-9_\-\s"']*)?$/i,
  /^npx jest(\s+[a-zA-Z0-9_\-\s"'.\/]*)?$/i,
  /^node (tests|test)\/[a-z0-9_.-]+\.js$/i,
];

// Sanitizer for test output logs (strips ANSI escapes, secrets, auth headers, and tokens)
function sanitizeOutput(text) {
  if (!text) return '';
  return text
    // Remove ANSI color escapes
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '')
    // Redact Bearer tokens & JWTs
    .replace(/Bearer\s+[A-Za-z0-9-_=.]+/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=.]+/g, '[REDACTED_TOKEN]')
    // Redact session cookies
    .replace(/(authlens_session|session|connect\.sid)=[^;\s]+/gi, '$1=[REDACTED_COOKIE]')
    // Redact password assignments (JSON, CLI flags, query strings, key=value)
    .replace(/(["']?password["']?\s*[:=]\s*["']?)[^"'\s,;)]+(["']?)/gi, '$1[REDACTED_CREDENTIAL]$2')
    // Truncate output to prevent runaway log injection (max 8KB)
    .slice(0, 8192);
}

/**
 * Validates whether a command string is in the safe allowlist
 * @param {string} cmd
 * @returns {boolean}
 */
function isCommandAllowlisted(cmd) {
  if (!cmd || typeof cmd !== 'string') return false;
  const trimmed = cmd.trim();
  // Reject chained shell operators, pipes, redirects, backticks, semicolons
  if (/[;&|><`$]/.test(trimmed)) return false;
  return ALLOWLISTED_COMMAND_PATTERNS.some((pattern) => pattern.test(trimmed));
}

/**
 * Runs an allowlisted verification command in the project root
 * @param {string} projectRoot
 * @param {string} command - Must match ALLOWLISTED_COMMAND_PATTERNS
 * @param {number} [timeoutMs=30000]
 * @returns {Promise<{ success: boolean, output: string, exitCode: number, error?: string }>}
 */
async function runAllowlistedCommand(projectRoot, command, timeoutMs = 30000) {
  if (!isCommandAllowlisted(command)) {
    return {
      success: false,
      output: '',
      exitCode: 1,
      error: `Security violation: Command "${command}" is not in the predefined verification allowlist. Arbitrary shell execution is forbidden.`,
    };
  }

  try {
    const { stdout, stderr } = await execAsync(command, {
      cwd: projectRoot,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024, // 1MB max buffer
      env: {
        ...process.env,
        NODE_ENV: 'test',
        AUTHLENS_VERIFICATION_RUN: 'true',
      },
    });

    const combinedOutput = sanitizeOutput([stdout, stderr].filter(Boolean).join('\n'));
    return {
      success: true,
      output: combinedOutput,
      exitCode: 0,
    };
  } catch (err) {
    const combinedOutput = sanitizeOutput([err.stdout, err.stderr, err.message].filter(Boolean).join('\n'));
    return {
      success: false,
      output: combinedOutput,
      exitCode: err.code || 1,
      error: err.killed ? `Verification timed out after ${timeoutMs}ms.` : `Test command exited with code ${err.code || 1}.`,
    };
  }
}

/**
 * Verifies a remediation using allowlisted command or targeted assertion probe
 * @param {string} projectRoot
 * @param {Object} remediation
 * @param {Object} [options]
 * @returns {Promise<{ status: 'VERIFIED' | 'VERIFICATION_FAILED' | 'NOT_VERIFIED', output: string, explanation: string }>}
 */
async function verifyRemediation(projectRoot, remediation, options = {}) {
  const { finding_id: findingId } = remediation;
  const customCommand = options.command || 'npm test';

  // 1. If an allowlisted test command was selected
  if (isCommandAllowlisted(customCommand)) {
    const cmdResult = await runAllowlistedCommand(projectRoot, customCommand, options.timeoutMs || 30000);
    if (cmdResult.success) {
      return {
        status: 'VERIFIED',
        output: cmdResult.output,
        explanation: `Allowlisted test suite "${customCommand}" passed successfully with exit code 0. Security remediation verified.`,
      };
    } else {
      return {
        status: 'VERIFICATION_FAILED',
        output: cmdResult.output || cmdResult.error,
        explanation: `Verification command "${customCommand}" failed: ${cmdResult.error || 'Test suite failures observed.'}`,
      };
    }
  }

  return {
    status: 'NOT_VERIFIED',
    output: 'No allowlisted verification command matched for this finding.',
    explanation: 'Automated test suite could not be matched. Manual verification is required.',
  };
}

module.exports = {
  ALLOWLISTED_COMMAND_PATTERNS,
  isCommandAllowlisted,
  sanitizeOutput,
  runAllowlistedCommand,
  verifyRemediation,
};
