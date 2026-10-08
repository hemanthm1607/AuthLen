/**
 * remediation-engine/index.js — Unified User-Approved Remediation Engine
 * Exports core functions and high-level safe wrappers for both the Express
 * backend controller and the local AuthLens Companion CLI.
 */

const pathSecurity = require('./pathSecurity');
const filePatcher = require('./filePatcher');
const verifier = require('./verifier');
const sourceContextCollector = require('./sourceContextCollector');

/**
 * Validates project path and throws descriptive error if invalid
 */
function validateProjectPath(projectRoot, targetFile) {
  const res = pathSecurity.validateFilePath(projectRoot, targetFile);
  if (!res.valid) {
    if (res.error && res.error.includes('sensitive')) {
      throw new Error(`SECURITY_VIOLATION: Access to sensitive file is prohibited: ${res.error}`);
    }
    if (res.error && res.error.includes('null-byte')) {
      throw new Error(`SECURITY_VIOLATION: Null bytes not allowed: ${res.error}`);
    }
    throw new Error(`SECURITY_VIOLATION: Path traversal detected: ${res.error}`);
  }
  return {
    resolvedPath: res.canonicalPath,
    relativePath: res.relativePath,
  };
}

/**
 * Resolves canonical project root or throws error
 */
function resolveProjectRoot(rawProjectRoot) {
  const res = pathSecurity.validateProjectRoot(rawProjectRoot);
  if (!res.valid) {
    throw new Error(`Invalid project root: ${res.error}`);
  }
  return res.canonicalRoot;
}

/**
 * High-level patch helper that executes pre-flight checks, backup snapshot,
 * and atomic write, throwing Error on failure.
 */
function patchFile(projectRoot, targetFile, codeBefore, codeAfter, remediationId) {
  const res = filePatcher.applyPatch(projectRoot, targetFile, codeBefore, codeAfter, remediationId);
  if (!res.success) {
    throw new Error(res.error || 'Patch application failed');
  }
  return res;
}

/**
 * High-level rollback helper that restores from backup snapshot or throws
 */
function restoreBackup(projectRoot, remediationId) {
  const res = filePatcher.rollbackPatch(projectRoot, remediationId);
  if (!res.success) {
    throw new Error(res.error || 'Rollback restoration failed');
  }
  return {
    success: true,
    targetPath: res.restoredPath,
    restoredFrom: `Snapshot for #${remediationId}`,
  };
}

/**
 * Command allowlist validator
 */
function validateVerificationCommand(cmd) {
  return {
    isValid: verifier.isCommandAllowlisted(cmd),
  };
}

/**
 * Runs allowlisted verification command
 */
async function runVerificationCommand(cmd, projectRoot, timeoutMs = 30000) {
  return verifier.runAllowlistedCommand(projectRoot, cmd, timeoutMs);
}

module.exports = {
  ...pathSecurity,
  ...filePatcher,
  ...verifier,
  ...sourceContextCollector,
  validateProjectPath,
  resolveProjectRoot,
  patchFile,
  restoreBackup,
  validateVerificationCommand,
  runVerificationCommand,
};
