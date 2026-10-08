/**
 * remediation-engine/pathSecurity.js — Strict Path Traversal & Symlink Defense
 * Ensures all file access and patch operations are strictly confined within the
 * explicitly authorized project root, excluding sensitive credentials and system files.
 */
const path = require('path');
const fs = require('fs');

// Blacklisted filenames, extensions, and directory segments that can NEVER be accessed or patched
const EXCLUDED_PATTERNS = [
  /^\.env(\..+)?$/i,               // .env, .env.local, .env.production, etc.
  /\.(pem|key|cert|pfx|pkcs12)$/i, // Private keys and certificate files
  /^id_rsa/i,                      // SSH keys
  /^credentials/i,                 // Cloud / DB credentials
  /(^|[/\\])node_modules([/\\]|$)/i,
  /(^|[/\\])\.git([/\\]|$)/i,
  /(^|[/\\])\.authlens-backups([/\\]|$)/i,
  /(^|[/\\])(dist|build|\.next|\.vercel)([/\\]|$)/i,
];

/**
 * Validates a target project root directory
 * @param {string} rawProjectRoot
 * @returns {{ valid: boolean, canonicalRoot?: string, error?: string }}
 */
function validateProjectRoot(rawProjectRoot) {
  if (!rawProjectRoot || typeof rawProjectRoot !== 'string') {
    return { valid: false, error: 'Project root path is required.' };
  }

  const resolved = path.resolve(rawProjectRoot.trim());
  if (!fs.existsSync(resolved)) {
    return { valid: false, error: `Project root directory does not exist: ${resolved}` };
  }

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    return { valid: false, error: `Project root path is not a directory: ${resolved}` };
  }

  try {
    const canonical = fs.realpathSync(resolved);
    return { valid: true, canonicalRoot: canonical };
  } catch (err) {
    return { valid: false, error: `Could not resolve canonical project path: ${err.message}` };
  }
}

/**
 * Validates a target file path relative to an authorized project root
 * @param {string} projectRoot - Authorized root directory
 * @param {string} targetFile - Relative file path to inspect or patch
 * @returns {{ valid: boolean, canonicalPath?: string, relativePath?: string, error?: string }}
 */
function validateFilePath(projectRoot, targetFile) {
  const rootValidation = validateProjectRoot(projectRoot);
  if (!rootValidation.valid) {
    return { valid: false, error: rootValidation.error };
  }
  const root = rootValidation.canonicalRoot;

  if (!targetFile || typeof targetFile !== 'string') {
    return { valid: false, error: 'Target file path is required.' };
  }

  // 1. Detect null bytes
  if (targetFile.includes('\0')) {
    return { valid: false, error: 'Path traversal / null-byte injection detected.' };
  }

  // 2. Reject absolute paths specified by client
  const trimmed = targetFile.trim();
  if (path.isAbsolute(trimmed) || /^[a-zA-Z]:[/\\]/.test(trimmed)) {
    return { valid: false, error: 'Absolute paths are strictly forbidden. Target file must be relative to the project root.' };
  }

  // 3. Normalize and resolve within project root
  const resolved = path.resolve(root, trimmed);
  const relativeFromRoot = path.relative(root, resolved);

  // 4. Enforce strict containment within project root
  if (relativeFromRoot.startsWith('..') || path.isAbsolute(relativeFromRoot)) {
    return { valid: false, error: 'Path traversal attempt detected. Target file escapes the authorized project root.' };
  }

  // 5. Check against forbidden sensitive patterns and extensions
  const normalizedSlashPath = relativeFromRoot.replace(/\\/g, '/');
  const baseFilename = path.basename(resolved);

  for (const pattern of EXCLUDED_PATTERNS) {
    if (pattern.test(baseFilename) || pattern.test(normalizedSlashPath)) {
      return {
        valid: false,
        error: `Security policy violation: Modifying or reading sensitive file/directory "${normalizedSlashPath}" is forbidden.`,
      };
    }
  }

  // 6. Symlink escape detection
  if (fs.existsSync(resolved)) {
    try {
      const canonical = fs.realpathSync(resolved);
      const canonicalRel = path.relative(root, canonical);
      if (canonicalRel.startsWith('..') || path.isAbsolute(canonicalRel)) {
        return { valid: false, error: 'Symlink escape detected. File resolves outside the authorized project root.' };
      }
      return {
        valid: true,
        canonicalPath: canonical,
        relativePath: normalizedSlashPath,
      };
    } catch (err) {
      return { valid: false, error: `Failed to resolve canonical path: ${err.message}` };
    }
  }

  // File does not exist yet (e.g. creating a new module)
  return {
    valid: true,
    canonicalPath: resolved,
    relativePath: normalizedSlashPath,
  };
}

module.exports = {
  EXCLUDED_PATTERNS,
  validateProjectRoot,
  validateFilePath,
};
