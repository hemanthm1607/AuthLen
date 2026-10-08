/**
 * remediation-engine/filePatcher.js — Safe, Atomic Code Patch Application & Rollback
 * =========================================================================
 * Enforces pre-flight content matching, rejects placeholders and ambiguous matches,
 * creates rollback backup snapshots with SHA-256 integrity hashes, and detects
 * subsequent user edits prior to rolling back.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { validateFilePath } = require('./pathSecurity');
const { isPlaceholderText, countSnippetOccurrences } = require('./sourceContextCollector');

// Root directory within project for recoverable snapshots
const BACKUP_DIR_NAME = '.authlens-backups';

/**
 * Normalizes code snippets for whitespace-tolerant matching
 */
function normalizeSnippet(str) {
  if (!str) return '';
  return str.replace(/\r\n/g, '\n').trim();
}

/**
 * Detects the predominant line ending in a string (\r\n or \n)
 */
function detectLineEnding(content) {
  const crlfCount = (content.match(/\r\n/g) || []).length;
  const lfCount = (content.match(/[^\r]\n/g) || []).length;
  return crlfCount > lfCount ? '\r\n' : '\n';
}

/**
 * Checks if target file exists and contains the expected code_before context uniquely
 *
 * @param {string} projectRoot
 * @param {string} targetFile
 * @param {string} codeBefore
 * @param {string} [codeAfter]
 * @returns {{ valid: boolean, exists: boolean, originalContent?: string, error?: string, lineEnding?: string }}
 */
function preflightCheck(projectRoot, targetFile, codeBefore, codeAfter) {
  const pathCheck = validateFilePath(projectRoot, targetFile);
  if (!pathCheck.valid) {
    return { valid: false, error: pathCheck.error };
  }

  // Reject placeholder content in either before or after
  if (isPlaceholderText(codeBefore)) {
    return {
      valid: false,
      error: 'INVALID_PATCH_CONTENT: Original code snippet is empty, missing, or contains placeholder text. Cannot apply an ungrounded patch.',
    };
  }

  if (codeAfter !== undefined && isPlaceholderText(codeAfter)) {
    return {
      valid: false,
      error: 'INVALID_PATCH_CONTENT: Proposed replacement code contains placeholder text (e.g. "Proposed fix", "TODO"). Cannot apply an incomplete patch.',
    };
  }

  const filePath = pathCheck.canonicalPath;
  if (!fs.existsSync(filePath)) {
    return {
      valid: false,
      error: `Target source file does not exist on disk: "${pathCheck.relativePath}". Cannot apply patch to nonexistent file.`,
    };
  }

  const originalContent = fs.readFileSync(filePath, 'utf8');
  const lineEnding = detectLineEnding(originalContent);

  // Verify that the file actually contains the code_before context
  const normFile = originalContent.replace(/\r\n/g, '\n');
  const normBefore = codeBefore.replace(/\r\n/g, '\n');

  const occurrences = countSnippetOccurrences(normFile, normBefore);

  if (occurrences === 0) {
    // Try trimmed snippet fallback
    const trimmedOccurrences = countSnippetOccurrences(normFile, normBefore.trim());
    if (trimmedOccurrences === 0) {
      return {
        valid: false,
        error: `STALE_FILE_MISMATCH: Target file "${pathCheck.relativePath}" does not contain the expected original code snippet. The file may have been modified since the assessment was performed. Patch rejected for safety. Please regenerate the remediation workflow.`,
      };
    }
    if (trimmedOccurrences > 1) {
      return {
        valid: false,
        error: `AMBIGUOUS_SNIPPET_MATCH: The original code snippet appears ${trimmedOccurrences} times in target file "${pathCheck.relativePath}". Provide more surrounding lines to uniquely identify the block to replace.`,
      };
    }
  } else if (occurrences > 1) {
    return {
      valid: false,
      error: `AMBIGUOUS_SNIPPET_MATCH: The original code snippet appears ${occurrences} times in target file "${pathCheck.relativePath}". Patch rejected to prevent modifying unintended code blocks.`,
    };
  }

  return {
    valid: true,
    exists: true,
    originalContent,
    filePath,
    relativePath: pathCheck.relativePath,
    lineEnding,
  };
}

/**
 * Creates a safe recoverable backup snapshot of a file before modification
 *
 * @param {string} projectRoot
 * @param {string|number} remediationId
 * @param {string} relativePath
 * @param {string} originalContent
 * @param {string} postPatchContent
 * @returns {string} Backup snapshot identifier
 */
function createBackupSnapshot(projectRoot, remediationId, relativePath, originalContent, postPatchContent = '') {
  const backupRoot = path.join(projectRoot, BACKUP_DIR_NAME);
  const timestamp = Date.now();
  const backupId = `${remediationId}_${timestamp}`;
  const snapshotDir = path.join(backupRoot, backupId);

  fs.mkdirSync(snapshotDir, { recursive: true });

  const backupFilePath = path.join(snapshotDir, path.basename(relativePath));
  fs.writeFileSync(backupFilePath, originalContent, 'utf8');

  // Manifest records both pre-patch and post-patch SHA-256 for subsequent edit detection
  const manifest = {
    remediationId: String(remediationId),
    timestamp,
    relativePath,
    prePatchSha256: crypto.createHash('sha256').update(originalContent, 'utf8').digest('hex'),
    postPatchSha256: postPatchContent
      ? crypto.createHash('sha256').update(postPatchContent, 'utf8').digest('hex')
      : null,
  };

  fs.writeFileSync(path.join(snapshotDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
  fs.writeFileSync(path.join(snapshotDir, 'backup-manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

  return backupId;
}

/**
 * Applies an approved patch to the target source file atomically
 */
function applyPatch(projectRoot, remediationOrTargetFile, codeBeforeArg, codeAfterArg, idArg) {
  let targetFile, codeBefore, codeAfter, remediationId;

  if (remediationOrTargetFile && typeof remediationOrTargetFile === 'object') {
    targetFile = remediationOrTargetFile.target_file || remediationOrTargetFile.targetFile || remediationOrTargetFile.file_path;
    codeBefore = remediationOrTargetFile.code_before || remediationOrTargetFile.codeBefore;
    codeAfter = remediationOrTargetFile.code_after || remediationOrTargetFile.codeAfter;
    remediationId = remediationOrTargetFile.id;
  } else {
    targetFile = remediationOrTargetFile;
    codeBefore = codeBeforeArg;
    codeAfter = codeAfterArg;
    remediationId = idArg;
  }

  // 1. Preflight check
  const check = preflightCheck(projectRoot, targetFile, codeBefore, codeAfter);
  if (!check.valid) {
    return { success: false, error: check.error };
  }

  const { filePath, originalContent, relativePath, lineEnding } = check;

  // 2. Compute new file content with line ending preservation
  const normFile = originalContent.replace(/\r\n/g, '\n');
  const normBefore = codeBefore.replace(/\r\n/g, '\n');
  const normAfter = codeAfter.replace(/\r\n/g, '\n');

  let newContentLf = '';
  if (normFile.includes(normBefore)) {
    newContentLf = normFile.replace(normBefore, normAfter);
  } else {
    newContentLf = normFile.replace(normBefore.trim(), normAfter.trim());
  }

  // Restore predominant line ending style
  const finalContent = lineEnding === '\r\n'
    ? newContentLf.replace(/\n/g, '\r\n')
    : newContentLf;

  // 3. Create backup snapshot
  let backupId = null;
  try {
    backupId = createBackupSnapshot(projectRoot, remediationId, relativePath, originalContent, finalContent);
  } catch (err) {
    return {
      success: false,
      error: `Failed to create pre-patch backup checkpoint: ${err.message}. Aborting patch to prevent unrecoverable edits.`,
    };
  }

  // 4. Atomic file write via temporary file
  const tempFilePath = `${filePath}.authlens.tmp`;
  try {
    fs.writeFileSync(tempFilePath, finalContent, 'utf8');
    fs.renameSync(tempFilePath, filePath);

    return {
      success: true,
      backupId,
      targetPath: filePath,
      relativePath,
      bytesWritten: Buffer.byteLength(finalContent, 'utf8'),
      sha256: crypto.createHash('sha256').update(finalContent, 'utf8').digest('hex'),
    };
  } catch (err) {
    if (fs.existsSync(tempFilePath)) {
      try { fs.unlinkSync(tempFilePath); } catch (_) {}
    }
    return {
      success: false,
      error: `Atomic write failure during patch application: ${err.message}`,
    };
  }
}

/**
 * Rolls back an applied patch using the created backup snapshot
 * Guarantees that subsequent user modifications are not accidentally overwritten.
 *
 * @param {string} projectRoot
 * @param {string|number} backupIdOrRemediationId
 * @param {Object} [options] - Options e.g. { force: false }
 * @returns {{ success: boolean, restoredPath?: string, error?: string }}
 */
function rollbackPatch(projectRoot, backupIdOrRemediationId, options = {}) {
  if (!backupIdOrRemediationId) {
    return { success: false, error: 'Valid backup ID or remediation ID is required for rollback.' };
  }

  const backupRoot = path.join(projectRoot, BACKUP_DIR_NAME);
  let snapshotDir = path.join(backupRoot, String(backupIdOrRemediationId));

  if (!fs.existsSync(snapshotDir)) {
    if (fs.existsSync(backupRoot)) {
      const candidates = fs.readdirSync(backupRoot).filter(
        (d) => d.startsWith(`${backupIdOrRemediationId}_`) || d === String(backupIdOrRemediationId)
      );
      if (candidates.length > 0) {
        candidates.sort().reverse();
        snapshotDir = path.join(backupRoot, candidates[0]);
      }
    }
  }

  let manifestPath = path.join(snapshotDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    manifestPath = path.join(snapshotDir, 'backup-manifest.json');
  }

  if (!fs.existsSync(manifestPath)) {
    return { success: false, error: `Backup snapshot manifest not found for identifier: ${backupIdOrRemediationId}` };
  }

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const relativePath = manifest.relativePath;
    const backupFilePath = path.join(snapshotDir, path.basename(relativePath));

    if (!fs.existsSync(backupFilePath)) {
      return { success: false, error: `Backup data file missing in snapshot: ${backupFilePath}` };
    }

    const restoredContent = fs.readFileSync(backupFilePath, 'utf8');
    const pathCheck = validateFilePath(projectRoot, relativePath);
    if (!pathCheck.valid) {
      return { success: false, error: pathCheck.error };
    }

    const targetPath = pathCheck.canonicalPath;

    // Subsequent user edits protection:
    // If the file currently exists, check if it was modified since the patch was applied
    if (fs.existsSync(targetPath) && manifest.postPatchSha256 && !options.force) {
      const currentContent = fs.readFileSync(targetPath, 'utf8');
      const currentSha256 = crypto.createHash('sha256').update(currentContent, 'utf8').digest('hex');

      if (currentSha256 !== manifest.postPatchSha256) {
        return {
          success: false,
          error: `SUBSEQUENT_CHANGES_DETECTED: Target file "${relativePath}" has been modified since this patch was applied. Rollback aborted to protect your subsequent edits.`,
        };
      }
    }

    // Atomic restore
    const tmpPath = `${targetPath}.rollback.tmp`;
    fs.writeFileSync(tmpPath, restoredContent, 'utf8');
    fs.renameSync(tmpPath, targetPath);

    return {
      success: true,
      restoredPath: relativePath,
    };
  } catch (err) {
    return { success: false, error: `Failed to restore rollback snapshot: ${err.message}` };
  }
}

module.exports = {
  BACKUP_DIR_NAME,
  detectLineEnding,
  preflightCheck,
  createBackupSnapshot,
  applyPatch,
  rollbackPatch,
};
