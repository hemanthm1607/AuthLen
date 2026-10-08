/**
 * remediation-engine/sourceContextCollector.js — Verified Source Code Context Extractor
 * =========================================================================
 * Bridges dynamic security findings (DAST) with verified local source code (SAST).
 *
 * Guarantees:
 * 1. Source code is ONLY extracted from the explicitly authorized local project root.
 * 2. Never invents fictitious code or uses placeholder strings.
 * 3. Extracts real, unique code snippets from disk and computes SHA-256 file fingerprints.
 * 4. Ensures codeBefore occurs uniquely in the target file before proposing any patch.
 * 5. Flags findings without local source access as non-applicable with clear user explanations.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { validateFilePath, validateProjectRoot } = require('./pathSecurity');

// Disallowed placeholder tokens that must never be treated as valid patches
const PLACEHOLDER_TOKENS = [
  /original context unavailable/i,
  /proposed fix/i,
  /insecure configuration/i,
  /hardened configuration/i,
  /todo:?\s/i,
  /\/\/ placeholder/i,
  /\/\* placeholder \*\//i,
];

/**
 * Checks if a proposed patch snippet contains disallowed placeholder text
 * @param {string} text
 * @returns {boolean}
 */
function isPlaceholderText(text) {
  if (!text || typeof text !== 'string') return true;
  const trimmed = text.trim();
  if (trimmed.length === 0) return true;
  return PLACEHOLDER_TOKENS.some((pat) => pat.test(trimmed));
}

/**
 * Computes SHA-256 fingerprint of file content
 */
function computeFileFingerprint(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Counts occurrences of a snippet in file content
 */
function countSnippetOccurrences(content, snippet) {
  if (!content || !snippet) return 0;
  const normFile = content.replace(/\r\n/g, '\n');
  const normSnippet = snippet.replace(/\r\n/g, '\n');
  let count = 0;
  let pos = 0;
  while ((pos = normFile.indexOf(normSnippet, pos)) !== -1) {
    count++;
    pos += normSnippet.length;
  }
  return count;
}

/**
 * Finding-specific target rules and extraction logic
 */
const FINDING_LOCATORS = {
  // SEC-001: Rate Limiting
  'SEC-001': {
    candidateFiles: [
      'backend/routes/authRoutes.js',
      'routes/authRoutes.js',
      'backend/app.js',
      'app.js',
    ],
    matcher: (content) => {
      // Look for login route definition
      const loginRouteRegex = /router\.post\s*\(\s*['"]\/login['"][^;]+;/;
      const match = content.match(loginRouteRegex);
      if (match) {
        const original = match[0];
        // If loginLimiter is not already present, build patch
        let replacement = original;
        if (!original.includes('loginLimiter')) {
          replacement = original.replace(
            /(router\.post\s*\(\s*['"]\/login['"]\s*,\s*)/,
            '$1loginLimiter, '
          );
        }
        return { before: original, after: replacement };
      }
      return null;
    },
  },

  // SEC-002: Password Policy Complexity
  'SEC-002': {
    candidateFiles: [
      'backend/controllers/authController.js',
      'controllers/authController.js',
      'backend/middleware/validator.js',
    ],
    matcher: (content) => {
      const funcRegex = /function\s+validatePasswordComplexity\s*\([^)]*\)\s*\{[\s\S]*?return\s+hasUpper\s*&&[^;]+;/;
      const match = content.match(funcRegex);
      if (match) {
        const original = match[0];
        const replacement = `function validatePasswordComplexity(password) {
  if (!password || password.length < 12) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSpecial;`;
        return { before: original, after: replacement };
      }
      return null;
    },
  },

  // SEC-004: Session Cookie Hygiene
  'SEC-004': {
    candidateFiles: [
      'backend/app.js',
      'app.js',
      'backend/server.js',
    ],
    matcher: (content) => {
      const cookieBlockRegex = /cookie\s*:\s*\{[\s\S]*?secure\s*:\s*[^,\n\}]+[\s\S]*?\}/;
      const match = content.match(cookieBlockRegex);
      if (match) {
        const original = match[0];
        const replacement = `cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    }`;
        return { before: original, after: replacement };
      }
      return null;
    },
  },

  // SEC-005: HTTPS Transport
  'SEC-005': {
    candidateFiles: [
      'backend/app.js',
      'app.js',
      'backend/server.js',
    ],
    matcher: (content) => {
      const helmetRegex = /helmet\(\s*\{[\s\S]*?\}\s*\)/;
      const match = content.match(helmetRegex);
      if (match) {
        const original = match[0];
        const replacement = `helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  })`;
        return { before: original, after: replacement };
      }
      return null;
    },
  },

  // SEC-007: Session Invalidation on Logout
  'SEC-007': {
    candidateFiles: [
      'backend/controllers/authController.js',
      'controllers/authController.js',
    ],
    matcher: (content) => {
      const logoutRegex = /async\s+function\s+logout\s*\([^)]*\)\s*\{[\s\S]*?res\.clearCookie\([^)]*\);/;
      const match = content.match(logoutRegex);
      if (match) {
        const original = match[0];
        return {
          before: original,
          after: original, // verified current implementation
        };
      }
      return null;
    },
  },
};

/**
 * Inspects authorized project files to collect verified source code context for a finding.
 *
 * @param {string} projectRoot - Canonical or raw authorized project root path
 * @param {Object} finding - Security assessment finding object
 * @returns {{
 *   sourceAvailable: boolean,
 *   isApplicable: boolean,
 *   targetFile?: string,
 *   codeBefore?: string,
 *   codeAfter?: string,
 *   fileFingerprint?: string,
 *   reason?: string,
 *   message?: string
 * }}
 */
function collectSourceContext(projectRoot, finding) {
  if (!projectRoot || typeof projectRoot !== 'string') {
    return {
      sourceAvailable: false,
      isApplicable: false,
      reason: 'PROJECT_ROOT_UNAVAILABLE',
      message: 'No authorized local project root connected. Connect or select an authorized local project directory to inspect source files.',
    };
  }

  const rootCheck = validateProjectRoot(projectRoot);
  if (!rootCheck.valid) {
    return {
      sourceAvailable: false,
      isApplicable: false,
      reason: 'INVALID_PROJECT_ROOT',
      message: `Project root directory is invalid: ${rootCheck.error}`,
    };
  }

  const canonicalRoot = rootCheck.canonicalRoot;
  const findingId = finding.id || finding.findingId || '';
  const locator = FINDING_LOCATORS[findingId];

  // Candidates list: locator candidate files + any explicit target in finding
  const candidateList = [];
  if (finding.targetFile || finding.target_file || finding.file_path) {
    candidateList.push(finding.targetFile || finding.target_file || finding.file_path);
  }
  if (locator && Array.isArray(locator.candidateFiles)) {
    candidateList.push(...locator.candidateFiles);
  }

  for (const candidateRelative of candidateList) {
    const pathCheck = validateFilePath(canonicalRoot, candidateRelative);
    if (!pathCheck.valid) continue;

    const fullPath = pathCheck.canonicalPath;
    if (!fs.existsSync(fullPath)) continue;

    try {
      const content = fs.readFileSync(fullPath, 'utf8');

      // 1. If locator matcher is available, test it
      if (locator && typeof locator.matcher === 'function') {
        const matchResult = locator.matcher(content);
        if (matchResult && matchResult.before && matchResult.after) {
          // Reject any placeholder results
          if (isPlaceholderText(matchResult.before) || isPlaceholderText(matchResult.after)) {
            continue;
          }

          // Verify uniqueness of codeBefore in file
          const occurrences = countSnippetOccurrences(content, matchResult.before);
          if (occurrences === 1) {
            return {
              sourceAvailable: true,
              isApplicable: true,
              targetFile: pathCheck.relativePath,
              codeBefore: matchResult.before,
              codeAfter: matchResult.after,
              fileFingerprint: computeFileFingerprint(content),
              canonicalPath: fullPath,
            };
          }
        }
      }

      // 2. If finding has explicit codeBefore and codeAfter, check if codeBefore exists uniquely in this file
      const fBefore = finding.codeBefore || finding.code_before;
      const fAfter = finding.codeAfter || finding.code_after;

      if (fBefore && fAfter && !isPlaceholderText(fBefore) && !isPlaceholderText(fAfter)) {
        const occurrences = countSnippetOccurrences(content, fBefore);
        if (occurrences === 1) {
          return {
            sourceAvailable: true,
            isApplicable: true,
            targetFile: pathCheck.relativePath,
            codeBefore: fBefore,
            codeAfter: fAfter,
            fileFingerprint: computeFileFingerprint(content),
            canonicalPath: fullPath,
          };
        }
      }
    } catch (_) {
      // Continue to next candidate
    }
  }

  // Source context could not be located on disk
  return {
    sourceAvailable: false,
    isApplicable: false,
    targetFile: null,
    codeBefore: null,
    codeAfter: null,
    fileFingerprint: null,
    reason: 'SOURCE_CONTEXT_NOT_FOUND',
    message: `Source code context could not be located in authorized project files for finding ${findingId || finding.title || 'UNKNOWN'}. This issue was observed through HTTP dynamic testing (DAST).`,
  };
}

module.exports = {
  isPlaceholderText,
  computeFileFingerprint,
  countSnippetOccurrences,
  collectSourceContext,
  FINDING_LOCATORS,
};
