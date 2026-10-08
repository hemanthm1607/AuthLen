#!/usr/bin/env node
/**
 * AuthLens Companion CLI
 * =========================================================================
 * Secure, User-Controlled AI Code Remediation Agent for Local Repositories.
 *
 * This companion CLI bridges the deployed AuthLens platform with authorized
 * local development projects. It prevents serverless cloud backends from needing
 * arbitrary filesystem access by allowing the developer to safely review,
 * approve, apply, verify, and roll back AI-generated code patches locally.
 *
 * Security Guarantees:
 * 1. Explicit approval required before patch application.
 * 2. Strict path confinement: Prevents path traversal and symlink escapes.
 * 3. Sensitive file protection: Blocks .env, keys, git internals, node_modules.
 * 4. Preflight file validation: Detects stale or modified target files.
 * 5. Automatic backup checkpoints created prior to any file alteration.
 * 6. Allowlisted verification commands only: No arbitrary AI shell execution.
 * 7. One-click instant atomic rollback.
 *
 * Usage:
 *   node cli/authlens-cli.js --help
 *   node cli/authlens-cli.js status
 *   node cli/authlens-cli.js list
 *   node cli/authlens-cli.js review <remediation-id>
 *   node cli/authlens-cli.js approve <remediation-id>
 *   node cli/authlens-cli.js apply <remediation-id>
 *   node cli/authlens-cli.js verify <remediation-id>
 *   node cli/authlens-cli.js rollback <remediation-id>
 */

const path = require('path');
const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');

// Import core remediation engine for standalone or companion execution
const {
  validateProjectPath,
  resolveProjectRoot,
  patchFile,
  restoreBackup,
  runVerificationCommand,
  ALLOWLISTED_COMMAND_PATTERNS
} = require('../backend/remediation-engine');

const API_BASE = process.env.AUTHLENS_API_URL || 'http://localhost:4000/api';
const PROJECT_ROOT = process.env.AUTHLENS_PROJECT_ROOT || process.cwd();

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
};

function banner() {
  console.log(`
${colors.blue}${colors.bold}========================================================================${colors.reset}
${colors.cyan}${colors.bold}   AuthLens Companion CLI — AI-Assisted Security Remediation${colors.reset}
${colors.dim}   Target Root: ${PROJECT_ROOT}${colors.reset}
${colors.dim}   AuthLens API: ${API_BASE}${colors.reset}
${colors.blue}${colors.bold}========================================================================${colors.reset}
`);
}

function printUsage() {
  banner();
  console.log(`${colors.bold}COMMANDS:${colors.reset}
  ${colors.cyan}status${colors.reset}                   Check project root security boundaries and environment.
  ${colors.cyan}list${colors.reset}                     List all remediations and their approval/verification statuses.
  ${colors.cyan}review <id>${colors.reset}              Review proposed patch diff, rationale, and target files for remediation <id>.
  ${colors.cyan}approve <id>${colors.reset}             Explicitly approve the proposed patch in AuthLens.
  ${colors.cyan}apply <id>${colors.reset}               Apply approved patch to local source with automatic backup.
  ${colors.cyan}verify <id>${colors.reset}              Run allowlisted automated tests to verify security fix.
  ${colors.cyan}rollback <id>${colors.reset}            Rollback applied patch using its backup checkpoint.
  ${colors.cyan}help${colors.reset}                     Show this help message.

${colors.bold}OPTIONS:${colors.reset}
  --api <url>              Override AuthLens API base URL (env: AUTHLENS_API_URL)
  --root <dir>             Override target project directory (env: AUTHLENS_PROJECT_ROOT)
  --cookie <sessionCookie> Provide session cookie for authenticated API calls
`);
}

/**
 * Helper to make HTTP/HTTPS requests to AuthLens API
 */
function apiRequest(method, endpoint, body = null, sessionCookie = null) {
  return new Promise((resolve, reject) => {
    const fullUrl = new URL(endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`);
    const isHttps = fullUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'AuthLens-Companion-CLI/1.0',
    };

    if (sessionCookie) {
      headers['Cookie'] = sessionCookie;
    }

    const options = {
      hostname: fullUrl.hostname,
      port: fullUrl.port || (isHttps ? 443 : 80),
      path: fullUrl.pathname + fullUrl.search,
      method: method.toUpperCase(),
      headers,
      timeout: 10000,
    };

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (_) {
          json = { raw: data };
        }
        resolve({ status: res.statusCode, data: json });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('API request timed out after 10s'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Command: status
 */
async function handleStatus(projectRoot) {
  banner();
  console.log(`${colors.bold}Checking Project Root & Security Boundaries...${colors.reset}\n`);

  const resolved = resolveProjectRoot(projectRoot);
  console.log(`  Project Directory: ${colors.green}${resolved}${colors.reset}`);

  try {
    const stats = fs.statSync(resolved);
    console.log(`  Directory Valid:   ${colors.green}YES (Directory exists)${colors.reset}`);
  } catch (err) {
    console.log(`  Directory Valid:   ${colors.red}NO (${err.message})${colors.reset}`);
  }

  // Check backup directory
  const backupDir = path.join(resolved, '.authlens-backups');
  const backupExists = fs.existsSync(backupDir);
  console.log(`  Backup Directory:  ${backupExists ? colors.green + backupDir + ' (Active)' : colors.yellow + 'Not yet created (will initialize on first patch)'}${colors.reset}`);

  // Test API reachability
  console.log(`\n${colors.bold}Checking AuthLens API Connection...${colors.reset}`);
  try {
    const health = await apiRequest('GET', '/health');
    console.log(`  API Health:        ${health.status === 200 ? colors.green + 'ONLINE (HTTP 200)' : colors.yellow + 'Response ' + health.status}${colors.reset}`);
  } catch (err) {
    console.log(`  API Health:        ${colors.yellow}UNREACHABLE (${err.message}) — Local direct file operations still supported.${colors.reset}`);
  }

  console.log(`\n${colors.bold}Allowed Verification Patterns:${colors.reset}`);
  ALLOWLISTED_COMMAND_PATTERNS.forEach(pat => {
    console.log(`  - ${colors.dim}${pat}${colors.reset}`);
  });
}

/**
 * Command: list
 */
async function handleList(cookie) {
  banner();
  console.log(`${colors.bold}Fetching Remediations from AuthLens...${colors.reset}\n`);

  try {
    const res = await apiRequest('GET', '/remediations', null, cookie);
    if (res.status === 401) {
      console.log(`${colors.yellow}Authentication required. Please login to AuthLens or pass --cookie "connect.sid=..."${colors.reset}`);
      return;
    }
    if (!res.data.remediations || res.data.remediations.length === 0) {
      console.log(`${colors.dim}No remediations found. Run an assessment in the AuthLens dashboard to generate findings.${colors.reset}`);
      return;
    }

    console.log(`${'ID'.padEnd(6)} | ${'STATUS'.padEnd(20)} | ${'FILE PATH'.padEnd(35)} | ${'VULNERABILITY'}`);
    console.log('-'.repeat(90));

    res.data.remediations.forEach(r => {
      let statusColor = colors.yellow;
      if (r.status === 'VERIFIED') statusColor = colors.green;
      if (r.status === 'APPLIED') statusColor = colors.cyan;
      if (r.status === 'REJECTED') statusColor = colors.red;
      if (r.status === 'ROLLED_BACK') statusColor = colors.dim;

      console.log(
        `${String(r.id).padEnd(6)} | ` +
        `${statusColor}${r.status.padEnd(20)}${colors.reset} | ` +
        `${(r.file_path || 'N/A').slice(0, 34).padEnd(35)} | ` +
        `${r.vulnerability_title || 'Finding #' + r.finding_id}`
      );
    });
  } catch (err) {
    console.log(`${colors.red}Error fetching remediations: ${err.message}${colors.reset}`);
  }
}

/**
 * Command: review <id>
 */
async function handleReview(id, cookie) {
  banner();
  if (!id) {
    console.log(`${colors.red}Error: Remediation ID required. Example: authlens review 1${colors.reset}`);
    return;
  }

  try {
    const res = await apiRequest('GET', `/remediations/${id}`, null, cookie);
    if (res.status === 404) {
      console.log(`${colors.red}Remediation #${id} not found.${colors.reset}`);
      return;
    }
    const r = res.data.remediation;

    console.log(`${colors.bold}Remediation #${r.id} Review:${colors.reset}`);
    console.log(`  Vulnerability:  ${colors.bold}${r.vulnerability_title || 'N/A'}${colors.reset} [${r.severity || 'UNKNOWN'}]`);
    console.log(`  Status:         ${colors.cyan}${r.status}${colors.reset}`);
    console.log(`  Target File:    ${colors.bold}${r.file_path}${colors.reset}`);
    console.log(`  Rationale:      ${r.technical_rationale || 'N/A'}`);
    console.log(`  Side Effects:   ${colors.yellow}${r.side_effects || 'None documented'}${colors.reset}`);
    console.log(`  Verify Command: ${colors.dim}${r.verification_command || 'npm test'}${colors.reset}`);

    console.log(`\n${colors.bold}--- ORIGINAL CODE CONTEXT (Lines to replace) ---${colors.reset}`);
    console.log(colors.red + (r.code_before || '') + colors.reset);

    console.log(`\n${colors.bold}+++ PROPOSED CODE CHANGES (Replacement) +++${colors.reset}`);
    console.log(colors.green + (r.code_after || '') + colors.reset);

    console.log(`\n${colors.bold}Actions Available:${colors.reset}`);
    if (r.status === 'PATCH_GENERATED' || r.status === 'AWAITING_APPROVAL') {
      console.log(`  Run: ${colors.cyan}node cli/authlens-cli.js approve ${r.id}${colors.reset} to approve this patch.`);
    } else if (r.status === 'APPROVED') {
      console.log(`  Run: ${colors.cyan}node cli/authlens-cli.js apply ${r.id}${colors.reset} to apply to your local repository.`);
    } else if (r.status === 'APPLIED' || r.status === 'VERIFICATION_FAILED') {
      console.log(`  Run: ${colors.cyan}node cli/authlens-cli.js verify ${r.id}${colors.reset} to run automated test verification.`);
      console.log(`  Run: ${colors.yellow}node cli/authlens-cli.js rollback ${r.id}${colors.reset} to restore original file.`);
    }
  } catch (err) {
    console.log(`${colors.red}Error fetching remediation: ${err.message}${colors.reset}`);
  }
}

/**
 * Command: approve <id>
 */
async function handleApprove(id, cookie) {
  banner();
  if (!id) {
    console.log(`${colors.red}Error: Remediation ID required.${colors.reset}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(`Are you sure you want to approve proposed patch #${id}? (y/N): `, async (answer) => {
    rl.close();
    if (answer.trim().toLowerCase() !== 'y') {
      console.log(`${colors.yellow}Approval cancelled.${colors.reset}`);
      return;
    }

    try {
      const res = await apiRequest('POST', `/remediations/${id}/approve`, {}, cookie);
      if (res.status === 200) {
        console.log(`${colors.green}${colors.bold}Success: Remediation #${id} approved.${colors.reset}`);
        console.log(`You may now apply the patch locally using: ${colors.cyan}node cli/authlens-cli.js apply ${id}${colors.reset}`);
      } else {
        console.log(`${colors.red}Failed to approve: ${res.data.error || 'Server error'}${colors.reset}`);
      }
    } catch (err) {
      console.log(`${colors.red}Error communicating with AuthLens: ${err.message}${colors.reset}`);
    }
  });
}

/**
 * Command: apply <id>
 */
async function handleApply(id, projectRoot, cookie) {
  banner();
  if (!id) {
    console.log(`${colors.red}Error: Remediation ID required.${colors.reset}`);
    return;
  }

  console.log(`${colors.bold}Fetching approved patch #${id}...${colors.reset}`);
  try {
    const fetchRes = await apiRequest('GET', `/remediations/${id}`, null, cookie);
    if (fetchRes.status !== 200) {
      console.log(`${colors.red}Failed to fetch remediation: ${fetchRes.data.error || fetchRes.status}${colors.reset}`);
      return;
    }

    const r = fetchRes.data.remediation;
    if (r.status !== 'APPROVED') {
      console.log(`${colors.red}Security Error: Remediation #${id} is in status '${r.status}', not 'APPROVED'.${colors.reset}`);
      console.log(`Explicit approval is mandatory before any source code modification.`);
      return;
    }

    console.log(`Target File: ${colors.cyan}${r.file_path}${colors.reset}`);
    console.log(`Executing atomic patch with pre-flight check and backup...`);

    // Execute atomic patch using local engine
    const patchResult = patchFile(projectRoot, r.file_path, r.code_before, r.code_after, r.id);

    console.log(`${colors.green}${colors.bold}Patch Applied Successfully!${colors.reset}`);
    console.log(`  File Updated:     ${patchResult.targetPath}`);
    console.log(`  Backup ID:        ${patchResult.backupId}`);
    console.log(`  Bytes Written:    ${patchResult.bytesWritten}`);

    // Update status in AuthLens API
    try {
      await apiRequest('POST', `/remediations/${id}/apply`, { backupId: patchResult.backupId }, cookie);
      console.log(`  AuthLens Ledger:  ${colors.green}Updated to APPLIED${colors.reset}`);
    } catch (_) {
      console.log(`  AuthLens Ledger:  ${colors.yellow}Offline mode — local patch applied.${colors.reset}`);
    }

    console.log(`\nNext Step: Run automated verification using:`);
    console.log(`  ${colors.cyan}node cli/authlens-cli.js verify ${id}${colors.reset}`);

  } catch (err) {
    console.log(`${colors.red}${colors.bold}Patch Application Rejected: ${err.message}${colors.reset}`);
  }
}

/**
 * Command: verify <id>
 */
async function handleVerify(id, projectRoot, cookie) {
  banner();
  if (!id) {
    console.log(`${colors.red}Error: Remediation ID required.${colors.reset}`);
    return;
  }

  try {
    const fetchRes = await apiRequest('GET', `/remediations/${id}`, null, cookie);
    const r = fetchRes.status === 200 ? fetchRes.data.remediation : null;
    const testCommand = (r && r.verification_command) ? r.verification_command : 'npm test';

    console.log(`${colors.bold}Running Allowlisted Automated Verification...${colors.reset}`);
    console.log(`Command: ${colors.cyan}${testCommand}${colors.reset}\n`);

    const result = await runVerificationCommand(testCommand, projectRoot, 30000);

    if (result.success) {
      console.log(`${colors.green}${colors.bold}Verification SUCCEEDED!${colors.reset}`);
      console.log(`Execution Time: ${result.durationMs}ms`);
      console.log(colors.dim + result.output + colors.reset);

      if (r) {
        await apiRequest('POST', `/remediations/${id}/verify`, { command: testCommand }, cookie);
        console.log(`\nAuthLens Status: ${colors.green}VERIFIED${colors.reset}`);
      }
    } else {
      console.log(`${colors.red}${colors.bold}Verification FAILED!${colors.reset}`);
      console.log(`Error: ${result.error}`);
      console.log(colors.dim + result.output + colors.reset);

      if (r) {
        await apiRequest('POST', `/remediations/${id}/verify`, { command: testCommand }, cookie);
        console.log(`\nAuthLens Status: ${colors.red}VERIFICATION_FAILED${colors.reset}`);
        console.log(`You can rollback changes using: ${colors.yellow}node cli/authlens-cli.js rollback ${id}${colors.reset}`);
      }
    }
  } catch (err) {
    console.log(`${colors.red}Verification error: ${err.message}${colors.reset}`);
  }
}

/**
 * Command: rollback <id>
 */
async function handleRollback(id, projectRoot, cookie) {
  banner();
  if (!id) {
    console.log(`${colors.red}Error: Remediation ID required.${colors.reset}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(`Are you sure you want to ROLL BACK remediation #${id} to its original state? (y/N): `, async (answer) => {
    rl.close();
    if (answer.trim().toLowerCase() !== 'y') {
      console.log(`${colors.yellow}Rollback cancelled.${colors.reset}`);
      return;
    }

    try {
      const result = restoreBackup(projectRoot, id);
      console.log(`${colors.green}${colors.bold}Rollback Complete!${colors.reset}`);
      console.log(`Restored: ${result.targetPath}`);
      console.log(`From Backup: ${result.restoredFrom}`);

      try {
        await apiRequest('POST', `/remediations/${id}/rollback`, {}, cookie);
        console.log(`AuthLens Status: ${colors.dim}ROLLED_BACK${colors.reset}`);
      } catch (_) {}
    } catch (err) {
      console.log(`${colors.red}Rollback failed: ${err.message}${colors.reset}`);
    }
  });
}

/**
 * Entrypoint & Argument Parsing
 */
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    printUsage();
    return;
  }

  let cookie = null;
  let customRoot = PROJECT_ROOT;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--cookie' && args[i + 1]) {
      cookie = args[i + 1];
    }
    if (args[i] === '--root' && args[i + 1]) {
      customRoot = args[i + 1];
    }
  }

  const command = args[0].toLowerCase();
  const targetId = args[1] && !args[1].startsWith('--') ? args[1] : null;

  switch (command) {
    case 'status':
      await handleStatus(customRoot);
      break;
    case 'list':
      await handleList(cookie);
      break;
    case 'review':
      await handleReview(targetId, cookie);
      break;
    case 'approve':
      await handleApprove(targetId, cookie);
      break;
    case 'apply':
      await handleApply(targetId, customRoot, cookie);
      break;
    case 'verify':
      await handleVerify(targetId, customRoot, cookie);
      break;
    case 'rollback':
      await handleRollback(targetId, customRoot, cookie);
      break;
    default:
      console.log(`${colors.red}Unknown command: '${command}'${colors.reset}`);
      printUsage();
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error(`Fatal CLI Error: ${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  main,
  handleStatus,
  handleApply,
  handleVerify,
  handleRollback
};
