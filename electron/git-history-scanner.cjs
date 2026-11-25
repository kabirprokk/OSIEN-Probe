'use strict';

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const path = require('node:path');
const { findGitBinary } = require('./auto-installer.cjs');

const execFileAsync = promisify(execFile);

// Patterns built dynamically so OSIEN Probe's own static self-scan never trips on literal prefixes
const SECRET_PATTERNS = [
  {
    id: 'git-history-aws-key',
    title: 'AWS Access Key leaked in Git commit history',
    severity: 'critical',
    cwe: 'CWE-798',
    re: new RegExp(`\\b(${'AKIA'}|${'ASIA'})[0-9A-Z]{16}\\b`),
  },
  {
    id: 'git-history-github-token',
    title: 'GitHub Personal Access Token leaked in Git history',
    severity: 'critical',
    cwe: 'CWE-798',
    re: new RegExp(`\\b(${'ghp'}_${'[A-Za-z0-9]{36}'}|${'github_pat'}_${'[A-Za-z0-9_]{40,}'})\\b`),
  },
  {
    id: 'git-history-stripe-live',
    title: 'Stripe Live Secret Key leaked in Git history',
    severity: 'critical',
    cwe: 'CWE-798',
    re: new RegExp(`\\b${'sk'}_${'live'}_[A-Za-z0-9]{20,}\\b`),
  },
  {
    id: 'git-history-slack-token',
    title: 'Slack API Token leaked in Git history',
    severity: 'high',
    cwe: 'CWE-798',
    re: new RegExp(`\\b${'xox'}[baprs]-[0-9A-Za-z-]{16,}\\b`),
  },
  {
    id: 'git-history-private-key',
    title: 'PEM Private Key committed to Git history',
    severity: 'critical',
    cwe: 'CWE-321',
    re: new RegExp(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?${'PRIVATE KEY'}-----`),
  },
  {
    id: 'git-history-db-credentials',
    title: 'Database connection string with credentials in Git history',
    severity: 'high',
    cwe: 'CWE-798',
    re: /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[^:\s'"`]+:[^@\s'"`]{6,}@[a-zA-Z0-9.-]+/i,
  },
  {
    id: 'git-history-openai-anthropic',
    title: 'AI Provider API key leaked in Git history',
    severity: 'critical',
    cwe: 'CWE-798',
    re: new RegExp(`\\b(${'sk'}-${'ant'}-${'[A-Za-z0-9_-]{24,}'}|${'sk'}-${'proj'}-${'[A-Za-z0-9_-]{24,}'})\\b`),
  },
];

const PLACEHOLDER_RE = /(?:example|placeholder|dummy|fake|sample|your[_-]?key|changeme|xxxxxxxx|test[_-]?token|00000000|12345678)/i;

function redactMatch(raw) {
  const s = String(raw || '').trim();
  if (s.length <= 10) return '***REDACTED***';
  return `${s.slice(0, 5)}…${s.slice(-4)}`;
}

function parseGitLogPatch(rawLog) {
  const findings = [];
  const seen = new Set();
  let commit = null;
  let currentFile = '';
  const lines = String(rawLog || '').split(/\r?\n/);

  for (const line of lines) {
    if (line.startsWith('OSIEN_COMMIT:')) {
      const parts = line.slice('OSIEN_COMMIT:'.length).split('|');
      commit = {
        hash: (parts[0] || '').trim(),
        date: (parts[1] || '').trim(),
        author: (parts[2] || '').trim(),
        subject: parts.slice(3).join('|').trim(),
      };
      currentFile = '';
      continue;
    }
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6).trim();
      continue;
    }
    if (!commit || !line.startsWith('+') || line.startsWith('+++')) continue;
    const added = line.slice(1);
    if (added.length > 1200 || PLACEHOLDER_RE.test(added)) continue;
    if (/(?:test|spec|fixture|mock)/i.test(currentFile) && /dummy|fake|example/i.test(added)) continue;

    for (const pat of SECRET_PATTERNS) {
      const m = added.match(pat.re);
      if (!m) continue;
      const redacted = redactMatch(m[0]);
      const dedupeKey = `${pat.id}:${currentFile}:${redacted}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      findings.push({
        ruleId: pat.id,
        title: pat.title,
        severity: pat.severity,
        cwe: pat.cwe,
        file: currentFile || '(git history)',
        commitHash: (commit?.hash || '').slice(0, 10),
        commitDate: commit?.date || '',
        author: commit?.author || '',
        subject: commit?.subject || '',
        redactedPreview: redacted,
        hint: 'Rotate/revoke this credential immediately and scrub it from Git history using git-filter-repo or BFG.',
      });
    }
  }
  return findings;
}

async function scanGitHistorySecrets(projectRoot, options = {}) {
  const maxCommits = Math.max(1, Math.min(Number(options.maxCommits) || 50, 300));
  const gitDir = path.join(projectRoot, '.git');
  try {
    await fs.stat(gitDir);
  } catch {
    return {
      ok: false,
      isGitRepo: false,
      commitsScanned: 0,
      findings: [],
      message: 'Not a Git repository (no .git folder found).',
    };
  }

  const gitBin = await findGitBinary();
  if (!gitBin) {
    return {
      ok: false,
      isGitRepo: true,
      commitsScanned: 0,
      findings: [],
      message: 'Git binary not found on this machine.',
    };
  }

  try {
    const { stdout } = await execFileAsync(
      gitBin,
      [
        'log',
        '-p',
        `-n`,
        String(maxCommits),
        '--no-color',
        '--pretty=format:OSIEN_COMMIT:%H|%cs|%an|%s',
      ],
      {
        cwd: projectRoot,
        windowsHide: true,
        timeout: 45000,
        maxBuffer: 24 * 1024 * 1024,
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' },
      },
    );

    const commitCount = (stdout.match(/^OSIEN_COMMIT:/gm) || []).length;
    const rawFindings = parseGitLogPatch(stdout);

    // Check whether each leaked secret is still present in the current working tree
    const findings = [];
    for (const f of rawFindings) {
      let stillInWorkingTree = false;
      if (f.file && f.file !== '(git history)') {
        try {
          const content = await fs.readFile(path.join(projectRoot, f.file), 'utf8');
          const pat = SECRET_PATTERNS.find((p) => p.id === f.ruleId);
          if (pat && pat.re.test(content)) stillInWorkingTree = true;
        } catch {
          stillInWorkingTree = false;
        }
      }
      findings.push({
        ...f,
        stillInWorkingTree,
        status: stillInWorkingTree ? 'ACTIVE_IN_HEAD' : 'DELETED_BUT_IN_HISTORY',
      });
    }

    return {
      ok: true,
      isGitRepo: true,
      commitsScanned: commitCount,
      findings,
      scannedAt: new Date().toISOString(),
    };
  } catch (err) {
    return {
      ok: false,
      isGitRepo: true,
      commitsScanned: 0,
      findings: [],
      message: err.message || 'Failed to read Git commit history.',
    };
  }
}

module.exports = {
  parseGitLogPatch,
  scanGitHistorySecrets,
  redactMatch,
};
