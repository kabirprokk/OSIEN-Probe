'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const HOOK_MARKER = '# OSIEN-PROBE-MANAGED-HOOK';

function resolveCliPath() {
  return path.resolve(__dirname, '..', 'bin', 'osien-probe.cjs');
}

async function getPreCommitHookStatus(projectRoot) {
  const gitDir = path.join(projectRoot, '.git');
  try {
    const stat = await fs.stat(gitDir);
    if (!stat.isDirectory()) return { isGitRepo: false, installed: false };
  } catch {
    return { isGitRepo: false, installed: false };
  }
  const hookPath = path.join(gitDir, 'hooks', 'pre-commit');
  try {
    const content = await fs.readFile(hookPath, 'utf8');
    return {
      isGitRepo: true,
      installed: content.includes(HOOK_MARKER),
      hasOtherHook: !content.includes(HOOK_MARKER) && content.trim().length > 0,
      hookPath,
    };
  } catch {
    return { isGitRepo: true, installed: false, hasOtherHook: false, hookPath };
  }
}

async function installPreCommitHook(projectRoot, options = {}) {
  const failOn = options.failOn || 'critical';
  const status = await getPreCommitHookStatus(projectRoot);
  if (!status.isGitRepo) {
    throw new Error('Cannot install pre-commit hook: target folder is not a Git repository.');
  }
  const hooksDir = path.join(projectRoot, '.git', 'hooks');
  await fs.mkdir(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');
  const cliPath = resolveCliPath().replace(/\\/g, '/');

  let existing = '';
  try {
    existing = await fs.readFile(hookPath, 'utf8');
  } catch {
    existing = '';
  }

  const block = [
    HOOK_MARKER,
    `node "${cliPath}" scan . --changed --bugs-only --fail-on ${failOn} --quiet`,
    'OSIEN_EXIT=$?',
    'if [ "$OSIEN_EXIT" -ne 0 ]; then',
    '  echo "[OSIEN Probe] Commit blocked: critical security/bug findings detected in changed files."',
    '  echo "[OSIEN Probe] Fix them or run with --no-verify to bypass."',
    '  exit "$OSIEN_EXIT"',
    'fi',
    '# END-OSIEN-PROBE-MANAGED-HOOK',
  ].join('\n');

  let nextContent;
  if (existing.includes(HOOK_MARKER)) {
    nextContent = existing.replace(
      /# OSIEN-PROBE-MANAGED-HOOK[\s\S]*?# END-OSIEN-PROBE-MANAGED-HOOK/,
      block,
    );
  } else if (existing.trim().length > 0) {
    nextContent = `${existing.trimEnd()}\n\n${block}\n`;
  } else {
    nextContent = `#!/bin/sh\n${block}\n`;
  }

  await fs.writeFile(hookPath, nextContent, { encoding: 'utf8', mode: 0o755 });
  return { installed: true, hookPath, failOn };
}

async function removePreCommitHook(projectRoot) {
  const status = await getPreCommitHookStatus(projectRoot);
  if (!status.isGitRepo || !status.installed) {
    return { removed: false, hookPath: status.hookPath || null };
  }
  const content = await fs.readFile(status.hookPath, 'utf8');
  const cleaned = content
    .replace(/\n*# OSIEN-PROBE-MANAGED-HOOK[\s\S]*?# END-OSIEN-PROBE-MANAGED-HOOK\n*/g, '\n')
    .trim();

  if (!cleaned || cleaned === '#!/bin/sh' || cleaned === '#!/usr/bin/env bash') {
    await fs.unlink(status.hookPath);
  } else {
    await fs.writeFile(status.hookPath, `${cleaned}\n`, { encoding: 'utf8', mode: 0o755 });
  }
  return { removed: true, hookPath: status.hookPath };
}

module.exports = {
  HOOK_MARKER,
  getPreCommitHookStatus,
  installPreCommitHook,
  removePreCommitHook,
};
