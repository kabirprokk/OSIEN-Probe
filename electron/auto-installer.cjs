'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const execFileAsync = promisify(execFile);

const GIT_ENV = () => ({ ...process.env, GIT_CONFIG_NOSYSTEM: '1' });

function candidateGitPaths() {
  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || '';
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    return [
      'git',
      path.join(programFiles, 'Git', 'cmd', 'git.exe'),
      path.join(programFiles, 'Git', 'bin', 'git.exe'),
      path.join(programFilesX86, 'Git', 'cmd', 'git.exe'),
      localAppData ? path.join(localAppData, 'Programs', 'Git', 'cmd', 'git.exe') : '',
    ].filter(Boolean);
  }
  return ['git', '/usr/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git'];
}

async function findGitBinary() {
  for (const bin of candidateGitPaths()) {
    try {
      await execFileAsync(bin, ['--version'], { windowsHide: true, timeout: 4000, env: GIT_ENV() });
      return bin;
    } catch (err) {
      void err;
    }
  }
  return null;
}

async function ensureGitBinary() {
  const existing = await findGitBinary();
  if (existing) return existing;

  if (process.platform === 'win32') {
    try {
      await execFileAsync(
        'winget',
        ['install', '--id', 'Git.Git', '-e', '--silent', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements'],
        { timeout: 180000, windowsHide: true },
      );
    } catch (err) {
      void err;
    }
    const installed = await findGitBinary();
    if (installed) return installed;
  }
  return null;
}

async function downloadRepoArchiveFallback(repoUrl, targetDir) {
  const cleanUrl = String(repoUrl || '').trim().replace(/\.git$/i, '').replace(/\/+$/, '');
  const ghMatch = cleanUrl.match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)$/i);
  const glMatch = cleanUrl.match(/^https:\/\/gitlab\.com\/([\w.-]+)\/([\w.-]+)$/i);

  let zipUrl = '';
  if (ghMatch) {
    zipUrl = `https://api.github.com/repos/${ghMatch[1]}/${ghMatch[2]}/zipball`;
  } else if (glMatch) {
    zipUrl = `https://gitlab.com/${glMatch[1]}/${glMatch[2]}/-/archive/main/${glMatch[2]}-main.zip`;
  } else {
    throw new Error('Could not resolve archive download URL for this repository.');
  }

  const res = await fetch(zipUrl, {
    headers: { 'User-Agent': 'OSIEN-Probe-AutoClone/1.0', Accept: 'application/vnd.github+json' },
    redirect: 'follow',
  });
  if (!res.ok) {
    throw new Error(`Repository archive download failed (HTTP ${res.status}). Check that the repository is public.`);
  }

  const zipBytes = Buffer.from(await res.arrayBuffer());
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-zip-'));
  const zipPath = path.join(tmpDir, 'repo.zip');
  const extractDir = path.join(tmpDir, 'extracted');
  await fs.writeFile(zipPath, zipBytes);
  await fs.mkdir(extractDir, { recursive: true });

  try {
    if (process.platform === 'win32') {
      await execFileAsync(
        'powershell',
        ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${zipPath.replace(/'/g, "''")}' -DestinationPath '${extractDir.replace(/'/g, "''")}' -Force`],
        { windowsHide: true, timeout: 120000 },
      );
    } else {
      await execFileAsync('unzip', ['-q', zipPath, '-d', extractDir], { timeout: 120000 });
    }

    const entries = await fs.readdir(extractDir, { withFileTypes: true });
    const innerDir = entries.find((e) => e.isDirectory());
    const sourceRoot = innerDir ? path.join(extractDir, innerDir.name) : extractDir;
    await fs.mkdir(path.dirname(targetDir), { recursive: true });
    await fs.cp(sourceRoot, targetDir, { recursive: true });
    return { method: 'zipball-fallback', targetDir };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch((err) => { void err; });
  }
}

async function cloneRepositoryAuto(repoUrl, targetDir) {
  const gitBin = await ensureGitBinary();
  if (gitBin) {
    try {
      await fs.mkdir(path.dirname(targetDir), { recursive: true });
      await execFileAsync(gitBin, ['clone', '--depth', '1', repoUrl, targetDir], {
        timeout: 120000,
        windowsHide: true,
        env: GIT_ENV(),
      });
      return { method: 'git', gitBin, targetDir };
    } catch (err) {
      void err;
      await fs.rm(targetDir, { recursive: true, force: true }).catch((e) => { void e; });
    }
  }
  return downloadRepoArchiveFallback(repoUrl, targetDir);
}

async function findOllamaBinary() {
  const localAppData = process.env.LOCALAPPDATA || '';
  const candidates = process.platform === 'win32'
    ? ['ollama', localAppData ? path.join(localAppData, 'Programs', 'Ollama', 'ollama.exe') : ''].filter(Boolean)
    : ['ollama', '/usr/local/bin/ollama', '/opt/homebrew/bin/ollama'];
  for (const bin of candidates) {
    try {
      await execFileAsync(bin, ['--version'], { windowsHide: true, timeout: 3000 });
      return bin;
    } catch (err) {
      void err;
    }
  }
  return null;
}

async function ensureOllamaBinary() {
  const existing = await findOllamaBinary();
  if (existing) return existing;
  if (process.platform === 'win32') {
    try {
      await execFileAsync(
        'winget',
        ['install', '--id', 'Ollama.Ollama', '-e', '--silent', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements'],
        { timeout: 180000, windowsHide: true },
      );
    } catch (err) {
      void err;
    }
    return findOllamaBinary();
  }
  return null;
}

module.exports = {
  findGitBinary,
  ensureGitBinary,
  downloadRepoArchiveFallback,
  cloneRepositoryAuto,
  findOllamaBinary,
  ensureOllamaBinary,
};
