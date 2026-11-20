'use strict';

const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const {
  getCodexAuthStatus,
  getAvailableCodexModels,
  connectCodexBrowser,
  disconnectCodex,
  runCodexExec,
} = require('./codex-auth.cjs');

const OPENAI_CHAT_ENDPOINT = 'https://api.openai.com/v1/chat/completions';
const ANTHROPIC_MESSAGES_ENDPOINT = 'https://api.anthropic.com/v1/messages';
const OPENCODE_CHAT_ENDPOINT = 'https://opencode.ai/zen/v1/chat/completions';

const CLAUDE_MODELS = ['claude-sonnet-4-5', 'claude-opus-4-1', 'claude-haiku-4-5', 'claude-3-7-sonnet-latest'];
const OPENCODE_MODELS = ['opencode/big-pickle', 'anthropic/claude-sonnet-4-5', 'openai/gpt-5.2-codex', 'google/gemini-2.5-pro'];
const PI_MODELS = ['claude-sonnet-4-5', 'gpt-5.2-codex', 'gemini-2.5-pro', 'o4-mini'];

const PROVIDER_META = {
  'cloud-codex': {
    id: 'cloud-codex',
    label: 'Cloud Codex (OpenAI)',
    shortLabel: 'Codex',
    cliName: 'codex',
    authHint: 'ChatGPT OAuth (~/.codex/auth.json)',
    connectLabel: 'Connect Codex (ChatGPT)',
    apiKeyPlaceholder: 'sk-...',
  },
  'cloud-claude': {
    id: 'cloud-claude',
    label: 'Cloud Claude (Anthropic)',
    shortLabel: 'Claude',
    cliName: 'claude',
    npxPkg: '@anthropic-ai/claude-code',
    authHint: 'Claude Code CLI (~/.claude/.credentials.json)',
    connectLabel: 'Connect Claude Code',
    apiKeyPlaceholder: 'sk-ant-...',
  },
  'cloud-opencode': {
    id: 'cloud-opencode',
    label: 'Cloud OpenCode',
    shortLabel: 'OpenCode',
    cliName: 'opencode',
    npxPkg: 'opencode-ai',
    authHint: 'OpenCode CLI (~/.local/share/opencode/auth.json)',
    connectLabel: 'Connect OpenCode',
    apiKeyPlaceholder: 'oc-...',
  },
  'cloud-pi': {
    id: 'cloud-pi',
    label: 'Cloud Pi Agent',
    shortLabel: 'Pi',
    cliName: 'pi',
    npxPkg: '@mariozechner/pi-coding-agent',
    authHint: 'Pi Coding Agent (~/.pi/agent/auth.json)',
    connectLabel: 'Connect Pi Agent',
    apiKeyPlaceholder: 'sk-...',
  },
};

function isCloudProvider(provider) {
  return Boolean(provider && PROVIDER_META[provider]);
}

function getProviderMeta(provider) {
  return PROVIDER_META[provider] || PROVIDER_META['cloud-codex'];
}

function resolveCliBinary(cmd) {
  const pathEnv = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? ['.cmd', '.exe', '.bat', ''] : [''];
  for (const dir of pathEnv) {
    for (const ext of exts) {
      const candidate = path.join(dir, `${cmd}${ext}`);
      if (fsSync.existsSync(candidate)) return candidate;
    }
  }
  const extraDirs = process.platform === 'win32'
    ? [
        process.env.APPDATA ? path.join(process.env.APPDATA, 'npm') : null,
        path.join(os.homedir(), '.local', 'bin'),
      ].filter(Boolean)
    : [
        path.join(os.homedir(), '.local', 'bin'),
        path.join(os.homedir(), '.npm-global', 'bin'),
        '/usr/local/bin',
      ];
  for (const dir of extraDirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, `${cmd}${ext}`);
      if (fsSync.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

async function fileHasJsonAuth(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const data = JSON.parse(raw);
    return Boolean(
      data && typeof data === 'object'
      && (Object.keys(data).length > 0),
    );
  } catch {
    return false;
  }
}

async function getProviderAuthStatus(provider) {
  if (provider === 'cloud-codex') return getCodexAuthStatus();

  const home = os.homedir();
  if (provider === 'cloud-claude') {
    const creds = path.join(home, '.claude', '.credentials.json');
    const cfg = path.join(home, '.claude.json');
    const hasCreds = await fileHasJsonAuth(creds);
    let hasOauthCfg = false;
    const rawCfg = await fs.readFile(cfg, 'utf8').catch(() => '');
    if (rawCfg) {
      try {
        const parsed = JSON.parse(rawCfg);
        hasOauthCfg = Boolean(parsed?.oauthAccount || parsed?.claudeAiOauth);
      } catch {
        hasOauthCfg = false;
      }
    }
    const connected = hasCreds || hasOauthCfg || Boolean(process.env.ANTHROPIC_API_KEY);
    return { connected, authPath: creds, cliInstalled: Boolean(resolveCliBinary('claude')) };
  }

  if (provider === 'cloud-opencode') {
    const candidates = [
      path.join(home, '.local', 'share', 'opencode', 'auth.json'),
      process.env.APPDATA ? path.join(process.env.APPDATA, 'opencode', 'auth.json') : null,
      path.join(home, '.config', 'opencode', 'auth.json'),
    ].filter(Boolean);
    for (const p of candidates) {
      if (await fileHasJsonAuth(p)) {
        return { connected: true, authPath: p, cliInstalled: Boolean(resolveCliBinary('opencode')) };
      }
    }
    return {
      connected: Boolean(process.env.OPENCODE_API_KEY),
      authPath: candidates[0],
      cliInstalled: Boolean(resolveCliBinary('opencode')),
    };
  }

  if (provider === 'cloud-pi') {
    const candidates = [
      path.join(home, '.pi', 'agent', 'auth.json'),
      path.join(home, '.pi', 'auth.json'),
    ];
    for (const p of candidates) {
      if (await fileHasJsonAuth(p)) {
        return { connected: true, authPath: p, cliInstalled: Boolean(resolveCliBinary('pi')) };
      }
    }
    return {
      connected: Boolean(process.env.PI_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY),
      authPath: candidates[0],
      cliInstalled: Boolean(resolveCliBinary('pi')),
    };
  }

  return { connected: false, authPath: '' };
}

async function getAvailableProviderModels(provider) {
  if (provider === 'cloud-codex') return getAvailableCodexModels();
  if (provider === 'cloud-claude') return CLAUDE_MODELS;
  if (provider === 'cloud-opencode') return OPENCODE_MODELS;
  if (provider === 'cloud-pi') return PI_MODELS;
  return [];
}

function openBrowserUrl(url) {
  try {
    const { shell } = require('electron');
    if (shell?.openExternal) {
      void shell.openExternal(url);
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

function spawnProviderCli(provider, args, cwd) {
  const meta = getProviderMeta(provider);
  const bin = resolveCliBinary(meta.cliName);
  const childEnv = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
  if (bin) {
    const isWinCmd = process.platform === 'win32' && /\.(cmd|bat)$/i.test(bin);
    return spawn(bin, args, {
      cwd: cwd || os.homedir(),
      windowsHide: !isWinCmd,
      shell: isWinCmd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });
  }
  if (meta.npxPkg) {
    const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    return spawn(npxBin, ['--yes', meta.npxPkg, ...args], {
      cwd: cwd || os.homedir(),
      windowsHide: true,
      shell: process.platform === 'win32',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });
  }
  throw new Error(`${meta.shortLabel} CLI ("${meta.cliName}") was not found on PATH.`);
}

async function connectProvider(provider) {
  if (provider === 'cloud-codex') return connectCodexBrowser();
  const meta = getProviderMeta(provider);
  const loginArgs = provider === 'cloud-claude'
    ? ['auth', 'login']
    : provider === 'cloud-opencode'
      ? ['auth', 'login']
      : ['--login'];

  const openedUrls = new Set();
  const maybeOpenAuthUrl = (text) => {
    const matches = String(text || '').match(/https:\/\/[^\s"'<>]+/g) || [];
    for (const rawUrl of matches) {
      const cleanUrl = rawUrl.replace(/[).,;]+$/, '');
      if (openedUrls.has(cleanUrl)) continue;
      if (/anthropic\.com|claude\.ai|opencode\.ai|github\.com|google\.com|openai\.com|auth|login|oauth/i.test(cleanUrl)) {
        openedUrls.add(cleanUrl);
        openBrowserUrl(cleanUrl);
      }
    }
  };

  await new Promise((resolve, reject) => {
    const child = spawnProviderCli(provider, loginArgs, os.homedir());
    let out = '';
    child.stdout.on('data', (d) => {
      const chunk = d.toString('utf8');
      out = (out + chunk).slice(-1600);
      maybeOpenAuthUrl(chunk);
    });
    child.stderr.on('data', (d) => {
      const chunk = d.toString('utf8');
      out = (out + chunk).slice(-1600);
      maybeOpenAuthUrl(chunk);
    });
    const timer = setTimeout(() => {
      try { child.kill(); } catch (err) { void err; }
      reject(new Error(`${meta.shortLabel} sign-in timed out after 3 minutes.`));
    }, 180000);
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(true);
      else reject(new Error(out.trim().slice(0, 240) || `${meta.shortLabel} login exited with code ${code}.`));
    });
  });

  const status = await getProviderAuthStatus(provider);
  if (!status.connected) {
    throw new Error(`${meta.shortLabel} login completed, but no credentials were detected at ${status.authPath}.`);
  }
  return status;
}

async function disconnectProvider(provider) {
  if (provider === 'cloud-codex') return disconnectCodex();
  const status = await getProviderAuthStatus(provider);
  if (status.authPath) {
    await fs.unlink(status.authPath).catch(() => undefined);
  }
  return true;
}

async function runProviderCliExec({ provider, root, model, prompt, timeoutMs = 90000 }) {
  if (provider === 'cloud-codex') return runCodexExec({ root, model, prompt, timeoutMs });
  const meta = getProviderMeta(provider);

  let args;
  if (provider === 'cloud-claude') {
    args = ['-p', prompt, '--output-format', 'text', ...(model ? ['--model', model] : [])];
  } else if (provider === 'cloud-opencode') {
    args = ['run', prompt, ...(model ? ['-m', model] : [])];
  } else {
    // cloud-pi
    args = ['-p', prompt, ...(model ? ['--model', model] : [])];
  }

  return new Promise((resolve, reject) => {
    const child = spawnProviderCli(provider, args, root || os.homedir());
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${meta.shortLabel} request timed out.`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && stdout.trim()) resolve(stdout.trim());
      else reject(new Error(stderr.trim().slice(0, 260) || `${meta.shortLabel} CLI exited with code ${code}.`));
    });
  });
}

async function callProviderHttp({ provider, model, apiKey, prompt, timeoutMs = 45000, endpoint, fetchImpl = fetch }) {
  const isAnthropic = provider === 'cloud-claude' || (provider === 'cloud-pi' && /^claude-/i.test(model || ''));
  const targetUrl = endpoint || (
    isAnthropic
      ? ANTHROPIC_MESSAGES_ENDPOINT
      : provider === 'cloud-opencode'
        ? OPENCODE_CHAT_ENDPOINT
        : OPENAI_CHAT_ENDPOINT
  );

  const headers = { 'content-type': 'application/json' };
  let body;
  if (isAnthropic) {
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
    body = JSON.stringify({
      model: model || CLAUDE_MODELS[0],
      max_tokens: 2048,
      temperature: 0,
      messages: [{ role: 'user', content: prompt }],
    });
  } else {
    headers.authorization = `Bearer ${apiKey}`;
    body = JSON.stringify({
      model: model || 'gpt-5.2-codex',
      temperature: 0,
      messages: [{ role: 'user', content: prompt }],
    });
  }

  let response;
  try {
    response = await fetchImpl(targetUrl, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new Error(`Cannot reach ${getProviderMeta(provider).shortLabel} API at ${targetUrl}: ${err.message}`);
  }

  if (!response.ok) {
    const errText = await response.text().catch(() => '');
    throw new Error(`${getProviderMeta(provider).shortLabel} returned HTTP ${response.status}: ${errText.slice(0, 240)}`);
  }

  const data = await response.json();
  if (isAnthropic) {
    return Array.isArray(data?.content)
      ? data.content.filter((b) => b?.type === 'text').map((b) => b.text).join('\n')
      : '';
  }
  return data?.choices?.[0]?.message?.content ?? data?.message?.content ?? data?.response ?? '';
}

module.exports = {
  CLOUD_PROVIDER_IDS: Object.keys(PROVIDER_META),
  CLAUDE_MODELS,
  OPENCODE_MODELS,
  PI_MODELS,
  isCloudProvider,
  getProviderMeta,
  getProviderAuthStatus,
  getAvailableProviderModels,
  connectProvider,
  disconnectProvider,
  runProviderCliExec,
  callProviderHttp,
};
