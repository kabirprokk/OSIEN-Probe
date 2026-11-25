'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { analyzeFrameWithLocalVision } = require('./local-vision.cjs');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
  '.jsx': 'application/javascript; charset=utf-8',
  '.tsx': 'application/javascript; charset=utf-8',
  '.ts': 'application/javascript; charset=utf-8',
};

const activeRuns = new Map();

function getSystemProfile() {
  const cpus = os.cpus() || [];
  const totalBytes = os.totalmem();
  const freeBytes = os.freemem();
  const totalMemGb = Math.round((totalBytes / (1024 ** 3)) * 10) / 10;
  const freeMemGb = Math.round((freeBytes / (1024 ** 3)) * 10) / 10;
  const cpuCores = cpus.length || 2;
  const cpuModel = cpus[0]?.model?.trim() || 'Local CPU';
  const tier = totalMemGb >= 15 && cpuCores >= 8 ? 'high' : totalMemGb >= 7 && cpuCores >= 4 ? 'balanced' : 'light';
  const maxSteps = tier === 'high' ? 80 : tier === 'balanced' ? 55 : 35;
  const stepDelayMs = tier === 'high' ? 140 : tier === 'balanced' ? 200 : 280;
  return { cpuModel, cpuCores, totalMemGb, freeMemGb, tier, maxSteps, stepDelayMs };
}

async function fileExists(target) {
  try {
    const stat = await fs.stat(target);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function dirExists(target) {
  try {
    const stat = await fs.stat(target);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

function isWebDevScript(cmd) {
  const s = String(cmd || '').toLowerCase();
  if (!s) return false;
  if (/\belectron\b/.test(s) && !/\bvite\b|\bnext\b|\bwebpack\b|\bparcel\b/.test(s)) return false;
  return /\b(vite|next|nuxt|astro|remix|react-scripts|webpack|parcel|svelte|quasar|ng serve|http-server|serve|live-server|wrangler|gatsby|storybook|node\s)/i.test(s);
}

async function detectWebEntryInDir(dir) {
  const pkgPath = path.join(dir, 'package.json');
  const hasNodeModules = await dirExists(path.join(dir, 'node_modules'));
  if (await fileExists(pkgPath)) {
    try {
      const pkg = JSON.parse(await fs.readFile(pkgPath, 'utf8'));
      const scripts = pkg.scripts || {};
      const preferred = ['dev', 'preview', 'start'].find((name) => scripts[name] && isWebDevScript(scripts[name]));
      if (preferred) {
        if (hasNodeModules) {
          return { mode: 'npm', cwd: dir, scriptName: preferred, command: `npm run ${preferred}` };
        }
        // Check if a built static bundle already exists before requiring npm install
        for (const candidate of ['dist/index.html', 'build/index.html', 'out/index.html']) {
          const full = path.join(dir, candidate);
          if (await fileExists(full)) {
            return { mode: 'static', entryDir: path.dirname(full), entryFile: candidate };
          }
        }
        return { mode: 'missing-deps', cwd: dir, scriptName: preferred, command: `npm run ${preferred}` };
      }
    } catch {
      // Fall through to static detection when package.json cannot be parsed.
    }
  }
  for (const candidate of ['dist/index.html', 'build/index.html', 'out/index.html', 'index.html', 'public/index.html']) {
    const full = path.join(dir, candidate);
    if (await fileExists(full)) {
      return { mode: 'static', entryDir: path.dirname(full), entryFile: candidate };
    }
  }
  return null;
}

async function detectWebEntry(root) {
  const direct = await detectWebEntryInDir(root);
  if (direct && direct.mode !== 'missing-deps') return direct;
  // Also check common monorepo/sub-app web folders (e.g. web/, client/, frontend/, app/)
  for (const sub of ['web', 'client', 'frontend', 'site', 'app']) {
    const subDir = path.join(root, sub);
    if (await dirExists(subDir)) {
      const subEntry = await detectWebEntryInDir(subDir);
      if (subEntry) return subEntry;
    }
  }
  if (direct) return direct;
  const pkgPath = path.join(root, 'package.json');
  const hasNodeModules = await dirExists(path.join(root, 'node_modules'));
  if (await fileExists(pkgPath) && !hasNodeModules) {
    return { mode: 'missing-deps', cwd: root, scriptName: 'dev', command: 'npm run dev' };
  }
  return { mode: 'static', entryDir: root, entryFile: null };
}

function autoInstallProjectDeps(cwd, onLog) {
  return new Promise((resolve, reject) => {
    const env = buildSandboxEnv();
    const child = process.platform === 'win32'
      ? spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'npm.cmd install --no-audit --no-fund'], {
          cwd,
          windowsHide: true,
          env,
        })
      : spawn('npm', ['install', '--no-audit', '--no-fund'], {
          cwd,
          windowsHide: true,
          env,
        });
    const timer = setTimeout(() => {
      killProcessTree(child);
      reject(new Error('Timed out auto-installing dependencies (npm install).'));
    }, 180000);
    const forward = (chunk) => {
      const text = stripAnsi(chunk.toString('utf8'));
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed) onLog(trimmed);
      }
    };
    child.stdout.on('data', forward);
    child.stderr.on('data', forward);
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(true);
      else reject(new Error(`Auto-install exited with code ${code}`));
    });
  });
}

async function waitForHttpReady(urlStr, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 1800);
      const res = await fetch(urlStr, { method: 'GET', signal: ctrl.signal });
      clearTimeout(t);
      if (res.status > 0) return true;
    } catch {
      // Server still booting.
    }
    await new Promise((r) => setTimeout(r, 350));
  }
  return false;
}

function startStaticSandboxServer(entryDir) {
  return new Promise((resolve, reject) => {
    const rootResolved = path.resolve(entryDir);
    const server = http.createServer(async (req, res) => {
      try {
        const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
        const cleanPath = decodeURIComponent(reqUrl.pathname).replace(/^\/+/, '');
        let target = path.resolve(rootResolved, cleanPath || 'index.html');
        if (!target.startsWith(rootResolved)) {
          res.writeHead(403);
          res.end('Forbidden');
          return;
        }
        let stat;
        try {
          stat = await fs.stat(target);
          if (stat.isDirectory()) target = path.join(target, 'index.html');
        } catch {
          target = path.join(rootResolved, 'index.html');
        }
        const data = await fs.readFile(target);
        const ext = path.extname(target).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(data);
      } catch {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function killProcessTree(child) {
  if (!child || child.killed) return;
  try {
    if (process.platform === 'win32' && child.pid) {
      spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true });
    } else if (child.pid) {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    } else {
      child.kill('SIGKILL');
    }
  } catch {
    // Process may already have exited.
  }
  if (child.stdout && !child.stdout.destroyed) child.stdout.destroy();
  if (child.stderr && !child.stderr.destroyed) child.stderr.destroy();
}

const ANSI_RE = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*[A-Za-z]`, 'g');
function stripAnsi(text) {
  return String(text || '').replace(ANSI_RE, '');
}

function buildSandboxEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (/(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|AUTH)/i.test(k)) continue;
    env[k] = v;
  }
  env.BROWSER = 'none';
  env.FORCE_COLOR = '0';
  env.NO_COLOR = '1';
  return env;
}

function startNpmSandboxServer(root, scriptName, onLog) {
  return new Promise((resolve, reject) => {
    if (!/^[a-zA-Z0-9:_-]+$/.test(scriptName)) {
      reject(new Error(`Invalid npm script name: ${scriptName}`));
      return;
    }
    const env = buildSandboxEnv();
    const child = process.platform === 'win32'
      ? spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `npm.cmd run ${scriptName}`], {
          cwd: root,
          windowsHide: true,
          env,
        })
      : spawn('npm', ['run', scriptName], {
          cwd: root,
          windowsHide: true,
          detached: true,
          env,
        });

    const recentLogs = [];
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        killProcessTree(child);
        const tail = recentLogs.slice(-5).join(' | ');
        reject(new Error(`Timed out waiting for "npm run ${scriptName}" to expose a local URL.${tail ? ` Output: ${tail}` : ''}`));
      }
    }, 25000);

    const handleChunk = (chunk) => {
      const text = stripAnsi(chunk.toString('utf8'));
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed) {
          recentLogs.push(trimmed);
          if (recentLogs.length > 20) recentLogs.shift();
          onLog(trimmed);
        }
        const match = trimmed.match(/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1?\]):\d{2,5}[^\s]*/i);
        if (match && !settled) {
          settled = true;
          clearTimeout(timeout);
          const normalizedUrl = match[0]
            .replace(/\/\/0\.0\.0\.0:/i, '//127.0.0.1:')
            .replace(/\/\/\[::1?\]:/i, '//127.0.0.1:');
          resolve({
            url: normalizedUrl,
            close: async () => {
              killProcessTree(child);
            },
          });
        }
      }
    };

    child.stdout.on('data', handleChunk);
    child.stderr.on('data', handleChunk);
    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        reject(err);
      }
    });
    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        const tail = recentLogs.slice(-6).join(' | ');
        reject(new Error(`Dev server exited early with code ${code}.${tail ? ` Output: ${tail}` : ''}`));
      }
    });
  });
}

// Intelligent, curiosity-driven human-like DOM explorer, semantic form filler, and defensive stress driver.
function buildExtremeProbeScript(stepIndex) {
  return `(() => {
    const STEP = ${Number(stepIndex)};
    const PROBE_ID = '__osien_probe_cursor__';
    let cursor = document.getElementById(PROBE_ID);
    if (!cursor) {
      cursor = document.createElement('div');
      cursor.id = PROBE_ID;
      cursor.style.cssText = 'position:fixed;z-index:2147483647;width:20px;height:20px;border-radius:50%;border:2px solid #a8c77e;background:rgba(140,207,94,0.28);box-shadow:0 0 14px rgba(168,199,126,0.85);pointer-events:none;transition:left .14s ease,top .14s ease,transform .1s ease;left:16px;top:16px;';
      document.documentElement.appendChild(cursor);
    }

    const mem = window.__osienBrain || (window.__osienBrain = {
      clicked: new Map(),
      filled: new Map(),
      states: new Set(),
      lastStateSig: '',
      pendingFormSubmit: null,
      runtimeErrors: [],
      trapsInstalled: false,
    });

    if (!mem.trapsInstalled) {
      mem.trapsInstalled = true;
      window.addEventListener('error', (ev) => {
        mem.runtimeErrors.push({
          ruleId: 'extreme-uncaught-exception',
          title: 'Uncaught runtime exception',
          severity: 'high',
          cwe: 'CWE-755',
          detail: String(ev.message || 'Unknown error').slice(0, 180),
        });
      });
      window.addEventListener('unhandledrejection', (ev) => {
        const msg = ev.reason?.message || String(ev.reason || 'Unhandled promise rejection');
        mem.runtimeErrors.push({
          ruleId: 'extreme-unhandled-rejection',
          title: 'Unhandled Promise rejection in page',
          severity: 'high',
          cwe: 'CWE-755',
          detail: String(msg).slice(0, 180),
        });
      });
    }

    const moveCursor = (el, pulse = false) => {
      const r = el.getBoundingClientRect();
      cursor.style.left = Math.max(4, r.left + r.width / 2 - 10) + 'px';
      cursor.style.top = Math.max(4, r.top + r.height / 2 - 10) + 'px';
      if (pulse) {
        cursor.style.transform = 'scale(1.4)';
        setTimeout(() => { cursor.style.transform = 'scale(1)'; }, 110);
      }
      el.scrollIntoView({ block: 'nearest', behavior: 'instant' });
    };

    const isVisible = (el) => {
      if (!el || el.id === PROBE_ID) return false;
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 4 && r.height > 4 && s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0' && !el.disabled;
    };

    const getLabel = (el) => {
      const id = el.id;
      const explicitLabel = id ? document.querySelector('label[for="' + CSS.escape(id) + '"]')?.innerText : '';
      return (
        el.getAttribute('aria-label') ||
        explicitLabel ||
        el.innerText ||
        el.getAttribute('placeholder') ||
        el.getAttribute('name') ||
        el.getAttribute('title') ||
        el.getAttribute('href') ||
        el.tagName
      ).replace(/\\s+/g, ' ').trim().slice(0, 56);
    };

    const findings = [];
    const checkPageHealth = () => {
      if (document.documentElement.scrollWidth > window.innerWidth + 8) {
        findings.push({
          ruleId: 'extreme-layout-overflow',
          title: 'Horizontal layout overflow detected',
          severity: 'low',
          cwe: 'CWE-1084',
          detail: 'scrollWidth (' + document.documentElement.scrollWidth + 'px) exceeds viewport (' + window.innerWidth + 'px) at ' + location.pathname,
        });
      }
      for (const img of document.querySelectorAll('img')) {
        if (img.complete && img.naturalWidth === 0 && img.getAttribute('src')) {
          findings.push({
            ruleId: 'extreme-broken-image',
            title: 'Broken image failed to load',
            severity: 'low',
            cwe: 'CWE-404',
            detail: img.getAttribute('src'),
          });
        }
      }
      if (document.querySelector('[data-osien-xss-probe="1"]')) {
        findings.push({
          ruleId: 'extreme-dom-xss-unescaped',
          title: 'Unescaped HTML/XSS input rendered as live DOM node',
          severity: 'critical',
          cwe: 'CWE-79',
          detail: 'Fuzzed input containing <b data-osien-xss-probe="1"> was parsed as active HTML in the DOM.',
        });
      }
      for (const a of document.querySelectorAll('a[target="_blank"]')) {
        const rel = (a.getAttribute('rel') || '').toLowerCase();
        if (!rel.includes('noopener')) {
          findings.push({
            ruleId: 'extreme-tabnabbing-link',
            title: 'target="_blank" link missing rel="noopener"',
            severity: 'medium',
            cwe: 'CWE-1022',
            detail: a.getAttribute('href') || getLabel(a),
          });
        }
      }
      for (const a of document.querySelectorAll('a[href^="javascript:" i]')) {
        findings.push({
          ruleId: 'extreme-javascript-href',
          title: 'Unsafe javascript: URI in anchor href',
          severity: 'high',
          cwe: 'CWE-79',
          detail: getLabel(a),
        });
      }
      // Accessibility audit: unlabeled interactive buttons and missing img alt
      let unlabeledButtons = 0;
      for (const btn of document.querySelectorAll('button')) {
        if (!isVisible(btn)) continue;
        const txt = (btn.innerText || btn.getAttribute('aria-label') || btn.getAttribute('title') || '').trim();
        if (!txt) unlabeledButtons++;
      }
      if (unlabeledButtons > 0) {
        findings.push({
          ruleId: 'extreme-a11y-unlabeled-button',
          title: unlabeledButtons + ' interactive button(s) missing accessible label',
          severity: 'low',
          cwe: 'CWE-1059',
          detail: 'Add aria-label or visible text to icon-only buttons at ' + location.pathname,
        });
      }
      if (mem.runtimeErrors && mem.runtimeErrors.length > 0) {
        while (mem.runtimeErrors.length > 0) {
          findings.push(mem.runtimeErrors.shift());
        }
      }
    };

    const setNativeValue = (el, val) => {
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, val);
      else el.value = val;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };

    const chooseSmartPayload = (el, attempt) => {
      const meta = ((el.type || '') + ' ' + (el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' + getLabel(el)).toLowerCase();
      if (el.type === 'email' || /email|e-mail/.test(meta)) {
        return attempt === 0 ? 'alex.mercer@example.com' : 'invalid-email@';
      }
      if (el.type === 'password' || /pass(word|wd)?/.test(meta)) {
        return attempt === 0 ? 'Str0ng!Probe#2026' : '';
      }
      if (el.type === 'url' || /website|url|link/.test(meta)) {
        return attempt === 0 ? 'https://example.com' : 'javascript:alert(1)';
      }
      if (el.type === 'number' || /age|qty|count|price|amount|port|limit/.test(meta)) {
        return ['42', '-999', '0'][attempt % 3];
      }
      if (el.type === 'tel' || /phone|mobile|tel/.test(meta)) {
        return '+15550199283';
      }
      const probes = [
        'OSIEN Human QA Test',
        '<b data-osien-xss-probe="1">probe</b>',
        "' OR '1'='1",
        'A'.repeat(240),
      ];
      return probes[attempt % probes.length];
    };

    const inputs = [...document.querySelectorAll('input:not([type="hidden"]), textarea, select')].filter(isVisible);
    const clickables = [...document.querySelectorAll('button, a[href], [role="button"], [role="tab"], input[type="submit"], input[type="button"]')].filter(isVisible);

    const stateSig = location.pathname + '|' + document.title + '|' + inputs.length + '|' + clickables.length + '|' + Boolean(document.querySelector('[role="dialog"], dialog[open]'));
    const isNewState = stateSig !== mem.lastStateSig && !mem.states.has(stateSig);
    mem.states.add(stateSig);
    mem.lastStateSig = stateSig;

    let action = 'inspect';
    let targetLabel = '';
    let detailNote = isNewState ? 'new UI state discovered' : '';

    // 1. If we just finished filling a form, submit it like a real user!
    if (mem.pendingFormSubmit && isVisible(mem.pendingFormSubmit)) {
      const btn = mem.pendingFormSubmit;
      mem.pendingFormSubmit = null;
      moveCursor(btn, true);
      targetLabel = getLabel(btn);
      action = 'submit-form';
      detailNote = 'submitting populated form';
      btn.click();
    } else {
      // 2. Semantic input filling (prefer untouched or under-tested inputs)
      const nextInput = inputs.find((el) => {
        const key = location.pathname + '::' + getLabel(el);
        return (mem.filled.get(key) || 0) < 2;
      });

      if (nextInput) {
        const key = location.pathname + '::' + getLabel(nextInput);
        const attempt = mem.filled.get(key) || 0;
        mem.filled.set(key, attempt + 1);
        moveCursor(nextInput, false);
        targetLabel = getLabel(nextInput);

        if (nextInput.tagName === 'SELECT') {
          if (nextInput.options.length > 0) nextInput.selectedIndex = (attempt + 1) % nextInput.options.length;
          nextInput.dispatchEvent(new Event('change', { bubbles: true }));
          action = 'select-option';
          detailNote = 'selected option #' + nextInput.selectedIndex;
        } else if (nextInput.type === 'checkbox' || nextInput.type === 'radio') {
          nextInput.click();
          action = 'toggle-' + nextInput.type;
          detailNote = 'toggled state -> ' + nextInput.checked;
        } else {
          const payload = chooseSmartPayload(nextInput, attempt);
          setNativeValue(nextInput, payload);
          action = attempt === 0 ? 'human-type' : 'fuzz-input';
          detailNote = attempt === 0 ? 'entered realistic value' : 'probed edge/XSS escaping';
          const form = nextInput.closest('form');
          if (form) {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
            if (submitBtn && isVisible(submitBtn)) mem.pendingFormSubmit = submitBtn;
          }
        }
      } else if (clickables.length > 0) {
        // 3. Curiosity-ranked click selection (human-like prioritization)
        const scored = clickables.map((el) => {
          const label = getLabel(el);
          const key = location.pathname + '::' + label;
          const seen = mem.clicked.get(key) || 0;
          let score = seen === 0 ? 50 : Math.max(-40, 10 - seen * 20);
          if (el.closest('[role="dialog"], dialog[open]')) score += 25;
          if (/submit|save|create|next|continue|start|open|add|send|verify|tab|menu/i.test(label)) score += 18;
          if (el.tagName === 'A' && el.getAttribute('href')?.startsWith('/')) score += 14;
          if (/logout|sign ?out|delete account|remove all/i.test(label)) score -= 60;
          const href = el.getAttribute('href') || '';
          if (el.tagName === 'A' && /^https?:\\/\\//i.test(href) && !href.startsWith(location.origin)) score -= 100;
          return { el, label, key, seen, score };
        }).sort((a, b) => b.score - a.score);

        const pick = scored[0];
        mem.clicked.set(pick.key, pick.seen + 1);
        moveCursor(pick.el, true);
        targetLabel = pick.label;
        const href = pick.el.getAttribute('href') || '';
        if (pick.el.tagName === 'A' && /^https?:\\/\\//i.test(href) && !href.startsWith(location.origin)) {
          action = 'skip-external';
          detailNote = 'kept inside sandbox';
        } else {
          action = STEP % 7 === 0 ? 'stress-double-click' : 'human-click';
          detailNote = 'priority ' + pick.score + (pick.seen === 0 ? ' · first visit' : ' · re-test');
          pick.el.click();
          if (action === 'stress-double-click') pick.el.click();
        }
      }
    }

    checkPageHealth();
    return {
      url: location.href,
      title: document.title,
      action,
      targetLabel,
      detailNote,
      inputsCount: inputs.length,
      clickablesCount: clickables.length,
      findings,
    };
  })()`;
}

async function runExtremeTest({ project, BrowserWindow, session, onEvent }) {
  if (activeRuns.has(project.id)) {
    throw new Error('An Extreme Sandbox Test is already running for this project.');
  }
  const profile = getSystemProfile();
  const state = { cancelled: false, win: null, server: null };
  activeRuns.set(project.id, state);

  const emit = (type, payload) => {
    try {
      onEvent({ projectId: project.id, type, ...payload });
    } catch {
      // Renderer may have closed.
    }
  };

  const emittedFindings = new Set();
  const collectedFindings = [];
  const pushFinding = (f) => {
    const key = `${f.ruleId}:${f.detail || f.title}`;
    if (emittedFindings.has(key)) return;
    emittedFindings.add(key);
    collectedFindings.push(f);
    emit('finding', { finding: f });
  };

  try {
    emit('log', { level: 'info', text: `PC profile: ${profile.cpuCores} cores, ${profile.totalMemGb} GB RAM (${profile.tier} tier · ${profile.maxSteps} autonomous steps + Mirage-22M Vision AI)` });
    const isRemoteUrl = /^https?:\/\//i.test(String(project.root || '').trim());
    let server;
    if (isRemoteUrl) {
      server = { url: String(project.root).trim(), close: async () => {} };
      emit('log', { level: 'info', text: `Connecting Extreme Live Sandbox & Mirage-22M Vision AI to ${server.url}…` });
    } else {
      let entry = await detectWebEntry(project.root);
      if (entry.mode === 'missing-deps') {
        emit('log', { level: 'info', text: `Auto-installing dependencies in ${path.basename(entry.cwd || project.root)} via npm install…` });
        try {
          await autoInstallProjectDeps(entry.cwd || project.root, (line) => emit('log', { level: 'server', text: line }));
          entry = await detectWebEntry(project.root);
        } catch (installErr) {
          emit('log', { level: 'warn', text: `Auto-install skipped (${installErr.message}); falling back to static sandbox.` });
          entry = { mode: 'static', entryDir: project.root, entryFile: null };
        }
      }
      emit('log', { level: 'info', text: entry.mode === 'npm' ? `Starting sandboxed dev server (${entry.command})…` : `Starting isolated static sandbox server on 127.0.0.1…` });

      server = entry.mode === 'npm'
        ? await startNpmSandboxServer(entry.cwd || project.root, entry.scriptName, (line) => emit('log', { level: 'server', text: line }))
        : await startStaticSandboxServer(entry.entryDir);
      await waitForHttpReady(server.url, 12000);
    }
    state.server = server;
    if (state.cancelled) return { cancelled: true, findings: collectedFindings };

    const targetUrl = new URL(server.url);
    const targetPort = targetUrl.port;
    const allowedOrigins = new Set([
      targetUrl.origin,
      `http://localhost${targetPort ? `:${targetPort}` : ''}`,
      `http://127.0.0.1${targetPort ? `:${targetPort}` : ''}`,
      `http://[::1]${targetPort ? `:${targetPort}` : ''}`,
    ]);
    emit('log', { level: 'info', text: `Sandbox live at ${server.url} — Vision-22M visual perception active` });

    const blockedOrigins = new Set();
    const sandboxSession = session.fromPartition(`osien-sandbox-${project.id}-${Date.now()}`, { cache: false });
    sandboxSession.webRequest.onBeforeRequest((details, callback) => {
      const u = details.url || '';
      const isStaticAsset = isRemoteUrl && ['stylesheet', 'script', 'image', 'font', 'media'].includes(details.resourceType);
      const allowed = isStaticAsset || [...allowedOrigins].some((o) => u.startsWith(o)) || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('devtools:');
      if (!allowed) {
        try {
          const origin = new URL(u).origin;
          if (!blockedOrigins.has(origin)) {
            blockedOrigins.add(origin);
            emit('log', { level: 'warn', text: `Sandbox blocked outbound origin: ${origin}` });
          }
        } catch {
          // Ignore malformed URLs.
        }
      }
      callback({ cancel: !allowed });
    });

    let headerChecked = false;
    sandboxSession.webRequest.onCompleted((details) => {
      if (details.statusCode >= 500) {
        pushFinding({
          ruleId: 'extreme-http-5xx',
          title: `Server returned HTTP ${details.statusCode}`,
          severity: 'high',
          cwe: 'CWE-703',
          detail: details.url,
        });
      }
      if (!headerChecked && details.resourceType === 'mainFrame') {
        headerChecked = true;
        const headers = details.responseHeaders || {};
        const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v)]));
        if (!lower['content-security-policy']) {
          pushFinding({
            ruleId: 'extreme-missing-csp',
            title: 'Missing Content-Security-Policy header on document response',
            severity: 'medium',
            cwe: 'CWE-693',
            detail: details.url,
          });
        }
        if (!lower['x-content-type-options']) {
          pushFinding({
            ruleId: 'extreme-missing-xcto',
            title: 'Missing X-Content-Type-Options: nosniff header',
            severity: 'low',
            cwe: 'CWE-693',
            detail: details.url,
          });
        }
      }
    });

    const win = new BrowserWindow({
      width: 1120,
      height: 740,
      show: false,
      webPreferences: {
        offscreen: true,
        session: sandboxSession,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
      },
    });
    state.win = win;

    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    if (typeof win.webContents.setFrameRate === 'function') {
      win.webContents.setFrameRate(15);
    }
    let latestPaintedFrame = null;
    win.webContents.on('paint', (_event, _dirty, image) => {
      if (image && !image.isEmpty()) latestPaintedFrame = image;
    });
    const grabFrame = async () => {
      if (latestPaintedFrame && !latestPaintedFrame.isEmpty()) return latestPaintedFrame;
      if (win.isDestroyed()) return null;
      const cap = await win.webContents.capturePage();
      return cap && !cap.isEmpty() ? cap : null;
    };
    win.webContents.on('did-fail-load', (_e, errorCode, errorDesc, validatedURL, isMainFrame) => {
      if (isMainFrame && errorCode !== -3) {
        pushFinding({
          ruleId: 'extreme-load-failure',
          title: `Page failed to load (${errorDesc})`,
          severity: 'high',
          cwe: 'CWE-703',
          detail: `${validatedURL || server.url} (code ${errorCode})`,
        });
      }
    });
    win.webContents.on('console-message', (_e, level, msg, line, sourceId) => {
      if (level >= 3) {
        pushFinding({
          ruleId: 'extreme-console-error',
          title: 'Runtime console error in browser',
          severity: 'medium',
          cwe: 'CWE-390',
          detail: `${msg} (${sourceId || 'page'}:${line})`.slice(0, 180),
        });
      }
    });
    win.webContents.on('render-process-gone', (_e, details) => {
      pushFinding({
        ruleId: 'extreme-renderer-crash',
        title: `Browser tab crashed (${details.reason})`,
        severity: 'critical',
        cwe: 'CWE-248',
        detail: `Exit code ${details.exitCode}`,
      });
    });

    const loadStart = Date.now();
    await win.loadURL(server.url);
    const loadMs = Date.now() - loadStart;
    if (loadMs > 4500) {
      pushFinding({
        ruleId: 'extreme-slow-initial-load',
        title: `Slow initial page load (${(loadMs / 1000).toFixed(1)}s)`,
        severity: 'low',
        cwe: 'CWE-400',
        detail: `${server.url} took ${loadMs}ms to reach initial load.`,
      });
    }
    emit('log', { level: 'info', text: `Loaded ${server.url} in ${loadMs}ms — waiting for UI hydration…` });
    for (let w = 0; w < 24; w++) {
      if (state.cancelled || win.isDestroyed()) break;
      try {
        const ready = await win.webContents.executeJavaScript(`(() => {
          const ready = document.readyState === 'complete';
          const textLen = (document.body?.innerText || '').trim().length;
          const interactive = document.querySelectorAll('button, a[href], input, textarea, select').length;
          const isLoading = /\\bloading\\b/i.test(document.body?.innerText || '') && interactive <= 2;
          return { ready, ok: ready && !isLoading && (interactive > 0 || textLen > 80) };
        })()`, true);
        if (!win.isDestroyed()) {
          const frame = await grabFrame();
          if (frame) {
            const jpeg = frame.resize({ width: 760, quality: 'good' }).toJPEG(72);
            emit('frame', { dataUrl: `data:image/jpeg;base64,${jpeg.toString('base64')}` });
          }
        }
        if (ready?.ok && w >= 3) break;
      } catch (err) {
        void err;
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    let clicks = 0;
    let inputsFuzzed = 0;
    let prevVisionEmbedding = null;
    const routes = new Set([server.url]);
    const mobileSwitchStep = Math.max(4, Math.floor(profile.maxSteps * 0.65));
    const desktopRestoreStep = Math.min(profile.maxSteps - 2, mobileSwitchStep + 6);

    for (let step = 0; step < profile.maxSteps; step++) {
      if (state.cancelled || win.isDestroyed()) break;
      if (step === mobileSwitchStep && !win.isDestroyed()) {
        try {
          win.setSize(390, 844);
          emit('log', { level: 'info', text: 'Switching sandbox viewport to Mobile (390×844) for responsive overflow & tap-target audit…' });
        } catch (err) {
          void err;
        }
      } else if (step === desktopRestoreStep && !win.isDestroyed()) {
        try {
          win.setSize(1120, 740);
          emit('log', { level: 'info', text: 'Restoring Desktop viewport (1120×740)…' });
        } catch (err) {
          void err;
        }
      }
      try {
        const res = await win.webContents.executeJavaScript(buildExtremeProbeScript(step), true);
        if (res) {
          routes.add(res.url);
          if (res.action === 'fuzz-input' || res.action === 'human-type' || res.action === 'select-option') inputsFuzzed += 1;
          else if (res.action === 'human-click' || res.action === 'stress-double-click' || res.action === 'submit-form') clicks += 1;
          for (const f of res.findings || []) pushFinding(f);
          emit('step', {
            step: step + 1,
            maxSteps: profile.maxSteps,
            url: res.url,
            action: res.action,
            targetLabel: res.detailNote ? `${res.targetLabel} (${res.detailNote})` : res.targetLabel,
            stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
          });
        }
      } catch (err) {
        emit('log', { level: 'warn', text: `Step ${step + 1} probe error: ${err.message}` });
      }

      if (!win.isDestroyed()) {
        try {
          const domMetrics = await win.webContents.executeJavaScript(`(() => {
            const imgs = [...document.querySelectorAll('img')];
            const broken = imgs.filter(img => img.complete && img.naturalWidth === 0 && img.getAttribute('src'));
            const controls = [...document.querySelectorAll('button, input, select, a[href]')].filter(el => {
              const r = el.getBoundingClientRect();
              return r.width > 4 && r.height > 4 && getComputedStyle(el).visibility !== 'hidden';
            });
            let overlaps = 0;
            let overlapSummary = '';
            for (let i = 0; i < Math.min(controls.length, 25); i++) {
              const a = controls[i].getBoundingClientRect();
              for (let j = i + 1; j < Math.min(controls.length, 25); j++) {
                if (controls[i].contains(controls[j]) || controls[j].contains(controls[i])) continue;
                const b = controls[j].getBoundingClientRect();
                const ix = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
                const iy = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
                if (ix * iy > 140) {
                  overlaps++;
                  if (!overlapSummary) overlapSummary = (controls[i].innerText || controls[i].tagName) + ' overlaps ' + (controls[j].innerText || controls[j].tagName);
                }
              }
            }
            return {
              brokenImages: broken.length,
              brokenImageSrc: broken[0]?.getAttribute('src') || '',
              overlappingControls: overlaps,
              overlapSummary: overlapSummary.slice(0, 120),
            };
          })()`, true).catch(() => ({}));

          const frame = await grabFrame();
          if (frame) {
            const jpeg = frame.resize({ width: 760, quality: 'good' }).toJPEG(72);
            const visionSample = frame.resize({ width: 256, height: 160, quality: 'good' });
            const vSize = visionSample.getSize();
            const visionReport = analyzeFrameWithLocalVision({
              rgbaBuffer: visionSample.toBitmap(),
              width: vSize.width,
              height: vSize.height,
              prevEmbedding: prevVisionEmbedding,
              domMetrics,
            });
            prevVisionEmbedding = visionReport.embedding;
            for (const vf of visionReport.findings) pushFinding(vf);
            if (step % 4 === 0) {
              emit('log', { level: 'info', text: visionReport.caption });
            }
            emit('frame', {
              dataUrl: `data:image/jpeg;base64,${jpeg.toString('base64')}`,
              vision: {
                caption: visionReport.caption,
                activePatchRatio: visionReport.activePatchRatio,
                dominantBrightness: visionReport.dominantBrightness,
                contrastStd: visionReport.contrastStd,
                visualDelta: visionReport.visualDelta,
                heatmap64: visionReport.heatmap64,
              },
            });
          }
        } catch (err) {
          void err;
        }
      }
      await new Promise((r) => setTimeout(r, profile.stepDelayMs));
    }

    emit('done', {
      cancelled: state.cancelled,
      stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
      findings: collectedFindings,
    });
    return {
      cancelled: state.cancelled,
      stats: { pages: routes.size, clicks, inputsFuzzed, findings: emittedFindings.size },
      findings: collectedFindings,
    };
  } finally {
    await cleanupRunState(state);
    activeRuns.delete(project.id);
  }
}

async function cleanupRunState(state) {
  if (state.win && !state.win.isDestroyed()) {
    try { state.win.destroy(); } catch (err) { void err; }
  }
  if (state.server) {
    try { await state.server.close(); } catch (err) { void err; }
  }
}

async function stopExtremeTest(projectId) {
  const state = activeRuns.get(projectId);
  if (!state) return false;
  state.cancelled = true;
  await cleanupRunState(state);
  activeRuns.delete(projectId);
  return true;
}

module.exports = {
  getSystemProfile,
  detectWebEntry,
  startStaticSandboxServer,
  startNpmSandboxServer,
  stripAnsi,
  buildExtremeProbeScript,
  runExtremeTest,
  stopExtremeTest,
};
