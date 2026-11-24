'use strict';
const { app, BrowserWindow, dialog, ipcMain, shell, Menu, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const execFileAsync = promisify(execFile);
// ipcMain is undefined when this file is required by the test runner.
const ipc = typeof ipcMain?.handle === 'function' ? ipcMain.handle.bind(ipcMain) : () => {};
const { scanProjectRoot, toSarifReport, toMarkdownReport, toHtmlReport, kinds } = require('./scanner.cjs');
const { scanLiveUrl, generateWebRemediation } = require('./web-auditor.cjs');
const { shared, categoryRules } = require('./rules.cjs');
const { verifyFinding, reviewFindings, getSourceContext, checkAiHealth, generateFindingFix, generateFileBatchFixes, applyFindingFix } = require('./ai-review.cjs');
const { getCodexAuthStatus, getAvailableCodexModels, connectCodexBrowser, disconnectCodex } = require('./codex-auth.cjs');
const { isCloudProvider, getProviderAuthStatus, getAvailableProviderModels, connectProvider, disconnectProvider } = require('./agent-providers.cjs');
const { getSystemProfile, runExtremeTest, stopExtremeTest } = require('./extreme-tester.cjs');
const { runNpcSwarmTest, stopNpcSwarmTest } = require('./npc-swarm-tester.cjs');
const { getLocalVisionStatus, provisionLocalVisionModel, analyzeImageLocal, autoInstallCactusCompute } = require('./local-vision.cjs');
const { cloneRepositoryAuto, ensureOllamaBinary } = require('./auto-installer.cjs');
const { checkForAppUpdates, downloadAndLaunchUpdate } = require('./auto-updater.cjs');
const visionModelDir = () => path.join(app.getPath('userData'), 'models', 'osien-vision-22m');
const isInside = (root, target) => { const rel = path.relative(root, target); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); };
const statePath = () => path.join(app.getPath('userData'), 'deepcheck-projects.json');
const aiConfigPath = () => path.join(app.getPath('userData'), 'osien-ai-config.json');
const LIGHTEST_CODING_MODEL = 'qwen2.5-coder:0.5b';
async function readAiConfig() {
  try {
    const raw = JSON.parse(await fs.readFile(aiConfigPath(), 'utf8'));
    const provider = isCloudProvider(raw.provider) ? raw.provider : 'local';
    const validCategories = Array.isArray(raw.selectedCategories)
      ? raw.selectedCategories.filter((c) => kinds.includes(c))
      : [];
    return {
      provider,
      model: String(raw.model || (isCloudProvider(provider) ? 'default' : LIGHTEST_CODING_MODEL)),
      apiKey: String(raw.apiKey || ''),
      setupCompleted: Boolean(raw.setupCompleted),
      selectedCategories: validCategories,
      localModelInstalled: Boolean(raw.localModelInstalled),
    };
  } catch {
    return {
      provider: 'local',
      model: LIGHTEST_CODING_MODEL,
      apiKey: '',
      setupCompleted: false,
      selectedCategories: [],
      localModelInstalled: false,
    };
  }
}
async function saveAiConfig(cfg) {
  await fs.mkdir(path.dirname(aiConfigPath()), { recursive: true });
  await fs.writeFile(aiConfigPath(), JSON.stringify(cfg, null, 2), 'utf8');
}
async function publicAiConfig(cfg) {
  const [codexAuth, codexModels, claudeAuth, claudeModels, opencodeAuth, opencodeModels, piAuth, piModels, localHealth] = await Promise.all([
    getCodexAuthStatus(),
    getAvailableCodexModels(),
    getProviderAuthStatus('cloud-claude'),
    getAvailableProviderModels('cloud-claude'),
    getProviderAuthStatus('cloud-opencode'),
    getAvailableProviderModels('cloud-opencode'),
    getProviderAuthStatus('cloud-pi'),
    getAvailableProviderModels('cloud-pi'),
    checkAiHealth({ provider: 'local', model: cfg.model }),
  ]);
  const localModels = localHealth.models || [];
  const modelsByProvider = {
    'cloud-codex': codexModels,
    'cloud-claude': claudeModels,
    'cloud-opencode': opencodeModels,
    'cloud-pi': piModels,
  };
  const connectedByProvider = {
    'cloud-codex': codexAuth.connected,
    'cloud-claude': claudeAuth.connected,
    'cloud-opencode': opencodeAuth.connected,
    'cloud-pi': piAuth.connected,
  };
  const activeList = isCloudProvider(cfg.provider) ? (modelsByProvider[cfg.provider] || codexModels) : localModels;
  const effectiveModel = activeList.includes(cfg.model) ? cfg.model : (activeList[0] || cfg.model);
  return {
    provider: cfg.provider,
    model: effectiveModel,
    codexConnected: codexAuth.connected,
    claudeConnected: claudeAuth.connected,
    opencodeConnected: opencodeAuth.connected,
    piConnected: piAuth.connected,
    connectedByProvider,
    hasApiKey: Boolean(cfg.apiKey),
    apiKeyMasked: cfg.apiKey ? `${cfg.apiKey.slice(0, 5)}…${cfg.apiKey.slice(-4)}` : '',
    localModels,
    localAvailable: localHealth.available,
    codexModels,
    claudeModels,
    opencodeModels,
    piModels,
    setupCompleted: Boolean(cfg.setupCompleted),
    selectedCategories: Array.isArray(cfg.selectedCategories) && cfg.selectedCategories.length > 0 ? cfg.selectedCategories : kinds,
    localModelInstalled: Boolean(cfg.localModelInstalled),
  };
}
async function readProjects() { try { return JSON.parse(await fs.readFile(statePath(), 'utf8')); } catch { return []; } }
async function saveProjects(projects) { await fs.mkdir(path.dirname(statePath()), { recursive: true }); await fs.writeFile(statePath(), JSON.stringify(projects, null, 2), 'utf8'); }
const windowStatePath = () => path.join(app.getPath('userData'), 'osien-window-state.json');
async function readWindowState() {
  const text = await fs.readFile(windowStatePath(), 'utf8').catch(() => '');
  if (text) {
    try {
      const raw = JSON.parse(text);
      if (raw && typeof raw.width === 'number' && typeof raw.height === 'number') return raw;
    } catch (err) {
      void err;
    }
  }
  return { width: 1440, height: 920, isMaximized: false };
}
function createWindow(ws = { width: 1440, height: 920, isMaximized: false }) {
  const win = new BrowserWindow({
    width: Math.max(1000, ws.width),
    height: Math.max(680, ws.height),
    ...(typeof ws.x === 'number' && typeof ws.y === 'number' ? { x: ws.x, y: ws.y } : {}),
    minWidth: 1000,
    minHeight: 680,
    show: false,
    backgroundColor: '#0c0d0e',
    title: 'OSIEN Probe',
    icon: path.join(__dirname, process.platform === 'win32' ? '../build/icon.ico' : '../build/icon.png'),
    autoHideMenuBar: true,
    titleBarStyle: process.platform === 'linux' ? 'default' : 'hidden',
    ...(process.platform === 'win32' ? { titleBarOverlay: { color: '#0c0d0e', symbolColor: '#d7dce5', height: 44 } } : {}),
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false },
  });
  win.once('ready-to-show', () => {
    if (ws.isMaximized) win.maximize();
    win.show();
  });
  const saveWinState = () => {
    const isMaximized = win.isMaximized();
    const bounds = isMaximized ? win.getNormalBounds() : win.getBounds();
    void fs.writeFile(windowStatePath(), JSON.stringify({ ...bounds, isMaximized }), 'utf8').catch((err) => void err);
  };
  win.on('resize', saveWinState);
  win.on('move', saveWinState);
  win.on('close', saveWinState);
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  if (process.env.VITE_DEV_SERVER_URL) win.loadURL(process.env.VITE_DEV_SERVER_URL); else win.loadFile(path.join(__dirname, '../dist/index.html'));
  return win;
}
if (process.versions.electron && typeof ipcMain?.handle === 'function') {
  if (process.platform === 'win32') app.setAppUserModelId('dev.osien.probe');
  const gotLock = app.requestSingleInstanceLock();
  if (!gotLock) {
    app.quit();
  } else {
    app.on('second-instance', () => {
      const win = BrowserWindow.getAllWindows()[0];
      if (!win) return;
      if (win.isMinimized()) win.restore();
      win.focus();
    });
    app.whenReady().then(async () => {
      Menu.setApplicationMenu(null);
      const ws = await readWindowState();
      createWindow(ws);
      app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) void readWindowState().then(createWindow); });
    }).catch(() => app.quit());
    app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
  }
}
// IPC handlers remain registered only in the app process; tests call scanProjectRoot directly.
ipc('pick-folder', async () => { const result = await dialog.showOpenDialog({ properties: ['openDirectory'] }); return result.canceled ? null : result.filePaths[0]; });
ipc('list-projects', readProjects);
async function persistProject(rootPath, kind, displayName) {
  if (typeof rootPath === 'string' && /^https?:\/\//i.test(rootPath.trim())) {
    const parsed = new URL(rootPath.trim());
    const normalized = parsed.toString();
    const projects = await readProjects();
    if (projects.some(p => p.root.toLowerCase() === normalized.toLowerCase())) throw new Error('This URL is already connected');
    const project = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name: displayName || parsed.hostname,
      root: normalized,
      kind: 'Website',
      isLiveUrl: true,
      addedAt: new Date().toISOString(),
      latestRun: null,
      scanHistory: [],
    };
    projects.unshift(project); await saveProjects(projects); return project;
  }
  if (!kinds.includes(kind)) throw new Error('Choose a project category');
  const root = path.resolve(rootPath); const stat = await fs.stat(root).catch(() => null);
  if (!stat?.isDirectory()) throw new Error('The selected folder no longer exists');
  const projects = await readProjects();
  if (projects.some(p => path.resolve(p.root).toLowerCase() === root.toLowerCase())) throw new Error('This project is already connected');
  const project = { id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, name: displayName || path.basename(root), root, kind, addedAt: new Date().toISOString(), latestRun: null, scanHistory: [] };
  projects.unshift(project); await saveProjects(projects); return project;
}
ipc('add-project', async (_event, payload) => {
  if (!payload || typeof payload.root !== 'string') throw new Error('Choose a folder or URL and project category');
  const isUrl = /^https?:\/\//i.test(payload.root.trim());
  if (!isUrl && !kinds.includes(payload.kind)) throw new Error('Choose a folder and project category');
  return persistProject(payload.root, payload.kind || 'Website');
});
ipc('clone-repo', async (_event, payload) => {
  const url = String(payload?.url || '').trim();
  if (!/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+(?:\.git)?\/?$/i.test(url)) {
    throw new Error('Enter a public GitHub, GitLab, or Bitbucket repository URL');
  }
  const cleanUrl = url.replace(/\/+$/, '');
  const repoName = cleanUrl.replace(/\.git$/i, '').split('/').pop() || 'repository';
  const safeFolder = `${repoName.replace(/[^A-Za-z0-9._-]/g, '-')}-${Date.now()}`;
  const target = path.join(app.getPath('userData'), 'repositories', safeFolder);
  await cloneRepositoryAuto(cleanUrl, target);
  return persistProject(target, payload.kind || 'Software', repoName);
});
ipc('remove-project', async (_event, id) => { const projects = await readProjects(); const index = projects.findIndex(p => p.id === id); if (index < 0) throw new Error('Project not found'); const [removed] = projects.splice(index, 1); await saveProjects(projects); return removed; });
ipc('open-data-folder', async () => { const error = await shell.openPath(app.getPath('userData')); if (error) throw new Error(error); return true; });
ipc('open-project', async (_event, id) => {
  const p = (await readProjects()).find(item => item.id === id);
  if (!p) throw new Error('Project not found');
  if (p.isLiveUrl || /^https?:\/\//i.test(p.root)) {
    await shell.openExternal(p.root);
    return true;
  }
  const error = await shell.openPath(p.root);
  if (error) throw new Error(error);
  return true;
});
ipc('scan-project', async (_event, id) => {
  const projects = await readProjects(); const project = projects.find(p => p.id === id); if (!project) throw new Error('Project not found');
  const priorFindingIds = new Set((project.latestRun?.findings || []).map((f) => f.id));
  const priorScore = typeof project.latestRun?.score === 'number' ? project.latestRun.score : null;
  // A fresh source scan starts a new run; don't leave test output from the prior scan attached.
  if (project.latestRun) {
    delete project.latestRun.testResult;
    delete project.latestRun.testResults;
    for (const finding of project.latestRun.findings || []) { delete finding.aiAssessment; delete finding.aiReviewError; }
    await saveProjects(projects);
  }
  const isLive = Boolean(project.isLiveUrl || /^https?:\/\//i.test(project.root));
  let result;
  if (isLive) {
    const webRes = await scanLiveUrl(project.root, {
      bugsOnly: true,
      probeCorsReflection: true,
      probeExposedFiles: true,
      crawlPages: 3,
    });
    result = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      root: webRes.root,
      kind: 'Website',
      filesScanned: webRes.scannedFiles,
      rulesEvaluated: webRes.totalRules,
      totalChecks: webRes.totalChecks,
      durationMs: webRes.durationMs,
      score: webRes.score,
      severityCounts: webRes.severityCounts,
      findings: webRes.findings,
      truncated: webRes.truncated,
      completedAt: webRes.scannedAt,
    };
  } else {
    result = await scanProjectRoot(project.root, project.kind, { bugsOnly: true });
  }
  result.projectId = project.id;
  if (priorScore !== null) {
    result.scoreDelta = result.score - priorScore;
    for (const finding of result.findings) {
      finding.isNew = !priorFindingIds.has(finding.id);
    }
  }
  const history = Array.isArray(project.scanHistory) ? project.scanHistory : [];
  history.unshift({
    id: result.id,
    completedAt: result.completedAt,
    score: result.score,
    filesScanned: result.filesScanned,
    findingsCount: result.findings.length,
    durationMs: result.durationMs,
    severityCounts: result.severityCounts,
  });
  project.scanHistory = history.slice(0, 10);
  project.latestRun = result; await saveProjects(projects);
  // Return static results immediately; AI review runs in the background for local projects.
  if (!isLive) startBackgroundReview(project.id, project.root, result);
  return result;
});
ipc('generate-web-remediation', async (_event, id) => {
  const projects = await readProjects();
  const project = projects.find((p) => p.id === id);
  if (!project) throw new Error('Project not found');
  return generateWebRemediation(project.latestRun || { root: project.root, findings: [] }, project.root);
});
// ---- Background AI review -------------------------------------------------
// Only security-relevant findings are reviewed automatically (local CPU models
// take ~10-60s per finding). Lower severities can still be reviewed on demand.
const AUTO_REVIEW_SEVERITIES = new Set(['critical', 'high']);
const AUTO_REVIEW_LIMIT = 15;
const reviewJobs = new Map(); // projectId -> { cancelled, total, done, scanId }
let writeQueue = Promise.resolve();
function withProjects(mutator) {
  writeQueue = writeQueue.then(async () => {
    const fresh = await readProjects();
    const changed = await mutator(fresh);
    if (changed !== false) await saveProjects(fresh);
  }).catch(() => undefined);
  return writeQueue;
}
function broadcast(channel, payload) {
  for (const win of BrowserWindow.getAllWindows?.() || []) {
    if (!win.isDestroyed()) win.webContents.send(channel, payload);
  }
}
function startBackgroundReview(projectId, root, scan) {
  const previous = reviewJobs.get(projectId);
  if (previous) previous.cancelled = true;
  const queue = scan.findings.filter((f) => AUTO_REVIEW_SEVERITIES.has(f.severity)).slice(0, AUTO_REVIEW_LIMIT);
  const job = { cancelled: false, total: queue.length, done: 0, scanId: scan.id };
  reviewJobs.set(projectId, job);
  const progress = (state) => broadcast('ai-review-progress', { projectId, scanId: scan.id, total: job.total, done: job.done, state });
  if (!queue.length) { reviewJobs.delete(projectId); progress('idle'); return; }
  progress('running');
  (async () => {
    const aiCfg = await readAiConfig();
    await reviewFindings(root, queue, {
      provider: aiCfg.provider,
      model: aiCfg.model,
      apiKey: aiCfg.apiKey,
      shouldStop: () => job.cancelled,
      onFinding: async (finding) => {
        if (job.cancelled) return;
        job.done++;
        await withProjects((fresh) => {
          const target = fresh.find((p) => p.id === projectId)?.latestRun;
          if (!target || target.id !== scan.id) return false;
          const stored = target.findings.find((f) => f.id === finding.id);
          if (!stored) return false;
          if (finding.aiAssessment) { stored.aiAssessment = finding.aiAssessment; delete stored.aiReviewError; }
          else if (finding.aiReviewError) { stored.aiReviewError = finding.aiReviewError; }
          return true;
        });
        progress('running');
      },
    });
    if (reviewJobs.get(projectId) === job) reviewJobs.delete(projectId);
    progress(job.cancelled ? 'cancelled' : 'done');
  })().catch(() => { reviewJobs.delete(projectId); progress('done'); });
}
ipc('cancel-ai-review', async (_event, projectId) => {
  const job = reviewJobs.get(projectId);
  if (job) job.cancelled = true;
  return Boolean(job);
});
ipc('ai-review-status', async () => Object.fromEntries([...reviewJobs.entries()].map(([id, j]) => [id, { total: j.total, done: j.done, scanId: j.scanId }])));
ipc('verify-finding', async (_event, payload) => {
  const { projectId, findingId } = payload || {};
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project?.latestRun) throw new Error('Scan this project before verifying a finding.');
  const finding = project.latestRun.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error('Finding is no longer present in the latest scan. Run a fresh scan.');
  const aiCfg = await readAiConfig();
  const assessment = await verifyFinding(project.root, finding, { provider: aiCfg.provider, model: aiCfg.model, apiKey: aiCfg.apiKey });
  await withProjects((fresh) => {
    const stored = fresh.find((p) => p.id === projectId)?.latestRun?.findings.find((f) => f.id === findingId);
    if (!stored) return false;
    stored.aiAssessment = assessment;
    delete stored.aiReviewError;
    return true;
  });
  return assessment;
});
ipc('get-finding-context', async (_event, payload) => {
  const { projectId, findingId } = payload || {};
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project?.latestRun) throw new Error('Scan this project before viewing source context.');
  const finding = project.latestRun.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error('Finding is no longer present in the latest scan.');
  return getSourceContext(project.root, finding.file, finding.line, 6);
});
ipc('check-ai-status', async () => {
  const aiCfg = await readAiConfig();
  return checkAiHealth({ provider: aiCfg.provider, model: aiCfg.model, apiKey: aiCfg.apiKey });
});
ipc('get-ai-config', async () => publicAiConfig(await readAiConfig()));
ipc('connect-codex', async () => {
  await connectCodexBrowser();
  const [current, codexModels] = await Promise.all([readAiConfig(), getAvailableCodexModels()]);
  const next = { ...current, provider: 'cloud-codex', model: codexModels.includes(current.model) ? current.model : codexModels[0], apiKey: current.apiKey };
  await saveAiConfig(next);
  return { config: await publicAiConfig(next), health: await checkAiHealth(next) };
});
ipc('disconnect-codex', async () => {
  await disconnectCodex();
  const current = await readAiConfig();
  return { config: await publicAiConfig(current), health: await checkAiHealth(current) };
});
ipc('connect-provider', async (_event, providerId) => {
  const provider = isCloudProvider(providerId) ? providerId : 'cloud-codex';
  await connectProvider(provider);
  const [current, models] = await Promise.all([readAiConfig(), getAvailableProviderModels(provider)]);
  const next = { ...current, provider, model: models.includes(current.model) ? current.model : models[0], apiKey: current.apiKey };
  await saveAiConfig(next);
  return { config: await publicAiConfig(next), health: await checkAiHealth(next) };
});
ipc('disconnect-provider', async (_event, providerId) => {
  const provider = isCloudProvider(providerId) ? providerId : 'cloud-codex';
  await disconnectProvider(provider);
  const current = await readAiConfig();
  return { config: await publicAiConfig(current), health: await checkAiHealth(current) };
});
ipc('save-ai-config', async (_event, payload) => {
  const current = await readAiConfig();
  const provider = isCloudProvider(payload?.provider) ? payload.provider : 'local';
  const cloudModels = isCloudProvider(provider) ? await getAvailableProviderModels(provider) : [];
  const defaultModel = isCloudProvider(provider) ? cloudModels[0] : LIGHTEST_CODING_MODEL;
  const model = String(payload?.model || defaultModel).trim();
  const nextKey = typeof payload?.apiKey === 'string' && payload.apiKey.trim()
    ? payload.apiKey.trim()
    : (payload?.clearApiKey ? '' : current.apiKey);
  const nextCategories = Array.isArray(payload?.selectedCategories)
    ? payload.selectedCategories.filter((c) => kinds.includes(c))
    : current.selectedCategories;
  const next = {
    ...current,
    provider,
    model,
    apiKey: nextKey,
    selectedCategories: nextCategories,
  };
  await saveAiConfig(next);
  return { config: await publicAiConfig(next), health: await checkAiHealth(next) };
});
ipc('complete-onboarding-setup', async (_event, payload) => {
  const current = await readAiConfig();
  const provider = isCloudProvider(payload?.provider) ? payload.provider : 'local';
  const cloudModels = isCloudProvider(provider) ? await getAvailableProviderModels(provider) : [];
  const defaultModel = isCloudProvider(provider) ? cloudModels[0] : LIGHTEST_CODING_MODEL;
  const model = String(payload?.model || defaultModel).trim();
  const nextKey = typeof payload?.apiKey === 'string' && payload.apiKey.trim()
    ? payload.apiKey.trim()
    : current.apiKey;
  const chosenCategories = Array.isArray(payload?.selectedCategories)
    ? payload.selectedCategories.filter((c) => kinds.includes(c))
    : [];
  const selectedCategories = chosenCategories.length > 0 ? chosenCategories : [...kinds];

  let localModelPullStarted = false;
  if (provider === 'local') {
    // Only when Local is chosen: auto-install Ollama if missing, then pull the ultra-lightweight coding model.
    try {
      const ollamaBin = await ensureOllamaBinary();
      if (ollamaBin) {
        const child = spawn(ollamaBin, ['pull', model], { detached: true, stdio: 'ignore', windowsHide: true });
        child.on('error', (err) => { void err; });
        child.unref();
        localModelPullStarted = true;
      }
    } catch (err) {
      void err;
    }
  }

  const next = {
    provider,
    model,
    apiKey: nextKey,
    setupCompleted: true,
    selectedCategories,
    localModelInstalled: provider === 'local',
  };
  await saveAiConfig(next);
  return {
    config: await publicAiConfig(next),
    health: await checkAiHealth(next),
    localModelPullStarted,
    installedCategories: selectedCategories,
  };
});
ipc('generate-finding-fix', async (_event, payload) => {
  const { projectId, findingId } = payload || {};
  const aiCfg = await readAiConfig();
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project?.latestRun) throw new Error('Scan this project before fixing a finding.');
  const finding = project.latestRun.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error('Finding is no longer present in the latest scan.');
  return generateFindingFix(project.root, finding, { provider: aiCfg.provider, model: aiCfg.model, apiKey: aiCfg.apiKey });
});
ipc('apply-finding-fix', async (_event, payload) => {
  const { projectId, findingId, file, target, replacement, verifyCommand } = payload || {};
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project) throw new Error('Project not found');
  const res = await applyFindingFix(project.root, file, target, replacement, { verifyCommand });
  if (res.applied) {
    await withProjects((fresh) => {
      const stored = fresh.find((p) => p.id === projectId)?.latestRun?.findings.find((f) => f.id === findingId);
      if (!stored) return false;
      stored.fixed = true;
      return true;
    });
  }
  return res;
});
ipc('fix-all-findings', async (_event, payload) => {
  const { projectId } = payload || {};
  const aiCfg = await readAiConfig();
  if (!isCloudProvider(aiCfg.provider)) {
    throw new Error('Switch to a Cloud AI provider (Claude, Codex, OpenCode, or Pi) in Settings to use Fix all with AI.');
  }
  const projects = await readProjects();
  const project = projects.find((item) => item.id === projectId);
  if (!project?.latestRun) throw new Error('Scan this project before fixing findings.');
  const queue = project.latestRun.findings
    .filter((f) => !f.fixed && ['critical', 'high', 'medium'].includes(f.severity));
  const byFile = new Map();
  for (const finding of queue) {
    const key = finding.file || '';
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key).push(finding);
  }
  const fileGroups = [...byFile.values()];
  const concurrency = Math.min(6, Math.max(1, fileGroups.length));
  const fixedIds = new Set();
  let cursor = 0;
  let done = 0;
  let fixed = 0;
  let failed = 0;
  broadcast('fix-all-progress', { projectId, total: queue.length, done: 0, fixed: 0, failed: 0, currentTitle: queue[0]?.title || '', state: 'running' });

  const worker = async () => {
    while (cursor < fileGroups.length) {
      const group = fileGroups[cursor++];
      const fileRel = group[0]?.file || '';
      const handledIds = new Set();
      if (group.length > 1) {
        for (let offset = 0; offset < group.length; offset += 12) {
          const slice = group.slice(offset, offset + 12);
          try {
            const patches = await generateFileBatchFixes(project.root, fileRel, slice, { provider: aiCfg.provider, model: aiCfg.model, apiKey: aiCfg.apiKey });
            for (const patch of patches) {
              let applied = false;
              try {
                await applyFindingFix(project.root, patch.file, patch.target, patch.replacement);
                applied = true;
              } catch {
                applied = false;
              }
              if (applied) {
                fixed++;
                fixedIds.add(patch.findingId);
                handledIds.add(patch.findingId);
                done++;
                broadcast('fix-all-progress', { projectId, total: queue.length, done, fixed, failed, currentTitle: patch.explanation || fileRel, state: 'running' });
              }
            }
          } catch (batchErr) {
            if (batchErr) handledIds.delete('');
          }
        }
      }
      for (const finding of group) {
        if (handledIds.has(finding.id)) continue;
        try {
          const patch = await generateFindingFix(project.root, finding, { provider: aiCfg.provider, model: aiCfg.model, apiKey: aiCfg.apiKey });
          await applyFindingFix(project.root, patch.file, patch.target, patch.replacement);
          fixed++;
          fixedIds.add(finding.id);
        } catch {
          failed++;
        }
        done++;
        broadcast('fix-all-progress', { projectId, total: queue.length, done, fixed, failed, currentTitle: finding.title, state: 'running' });
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  if (fixedIds.size > 0) {
    await withProjects((fresh) => {
      const storedFindings = fresh.find((p) => p.id === projectId)?.latestRun?.findings;
      if (!storedFindings) return false;
      for (const item of storedFindings) {
        if (fixedIds.has(item.id)) item.fixed = true;
      }
      return true;
    });
  }
  broadcast('fix-all-progress', { projectId, total: queue.length, done: queue.length, fixed, failed, currentTitle: '', state: 'done' });
  return { total: queue.length, fixed, failed };
});
ipc('get-system-profile', async () => getSystemProfile());
ipc('start-extreme-test', async (_event, projectId) => {
  const aiCfg = await readAiConfig();
  const pub = await publicAiConfig(aiCfg);
  const isCloudReady = isCloudProvider(aiCfg.provider) && Boolean(pub.connectedByProvider?.[aiCfg.provider] || pub.hasApiKey);
  if (!isCloudReady) {
    throw new Error('Extreme Live Sandbox Test is only unlocked when you connect and use a Cloud AI Provider (e.g. Anthropic Claude, OpenAI Codex, OpenCode, or Pi).');
  }
  const project = (await readProjects()).find((p) => p.id === projectId);
  if (!project) throw new Error('Project not found.');
  return runExtremeTest({
    project,
    BrowserWindow,
    session,
    onEvent: (ev) => broadcast('extreme-test-event', ev),
  });
});
ipc('stop-extreme-test', async (_event, projectId) => stopExtremeTest(projectId));
ipc('start-npc-swarm', async (_event, payload) => {
  const projectId = typeof payload === 'string' ? payload : payload?.projectId;
  const npcCount = typeof payload === 'object' ? (payload?.npcCount || 120) : 120;
  const project = (await readProjects()).find((p) => p.id === projectId);
  if (!project) throw new Error('Project not found.');
  return runNpcSwarmTest(project, { npcCount }, (ev) => broadcast('npc-swarm-event', ev));
});
ipc('stop-npc-swarm', async (_event, projectId) => stopNpcSwarmTest(projectId));
const activeWatchers = new Map(); // projectId -> { watcher, timer }
ipc('scan-project-changed', async (_event, id) => {
  const projects = await readProjects();
  const project = projects.find((item) => item.id === id);
  if (!project) throw new Error('Project not found');
  if (/^https?:\/\//i.test(project.root)) {
    throw new Error('Git diff scan only applies to local project folders.');
  }
  const scan = await scanProjectRoot(project.root, project.kind, { changedOnly: true, bugsOnly: true });
  scan.projectId = id;
  await withProjects((fresh) => {
    const target = fresh.find((p) => p.id === id);
    if (!target) return false;
    target.latestRun = scan;
    return true;
  });
  return scan;
});
ipc('toggle-watch-project', async (_event, id) => {
  if (activeWatchers.has(id)) {
    const cur = activeWatchers.get(id);
    clearTimeout(cur.timer);
    try { cur.watcher.close(); } catch (err) { void err; }
    activeWatchers.delete(id);
    return { watching: false, projectId: id };
  }
  const projects = await readProjects();
  const project = projects.find((item) => item.id === id);
  if (!project || /^https?:\/\//i.test(project.root)) {
    throw new Error('File watch mode is only available for local project folders.');
  }
  const entry = { watcher: null, timer: null, pending: new Set() };
  const watcher = fsSync.watch(project.root, { recursive: true }, (_evType, fileName) => {
    if (!fileName) return;
    const norm = String(fileName).replace(/\\/g, '/');
    if (/(?:^|\/)(?:node_modules|\.git|dist|build|release)\//.test(norm)) return;
    entry.pending.add(norm);
    clearTimeout(entry.timer);
    entry.timer = setTimeout(async () => {
      const files = [...entry.pending];
      entry.pending.clear();
      try {
        const res = await scanProjectRoot(project.root, project.kind, { onlyFiles: files, bugsOnly: true });
        broadcast('watch-scan-update', { projectId: id, files, findingsCount: res.findings.length, score: res.score, durationMs: res.durationMs });
      } catch (err) {
        void err;
      }
    }, 450);
  });
  entry.watcher = watcher;
  activeWatchers.set(id, entry);
  return { watching: true, projectId: id };
});
ipc('vision-status', async () => getLocalVisionStatus(visionModelDir()));
ipc('vision-install', async () => {
  void autoInstallCactusCompute().catch((err) => { void err; });
  return provisionLocalVisionModel(visionModelDir());
});
ipc('vision-analyze', async (_event, imagePath) => analyzeImageLocal(imagePath));
ipc('check-app-updates', async () => checkForAppUpdates());
ipc('download-app-update', async (_event, updateInfo) => {
  const res = await downloadAndLaunchUpdate(updateInfo, (prog) => broadcast('update-download-progress', prog));
  if (res.launched) {
    setTimeout(() => { app.quit(); }, 1200);
  }
  return res;
});
ipc('list-rules', async () => {
  const aiCfg = await readAiConfig();
  const activeCats = Array.isArray(aiCfg.selectedCategories) && aiCfg.selectedCategories.length > 0
    ? aiCfg.selectedCategories
    : Object.keys(categoryRules);
  const catalog = [
    ...shared.map((r) => ({ id: r.id, title: r.title, severity: r.severity, cwe: r.cwe, lang: r.lang, category: 'Shared', hint: r.hint, bad: r.bad, good: r.good })),
    ...Object.entries(categoryRules)
      .filter(([cat]) => activeCats.includes(cat))
      .flatMap(([cat, list]) =>
        list.map((r) => ({ id: r.id, title: r.title, severity: r.severity, cwe: r.cwe, lang: r.lang, category: cat, hint: r.hint, bad: r.bad, good: r.good })),
      ),
  ];
  return { total: catalog.length, categories: ['Shared', ...activeCats], rules: catalog };
});
ipc('export-report', async (_event, payload) => {
  const format = payload?.format || 'sarif';
  const projects = await readProjects();
  const project = payload?.projectId ? projects.find((item) => item.id === payload.projectId) : null;
  const scan = project?.latestRun || {
    completedAt: new Date().toISOString(),
    filesScanned: projects.reduce((sum, p) => sum + (p.latestRun?.filesScanned || 0), 0),
    rulesEvaluated: projects.reduce((sum, p) => sum + (p.latestRun?.rulesEvaluated || 0), 0),
    score: projects.filter((p) => p.latestRun).length
      ? Math.round(projects.reduce((sum, p) => sum + (p.latestRun?.score || 0), 0) / projects.filter((p) => p.latestRun).length)
      : 100,
    findings: projects.flatMap((p) => (p.latestRun?.findings || []).map((f) => ({ ...f, file: `${p.name}/${f.file}` }))),
  };
  const ext = format === 'sarif' ? 'sarif.json' : format === 'markdown' ? 'md' : format === 'html' ? 'html' : 'json';
  const baseName = project ? `${project.name}-osien-probe.${ext}` : `osien-probe-workspace.${ext}`;
  const saveResult = await dialog.showSaveDialog({
    defaultPath: baseName,
    filters: [
      format === 'sarif' ? { name: 'SARIF 2.1.0 Report', extensions: ['json', 'sarif'] }
        : format === 'markdown' ? { name: 'Markdown Report', extensions: ['md'] }
          : format === 'html' ? { name: 'Executive HTML / PDF Report', extensions: ['html'] }
            : { name: 'JSON Report', extensions: ['json'] },
    ],
  });
  if (saveResult.canceled || !saveResult.filePath) return { saved: false, filePath: null };
  const body = format === 'sarif'
    ? JSON.stringify(toSarifReport(scan, project || { name: 'Workspace' }), null, 2)
    : format === 'markdown'
      ? toMarkdownReport(scan, project || { name: 'Workspace' })
      : format === 'html'
        ? toHtmlReport(scan, project || { name: 'Workspace' })
        : JSON.stringify({ project: project ? { name: project.name, root: project.root, kind: project.kind } : null, scan }, null, 2);
  await fs.writeFile(saveResult.filePath, body, 'utf8');
  return { saved: true, filePath: saveResult.filePath };
});
ipc('run-project-tests', async (_event, id) => {
  const projects = await readProjects(); const project = projects.find(p => p.id === id); if (!project?.latestRun?.testCommand) throw new Error('No supported project test command was detected.');
  const command = project.latestRun.testCommand;
  const exec = (file, args) => execFileAsync(file, args, { cwd: project.root, timeout: 10 * 60 * 1000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  try {
    const runNpm = (args) => process.platform === 'win32'
      ? exec(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', ['npm', ...args].join(' ')])
      : exec('npm', args);
    const result = command === 'npm test'
      ? await runNpm(['test'])
      : command === 'python -m pytest'
        ? await exec(process.platform === 'win32' ? 'python' : 'python3', ['-m', 'pytest'])
        : command === 'cargo test'
          ? await exec('cargo', ['test'])
          : await exec('go', ['test', './...']);
    project.latestRun.testResult = { command, exitCode: 0, output: `${result.stdout}\n${result.stderr}`.trim().slice(-50000) };
  } catch (error) { project.latestRun.testResult = { command, exitCode: error.code ?? 1, output: `${error.stdout || ''}\n${error.stderr || error.message}`.trim().slice(-50000) }; }
  await saveProjects(projects); return project.latestRun.testResult;
});
ipc('run-project-test-file', async (_event, payload) => {
  const projects = await readProjects();
  const project = projects.find((item) => item.id === payload?.projectId);
  const run = project?.latestRun;
  if (!run) throw new Error('Scan this project before running its test files.');
  const target = run.testFiles?.find((item) => item.file === payload?.file);
  if (!target || !['node', 'npm', 'pytest', 'go', 'cargo'].includes(target.runner)) throw new Error('That file is not in the detected test plan.');

  const root = await fs.realpath(project.root);
  const relative = path.normalize(target.file);
  if (path.isAbsolute(relative) || relative.split(path.sep).includes('..') || (target.runner === 'npm' && !/^[\w .\\/-]+$/.test(target.file))) {
    throw new Error('The detected test path is not safe to execute.');
  }
  const fullPath = await fs.realpath(path.resolve(root, relative));
  if (!isInside(root, fullPath) || !(await fs.stat(fullPath)).isFile()) throw new Error('The detected test file is outside the project or no longer exists.');

  const startedAt = Date.now();
  const options = { cwd: root, timeout: 10 * 60 * 1000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 };
  let result;
  try {
    let output;
    if (target.runner === 'node') {
      output = await execFileAsync(process.execPath, ['--test', relative], {
        ...options,
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      });
    } else if (target.runner === 'pytest') {
      output = await execFileAsync(process.platform === 'win32' ? 'python' : 'python3', ['-m', 'pytest', relative], options);
    } else if (target.runner === 'npm') {
      output = process.platform === 'win32'
        ? await execFileAsync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `npm test -- "${target.file}"`], options)
        : await execFileAsync('npm', ['test', '--', target.file], options);
    } else if (target.runner === 'cargo') {
      if (!/^tests[\\/][\w.-]+\.rs$/i.test(target.file)) throw new Error('Cargo target path is invalid.');
      output = await execFileAsync('cargo', ['test', '--test', path.basename(target.file, '.rs')], options);
    } else {
      if (!Array.isArray(target.names) || !target.names.length || target.names.some((name) => !/^(?:Test|Example|Fuzz)[A-Za-z0-9_]*$/.test(name))) {
        throw new Error('Go test names are invalid.');
      }
      const packagePath = `./${path.posix.dirname(target.file)}`.replace(/\/\.$/, '');
      const filter = `^(?:${target.names.join('|')})$`;
      output = await execFileAsync('go', ['test', packagePath, '-run', filter], options);
    }
    result = { file: target.file, command: target.command, exitCode: 0, output: `${output.stdout}\n${output.stderr}`.trim().slice(-50000), durationMs: Date.now() - startedAt };
  } catch (error) {
    result = { file: target.file, command: target.command, exitCode: error.code ?? 1, output: `${error.stdout || ''}\n${error.stderr || error.message}`.trim().slice(-50000), durationMs: Date.now() - startedAt };
  }

  const results = run.testResults || (run.testResults = []);
  const prior = results.findIndex((item) => item.file === result.file);
  if (prior >= 0) results.splice(prior, 1);
  results.push(result);
  await saveProjects(projects);
  return result;
});

module.exports = { scanProjectRoot, kinds };
