'use strict';
const { contextBridge, ipcRenderer, webUtils } = require('electron');
contextBridge.exposeInMainWorld('deepcheck', {
  getPathForFile: (file) => (webUtils?.getPathForFile ? webUtils.getPathForFile(file) : file?.path || ''),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  listProjects: () => ipcRenderer.invoke('list-projects'),
  addProject: (payload) => ipcRenderer.invoke('add-project', payload),
  cloneRepo: (payload) => ipcRenderer.invoke('clone-repo', payload),
  removeProject: (id) => ipcRenderer.invoke('remove-project', id),
  openProject: (id) => ipcRenderer.invoke('open-project', id),
  openDataFolder: () => ipcRenderer.invoke('open-data-folder'),
  scanProject: (id) => ipcRenderer.invoke('scan-project', id),
  scanProjectChanged: (id) => ipcRenderer.invoke('scan-project-changed', id),
  toggleWatchProject: (id) => ipcRenderer.invoke('toggle-watch-project', id),
  onWatchScanUpdate: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('watch-scan-update', listener);
    return () => ipcRenderer.removeListener('watch-scan-update', listener);
  },
  generateWebRemediation: (id) => ipcRenderer.invoke('generate-web-remediation', id),
  verifyFinding: (payload) => ipcRenderer.invoke('verify-finding', payload),
  getFindingContext: (payload) => ipcRenderer.invoke('get-finding-context', payload),
  checkAiStatus: () => ipcRenderer.invoke('check-ai-status'),
  getAiConfig: () => ipcRenderer.invoke('get-ai-config'),
  saveAiConfig: (payload) => ipcRenderer.invoke('save-ai-config', payload),
  completeOnboardingSetup: (payload) => ipcRenderer.invoke('complete-onboarding-setup', payload),
  connectCodex: () => ipcRenderer.invoke('connect-codex'),
  disconnectCodex: () => ipcRenderer.invoke('disconnect-codex'),
  connectProvider: (provider) => ipcRenderer.invoke('connect-provider', provider),
  disconnectProvider: (provider) => ipcRenderer.invoke('disconnect-provider', provider),
  generateFindingFix: (payload) => ipcRenderer.invoke('generate-finding-fix', payload),
  applyFindingFix: (payload) => ipcRenderer.invoke('apply-finding-fix', payload),
  fixAllFindings: (payload) => ipcRenderer.invoke('fix-all-findings', payload),
  onFixAllProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('fix-all-progress', listener);
    return () => ipcRenderer.removeListener('fix-all-progress', listener);
  },
  listRules: () => ipcRenderer.invoke('list-rules'),
  getSystemProfile: () => ipcRenderer.invoke('get-system-profile'),
  startExtremeTest: (projectId) => ipcRenderer.invoke('start-extreme-test', projectId),
  stopExtremeTest: (projectId) => ipcRenderer.invoke('stop-extreme-test', projectId),
  onExtremeTestEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('extreme-test-event', listener);
    return () => ipcRenderer.removeListener('extreme-test-event', listener);
  },
  startNpcSwarm: (payload) => ipcRenderer.invoke('start-npc-swarm', payload),
  stopNpcSwarm: (projectId) => ipcRenderer.invoke('stop-npc-swarm', projectId),
  onNpcSwarmEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('npc-swarm-event', listener);
    return () => ipcRenderer.removeListener('npc-swarm-event', listener);
  },
  getVisionStatus: () => ipcRenderer.invoke('vision-status'),
  installVisionModel: () => ipcRenderer.invoke('vision-install'),
  analyzeImageVision: (imagePath) => ipcRenderer.invoke('vision-analyze', imagePath),
  checkAppUpdates: () => ipcRenderer.invoke('check-app-updates'),
  downloadAppUpdate: (info) => ipcRenderer.invoke('download-app-update', info),
  onUpdateProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('update-download-progress', listener);
    return () => ipcRenderer.removeListener('update-download-progress', listener);
  },
  scanGitHistory: (payload) => ipcRenderer.invoke('scan-git-history', payload),
  auditSupplyChain: (projectId) => ipcRenderer.invoke('audit-supply-chain', projectId),
  exportSbom: (projectId) => ipcRenderer.invoke('export-sbom', projectId),
  getPreCommitHookStatus: (projectId) => ipcRenderer.invoke('get-precommit-hook-status', projectId),
  togglePreCommitHook: (projectId) => ipcRenderer.invoke('toggle-precommit-hook', projectId),
  exportReport: (payload) => ipcRenderer.invoke('export-report', payload),
  runProjectTests: (id) => ipcRenderer.invoke('run-project-tests', id),
  runProjectTestFile: (payload) => ipcRenderer.invoke('run-project-test-file', payload),
  cancelAiReview: (projectId) => ipcRenderer.invoke('cancel-ai-review', projectId),
  aiReviewStatus: () => ipcRenderer.invoke('ai-review-status'),
  onAiReviewProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('ai-review-progress', listener);
    return () => ipcRenderer.removeListener('ai-review-progress', listener);
  },
});
