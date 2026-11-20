'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('deepcheck', {
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  listProjects: () => ipcRenderer.invoke('list-projects'),
  addProject: (payload) => ipcRenderer.invoke('add-project', payload),
  cloneRepo: (payload) => ipcRenderer.invoke('clone-repo', payload),
  removeProject: (id) => ipcRenderer.invoke('remove-project', id),
  openProject: (id) => ipcRenderer.invoke('open-project', id),
  openDataFolder: () => ipcRenderer.invoke('open-data-folder'),
  scanProject: (id) => ipcRenderer.invoke('scan-project', id),
  generateWebRemediation: (id) => ipcRenderer.invoke('generate-web-remediation', id),
  verifyFinding: (payload) => ipcRenderer.invoke('verify-finding', payload),
  getFindingContext: (payload) => ipcRenderer.invoke('get-finding-context', payload),
  checkAiStatus: () => ipcRenderer.invoke('check-ai-status'),
  getAiConfig: () => ipcRenderer.invoke('get-ai-config'),
  saveAiConfig: (payload) => ipcRenderer.invoke('save-ai-config', payload),
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
