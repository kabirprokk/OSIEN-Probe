'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const pkg = require('../package.json');

const REPO_SLUG = 'kabirprokk/OSIEN-Probe';

function compareSemver(a, b) {
  const pa = String(a || '0.0.0').replace(/^v/i, '').split('.').map((n) => Number(n) || 0);
  const pb = String(b || '0.0.0').replace(/^v/i, '').split('.').map((n) => Number(n) || 0);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function pickPlatformAsset(assets = [], platform = process.platform) {
  const list = Array.isArray(assets) ? assets : [];
  if (platform === 'win32') {
    return list.find((a) => /\.exe$/i.test(a.name) && !/blockmap/i.test(a.name)) || null;
  }
  if (platform === 'darwin') {
    return list.find((a) => /\.dmg$/i.test(a.name) && !/blockmap/i.test(a.name)) || null;
  }
  return list.find((a) => /\.AppImage$/i.test(a.name)) || list.find((a) => /\.deb$/i.test(a.name)) || null;
}

async function checkForAppUpdates(currentVersion = pkg.version) {
  const url = `https://api.github.com/repos/${REPO_SLUG}/releases/latest`;
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': `OSIEN-Probe/${currentVersion}`, Accept: 'application/vnd.github+json' },
    });
    if (!res.ok) {
      return { available: false, currentVersion, latestVersion: currentVersion, error: `HTTP ${res.status}` };
    }
    const release = await res.json();
    const latestVersion = String(release.tag_name || currentVersion).replace(/^v/i, '');
    const asset = pickPlatformAsset(release.assets);
    const available = compareSemver(latestVersion, currentVersion) > 0 && Boolean(asset?.browser_download_url);
    return {
      available,
      currentVersion,
      latestVersion,
      releaseUrl: release.html_url || `https://github.com/${REPO_SLUG}/releases/tag/v${latestVersion}`,
      releaseNotes: String(release.body || '').slice(0, 800),
      assetName: asset?.name || '',
      downloadUrl: asset?.browser_download_url || '',
      sizeBytes: Number(asset?.size || 0),
    };
  } catch (err) {
    return { available: false, currentVersion, latestVersion: currentVersion, error: err?.message || 'Offline' };
  }
}

async function downloadAndLaunchUpdate(updateInfo, onProgress = () => {}) {
  if (!updateInfo?.downloadUrl) {
    throw new Error('No downloadable update asset was found for this platform.');
  }
  const res = await fetch(updateInfo.downloadUrl, {
    headers: { 'User-Agent': `OSIEN-Probe/${pkg.version}` },
    redirect: 'follow',
  });
  if (!res.ok || !res.body) {
    throw new Error(`Update download failed (HTTP ${res.status}).`);
  }

  const totalBytes = Number(res.headers.get('content-length')) || updateInfo.sizeBytes || 0;
  const safeName = path.basename(updateInfo.assetName || `OSIEN-Probe-Update-${updateInfo.latestVersion}.exe`).replace(/[^A-Za-z0-9._-]/g, '_');
  const destPath = path.join(os.tmpdir(), safeName);
  const chunks = [];
  let received = 0;

  for await (const chunk of res.body) {
    const buf = Buffer.from(chunk);
    chunks.push(buf);
    received += buf.length;
    const percent = totalBytes > 0 ? Math.min(100, Math.round((received / totalBytes) * 100)) : 0;
    onProgress({ received, totalBytes, percent, state: 'downloading' });
  }

  await fs.writeFile(destPath, Buffer.concat(chunks));
  onProgress({ received, totalBytes: received, percent: 100, state: 'launching', destPath });

  if (process.platform === 'win32') {
    const child = spawn(destPath, [], { detached: true, stdio: 'ignore' });
    child.unref();
  }
  return { launched: true, destPath };
}

module.exports = {
  compareSemver,
  pickPlatformAsset,
  checkForAppUpdates,
  downloadAndLaunchUpdate,
};
