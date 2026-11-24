'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const {
  getSystemProfile,
  detectWebEntry,
  startStaticSandboxServer,
  startNpmSandboxServer,
  stripAnsi,
  buildExtremeProbeScript,
} = require('../electron/extreme-tester.cjs');

test('Mensura · system hardware tier & step budget', () => {
  const profile = getSystemProfile();
  assert.ok(profile.cpuCores >= 1);
  assert.ok(profile.totalMemGb > 0);
  assert.ok(['high', 'balanced', 'light'].includes(profile.tier));
  assert.ok(profile.maxSteps >= 35);
  assert.ok(profile.stepDelayMs >= 140);
});

test('Vestibulum · detects npm dev & static entry', async () => {
  const npmRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-web-npm-'));
  await fs.mkdir(path.join(npmRoot, 'node_modules'));
  await fs.writeFile(path.join(npmRoot, 'package.json'), JSON.stringify({ name: 'site', scripts: { dev: 'vite' } }));
  const npmEntry = await detectWebEntry(npmRoot);
  assert.equal(npmEntry.mode, 'npm');
  assert.equal(npmEntry.scriptName, 'dev');

  const staticRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-web-static-'));
  await fs.writeFile(path.join(staticRoot, 'index.html'), '<h1>Hello</h1>');
  const staticEntry = await detectWebEntry(staticRoot);
  assert.equal(staticEntry.mode, 'static');
  assert.equal(staticEntry.entryFile, 'index.html');
});

test('Portus · static sandbox server on 127.0.0.1', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-sandbox-srv-'));
  await fs.writeFile(path.join(root, 'index.html'), '<!doctype html><h1>Sandbox OK</h1>');
  const srv = await startStaticSandboxServer(root);
  try {
    assert.match(srv.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    const body = await new Promise((resolve, reject) => {
      http.get(srv.url, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, data }));
      }).on('error', reject);
    });
    assert.equal(body.status, 200);
    assert.match(body.data, /Sandbox OK/);
  } finally {
    await srv.close();
  }
});

test('Hasta · builds executable extreme probe script', () => {
  const src = buildExtremeProbeScript(3);
  assert.match(src, /__osien_probe_cursor__/);
  assert.match(src, /data-osien-xss-probe/);
  assert.doesNotThrow(() => new Function(src));
});

test('Navis · npm sandbox server spawn & ANSI strip', async () => {
  assert.equal(stripAnsi('\x1b[36mhttp://localhost:\x1b[1m5173/\x1b[22m\x1b[39m'), 'http://localhost:5173/');
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-npm-srv-'));
  await fs.writeFile(path.join(root, 'server.js'), `
    const http = require('node:http');
    const srv = http.createServer((_req, res) => res.end('ok'));
    srv.listen(0, '127.0.0.1', () => {
      console.log('\\x1b[32mLocal:\\x1b[39m http://localhost:' + srv.address().port + '/');
    });
  `);
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({
    name: 'npm-srv-test',
    scripts: { dev: 'node server.js' },
  }));
  const logs = [];
  const srv = await startNpmSandboxServer(root, 'dev', (line) => logs.push(line));
  try {
    assert.match(srv.url, /^http:\/\/localhost:\d+\/$/);
    assert.ok(logs.some((l) => l.includes('Local:')));
  } finally {
    await srv.close();
  }
});
