'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { scanProjectRoot } = require('../electron/scanner.cjs');
const { generateFileBatchFixes } = require('../electron/ai-review.cjs');

test('Nexus · cross-file taint, race, TOCTOU & route auth', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-cross-'));
  try {
    await fs.writeFile(path.join(dir, 'db.js'), [
      'const fs = require("node:fs");',
      'function readAsset(filePath) {',
      '  return fs.readFileSync(filePath, "utf8");',
      '}',
      'async function saveAudit(entry) {',
      '  return Promise.resolve(entry);',
      '}',
      'module.exports = { readAsset, saveAudit };',
    ].join('\n'));

    await fs.writeFile(path.join(dir, 'routes.js'), [
      'const fs = require("node:fs");',
      'const { readAsset, saveAudit } = require("./db");',
      'let cachedCount = 0;',
      'async function bumpCount() {',
      '  const before = cachedCount;',
      '  await Promise.resolve(before);',
      '  cachedCount = before + 1;',
      '}',
      'function handleRoutes(router, requireAuth) {',
      '  router.get("/api/items", requireAuth, (req, res) => res.json([]));',
      '  router.post("/api/items", requireAuth, (req, res) => {',
      '    saveAudit(req.body.user_id);',
      '    const data = readAsset(req.query.name);',
      '    if (fs.existsSync(req.query.alt)) {',
      '      return res.send(fs.readFileSync(req.query.alt, "utf8"));',
      '    }',
      '    res.send(data);',
      '  });',
      '  router.delete("/api/items/:id", (req, res) => res.json({ deleted: true }));',
      '}',
      'module.exports = { bumpCount, handleRoutes };',
    ].join('\n'));

    await fs.writeFile(path.join(dir, 'client.js'), [
      'export async function createItem(userId) {',
      '  return fetch("/api/items", {',
      '    method: "POST",',
      '    body: JSON.stringify({ userId }),',
      '  });',
      '}',
    ].join('\n'));

    const res = await scanProjectRoot(dir, 'API / backend');
    const ruleIds = new Set(res.findings.map((f) => f.ruleId));

    assert.ok(ruleIds.has('js-crossfile-taint'), `Expected js-crossfile-taint, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-crossfile-unawaited-async'), `Expected js-crossfile-unawaited-async, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-route-missing-auth'), `Expected js-route-missing-auth, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-shared-state-async-race'), `Expected js-shared-state-async-race, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-toctou-fs'), `Expected js-toctou-fs, got: ${[...ruleIds]}`);
    assert.ok(ruleIds.has('js-api-contract-mismatch'), `Expected js-api-contract-mismatch, got: ${[...ruleIds]}`);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Cohortes · batch multi-patch fix generator', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-batch-'));
  try {
    await fs.writeFile(path.join(dir, 'app.js'), 'const a = eval(x);\nconst b = new Function(y);\n', 'utf8');
    const patches = await generateFileBatchFixes(dir, 'app.js', [
      { id: 'f1', line: 1, title: 'eval()', severity: 'high', cwe: 'CWE-95', hint: 'Avoid eval', excerpt: 'const a = eval(x);' },
      { id: 'f2', line: 2, title: 'new Function()', severity: 'high', cwe: 'CWE-95', hint: 'Avoid Function', excerpt: 'const b = new Function(y);' },
    ], {
      provider: 'cloud-codex',
      model: 'gpt-5.1-codex-mini',
      apiKey: 'test-key',
      fetch: async () => ({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                patches: [
                  { findingId: 'f1', explanation: 'Remove eval', target: 'const a = eval(x);', replacement: 'const a = JSON.parse(x);' },
                  { findingId: 'f2', explanation: 'Remove Function', target: 'const b = new Function(y);', replacement: 'const b = () => y;' },
                ],
              }),
            },
          }],
        }),
      }),
    });
    assert.equal(patches.length, 2);
    assert.equal(patches[0].findingId, 'f1');
    assert.equal(patches[1].findingId, 'f2');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Odysseia · alias taint, IDOR, CFG & bugsOnly mode', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-nextlevel-'));
  try {
    await fs.mkdir(path.join(dir, 'src', 'db'), { recursive: true });
    await fs.mkdir(path.join(dir, 'src', 'services'), { recursive: true });
    await fs.writeFile(path.join(dir, 'tsconfig.json'), JSON.stringify({
      compilerOptions: { paths: { '@/*': ['src/*'] } },
    }));
    await fs.writeFile(path.join(dir, 'src', 'db', 'fsRepo.ts'), [
      'import fs from "node:fs";',
      'export function loadRaw(p: string) { return fs.readFileSync(p, "utf8"); }',
    ].join('\n'));
    await fs.writeFile(path.join(dir, 'src', 'services', 'itemService.ts'), [
      'import { loadRaw } from "@/db/fsRepo";',
      'export function readItemFile(name: string) { return loadRaw(name); }',
    ].join('\n'));
    await fs.writeFile(path.join(dir, 'src', 'handler.ts'), [
      'import fs from "node:fs/promises";',
      'import { readItemFile } from "@/services/itemService";',
      'export async function handle(req: any, res: any, user: any, db: any, router: any, requireAuth: any) {',
      '  if (!user) { console.error("no user"); }',
      '  const id = user.id;',
      '  const fh = await fs.open(id, "r");',
      '  await fh.readFile();',
      '  router.delete("/api/posts/:id", requireAuth, (r: any, s: any) => db.posts.delete({ where: { id: r.params.id } }));',
      '  return res.send(readItemFile(req.query.path));',
      '}',
    ].join('\n'));
    await fs.writeFile(path.join(dir, 'src', 'Widget.tsx'), [
      'import { useEffect } from "react";',
      'export function Widget() {',
      '  useEffect(() => { window.addEventListener("resize", () => {}); }, []);',
      '  return null;',
      '}',
    ].join('\n'));
    await fs.writeFile(path.join(dir, 'src', 'style.css'), '.a { color: red !important; }\n');
    await fs.writeFile(path.join(dir, 'src', 'worker.py'), [
      'def add_item(item, bucket=[]):',
      '    bucket.append(item)',
      '    try:',
      '        return bucket',
      '    except:',
      '        pass',
    ].join('\n'));
    await fs.writeFile(path.join(dir, 'src', 'main.go'), [
      'package main',
      'import "os"',
      'func readAll(paths []string) {',
      '    for _, p := range paths {',
      '        f, _ := os.Open(p)',
      '        defer f.Close()',
      '    }',
      '}',
    ].join('\n'));

    const full = await scanProjectRoot(dir, 'API / backend');
    const ids = new Set(full.findings.map((f) => f.ruleId));
    assert.ok(ids.has('js-crossfile-taint'), `Expected multi-hop js-crossfile-taint, got: ${[...ids]}`);
    assert.ok(ids.has('js-idor-missing-ownership'), `Expected js-idor-missing-ownership, got: ${[...ids]}`);
    assert.ok(ids.has('js-unguarded-null-deref'), `Expected js-unguarded-null-deref, got: ${[...ids]}`);
    assert.ok(ids.has('js-resource-leak'), `Expected js-resource-leak, got: ${[...ids]}`);
    assert.ok(ids.has('js-react-effect-leak'), `Expected js-react-effect-leak, got: ${[...ids]}`);
    assert.ok(ids.has('py-mutable-default') || ids.has('polyglot-python-mutable-default'), `Expected Python mutable default rule, got: ${[...ids]}`);
    assert.ok(ids.has('py-bare-except') || ids.has('polyglot-python-bare-except'), `Expected Python bare except rule, got: ${[...ids]}`);
    assert.ok(ids.has('css-important'), 'Expected css-important in default scan');

    const bugsOnly = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
    const bugOnlyIds = new Set(bugsOnly.findings.map((f) => f.ruleId));
    assert.ok(!bugOnlyIds.has('css-important'), 'Expected css-important excluded in bugsOnly mode');
    assert.ok(bugOnlyIds.has('js-crossfile-taint'), 'Expected real bugs preserved in bugsOnly mode');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
