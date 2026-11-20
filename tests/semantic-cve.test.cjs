'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { scanProjectRoot } = require('../electron/scanner.cjs');

test('dependency auditor detects vulnerable npm, Python, and Go packages and ignores patched versions', async () => {
  const vulnDir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-dep-vuln-'));
  await fs.writeFile(path.join(vulnDir, 'package.json'), JSON.stringify({
    name: 'vuln-app',
    dependencies: { lodash: '^4.17.19', express: '^4.19.2' },
  }, null, 2));
  await fs.writeFile(path.join(vulnDir, 'requirements.txt'), 'pyyaml==5.3.1\nrequests==2.32.0\n');
  await fs.writeFile(path.join(vulnDir, 'go.mod'), 'module example.com/app\nrequire github.com/dgrijalva/jwt-go v3.2.0\n');

  const report = await scanProjectRoot(vulnDir, 'API / backend');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('dep-npm-lodash-cve'), 'flags lodash < 4.17.21');
  assert.ok(!ids.has('dep-npm-express-cve'), 'does not flag patched express >= 4.19.2');
  assert.ok(ids.has('dep-py-pyyaml-cve'), 'flags PyYAML < 5.4');
  assert.ok(!ids.has('dep-py-requests-cve'), 'does not flag patched requests >= 2.31.0');
  assert.ok(ids.has('dep-go-jwt-go-deprecated'), 'flags deprecated jwt-go');
});

test('semantic polyglot detects Solidity CEI reentrancy, unprotected init, and Python/Go taint', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-sem-'));
  await fs.writeFile(path.join(dir, 'Vault.sol'), [
    'pragma solidity ^0.8.20;',
    'contract Vault {',
    '  mapping(address => uint256) public balances;',
    '  function initialize(address _owner) external { owner = _owner; }',
    '  function withdraw(uint256 amount) external {',
    '    (bool ok, ) = msg.sender.call{value: amount}("");',
    '    require(ok);',
    '    balances[msg.sender] -= amount;',
    '  }',
    '  function safeWithdraw(uint256 amount) external nonReentrant {',
    '    balances[msg.sender] -= amount;',
    '    (bool ok, ) = msg.sender.call{value: amount}("");',
    '    require(ok);',
    '  }',
    '}',
  ].join('\n'));

  await fs.writeFile(path.join(dir, 'app.py'), [
    'def handler(request, cursor):',
    '    uid = request.args.get("id")',
    '    cursor.execute("SELECT * FROM users WHERE id = " + uid)',
  ].join('\n'));

  await fs.writeFile(path.join(dir, 'main.go'), [
    'package main',
    'func handler(r *http.Request, db *sql.DB) {',
    '    q := r.URL.Query().Get("name")',
    '    db.Query("SELECT * FROM users WHERE name = " + q)',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Blockchain / Web3');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('sol-reentrancy-cei'), 'detects Solidity CEI reentrancy');
  assert.ok(ids.has('sol-unprotected-sensitive-fn'), 'detects unprotected initialize()');
  assert.ok(ids.has('py-taint-sink'), 'detects Python request->SQL taint');
  assert.ok(ids.has('go-taint-sink'), 'detects Go request->SQL taint');
  const safeWithdrawFlags = report.findings.filter((f) => f.ruleId === 'sol-reentrancy-cei' && f.line >= 10);
  assert.equal(safeWithdrawFlags.length, 0, 'does not flag nonReentrant safeWithdraw');
});

test('monorepo lockfile CVE audit and Python/Go cross-file taint detection', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-xpoly-'));
  await fs.mkdir(path.join(dir, 'packages', 'web'), { recursive: true });
  await fs.writeFile(path.join(dir, 'packages', 'web', 'package-lock.json'), JSON.stringify({
    packages: { 'node_modules/minimist': { version: '1.2.5' } },
  }));
  await fs.writeFile(path.join(dir, 'Cargo.lock'), '[[package]]\nname = "hyper"\nversion = "0.14.20"\n');
  await fs.writeFile(path.join(dir, 'db_helpers.py'), 'def run_user_query(cursor, q):\n    cursor.execute("SELECT * FROM t WHERE a=" + q)\n');
  await fs.writeFile(path.join(dir, 'routes.py'), 'def endpoint(request, cursor):\n    name = request.args.get("name")\n    run_user_query(cursor, name)\n');
  await fs.writeFile(path.join(dir, 'store.go'), 'package main\nfunc FindUser(db *sql.DB, q string) {\n    db.Query("SELECT * FROM u WHERE n=" + q)\n}\n');
  await fs.writeFile(path.join(dir, 'api.go'), 'package main\nfunc Handle(r *http.Request, db *sql.DB) {\n    name := r.URL.Query().Get("n")\n    FindUser(db, name)\n}\n');

  const report = await scanProjectRoot(dir, 'API / backend');
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('dep-npm-minimist-cve'), 'flags vulnerable minimist in nested monorepo package-lock.json');
  assert.ok(ids.has('dep-rust-hyper-cve'), 'flags vulnerable hyper in Cargo.lock');
  assert.ok(ids.has('py-crossfile-taint'), 'detects Python cross-file taint');
  assert.ok(ids.has('go-crossfile-taint'), 'detects Go cross-file taint');
});

test('real-world false-positive regression guard (JSX attrs, JSON-LD, model.eval, platform.system, .env.local.example)', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-fp-guard-'));
  await fs.writeFile(path.join(dir, '.env.local.example'), 'NEXT_PUBLIC_SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo"\n');
  await fs.writeFile(path.join(dir, 'JsonLd.tsx'), [
    'export function JsonLd({ data }: { data: unknown }) {',
    '  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />;',
    '}',
    'export function InputField({ val }: { val: string }) {',
    '  return <input type="text" value={val} onChange={() => {}} />;',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'ml_check.py'), [
    'import hashlib, platform',
    'GRANT_TYPE_REFRESH_TOKEN = "refresh_token"',
    'sys_name = platform.system().lower()',
    'model.eval()',
    'digest = hashlib.sha256(b"blob %d\\0" % len(b"abc")).hexdigest()',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Website', { bugsOnly: true });
  assert.equal(report.findings.length, 0, `expected 0 false positives, got: ${report.findings.map((f) => `${f.ruleId}:${f.line}`).join(', ')}`);
});

test('deep security detectors: timing-unsafe compare, mass assignment, unawaited !async(), Next.js & Python missing route auth', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-deepsec-'));
  await fs.mkdir(path.join(dir, 'src', 'app', 'api', 'admin'), { recursive: true });
  await fs.writeFile(path.join(dir, 'src', 'app', 'api', 'admin', 'route.ts'), [
    'export async function POST(req: any) {',
    '  const body = req.body;',
    '  await User.create(req.body);',
    '  return Response.json({ ok: true });',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'security.js'), [
    'async function isAdmin(u) { return Boolean(u && u.admin); }',
    'function check(sig, hmac, user) {',
    '  if (sig === hmac) return true;',
    '  if (!isAdmin(user)) return false;',
    '  return false;',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'api.py'), [
    '@app.delete("/items/{item_id}")',
    'def delete_item(item_id: int, db=None):',
    '    db.execute("DELETE FROM items WHERE id=%s", [item_id])',
    '    db.commit()',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('js-timing-unsafe-secret-cmp'), 'detects non-constant-time hmac comparison');
  assert.ok(ids.has('js-promise-in-condition'), 'detects !isAdmin(user) without await');
  assert.ok(ids.has('js-mass-assignment-db'), 'detects User.create(req.body) mass assignment');
  assert.ok(ids.has('js-nextjs-api-no-auth'), 'detects Next.js mutating API route without auth');
  assert.ok(ids.has('py-route-missing-auth'), 'detects Python mutating route without auth');
});

test('Driftpost false-positive regression guard (HMAC .update, guarded cache/name, ternary math, delete obj[p], service_role)', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-driftpost-fp-'));
  await fs.writeFile(path.join(dir, 'webhook.js'), [
    'const expected = crypto.createHmac("sha256", secret).update(req.body).digest("hex");',
    'function load(cache, name) {',
    '  if (!cache) cache = { items: [] };',
    '  const x = cache.items.length;',
    '  if (!name) name = "default";',
    '  if (!name || name.length < 3) return null;',
    '  const v = x >= 1 ? 1 : 1 - Math.pow(1 - x, 2);',
    '  const n = { a: 1 }; targets.forEach((p) => { delete n[p]; });',
    '  return v + n.a;',
    '}',
    'function go(req, res, back) {',
    '  res.redirect(back.origin === req.protocol + "://" + req.get("host") ? back.pathname : "/");',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, '001.sql'), 'grant all on public.items to service_role;\n');

  const report = await scanProjectRoot(dir, 'Website', { bugsOnly: true });
  const fp = report.findings.filter((f) => [
    'js-mass-assignment-db', 'js-unguarded-null-deref', 'exp-logic-duplicate-ternary',
    'exp-logic-delete-array-index', 'js-redirect-param', 'sql-grant-all',
  ].includes(f.ruleId));
  assert.equal(fp.length, 0, `expected 0 false positives, got: ${fp.map((f) => `${f.ruleId}:${f.line}`).join(', ')}`);
});

test('Type-aware + CFG + Router-tree + Reachable Lockfile/OSV + AST Polyglot engine upgrades', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-nextgen-'));
  await fs.writeFile(path.join(dir, 'vault.js'), 'export async function saveVault(v) { return v; }\n');
  await fs.writeFile(path.join(dir, 'app.js'), [
    'import { saveVault } from "./vault.js";',
    'import lodash from "lodash";',
    'export function badCfg(flag) {',
    '  saveVault(1);',
    '  const items = [1, 2, 3];',
    '  delete items[0];',
    '  let rec = null;',
    '  if (!flag) { console.log("warn"); }',
    '  return rec.id;',
    '}',
    'app.use("/api/private", requireAuth);',
    'app.post("/api/private/save", (req, res) => { res.json({ ok: lodash.isArray([]) }); });',
    'app.post("/api/meta/deauthorize", (req, res) => {',
    '  const sig = crypto.createHmac("sha256", secret).update(req.body).digest("hex");',
    '  res.json({ sig });',
    '});',
    'app.get("/api/run", (req, res) => { exec(req.query.cmd); res.end(); });',
  ].join('\n'));

  await fs.writeFile(path.join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.20:\n    resolution: {}\n");
  await fs.writeFile(path.join(dir, 'Contract.sol'), [
    'contract Vault {',
    '  function auth() public view { require(tx.origin == owner); }',
    '  function pay(address payable t) public { t.call{value: 1}(""); }',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'safe.py'), [
    'import shlex, os',
    'def run_safe(request):',
    '  cmd = shlex.quote(request.args.get("x"))',
    '  os.system(cmd)',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('type-floating-promise'), 'detects cross-file floating promise via type inference');
  assert.ok(ids.has('type-delete-array-element'), 'detects delete on typed array');
  assert.ok(ids.has('cfg-null-deref'), 'detects CFG null deref');
  assert.ok(ids.has('js-reachable-unauth-sink'), 'detects reachable unauthenticated sink');
  assert.ok(!ids.has('js-route-missing-auth'), 'recognizes app.use prefix auth and webhook HMAC');
  assert.ok(ids.has('dep-npm-lodash-cve'), 'parses pnpm-lock.yaml');
  const lodashFinding = report.findings.find((f) => f.ruleId === 'dep-npm-lodash-cve');
  assert.equal(lodashFinding?.reachable, true, 'marks imported lodash as reachable');
  assert.ok(ids.has('sol-tx-origin-auth'), 'detects Solidity tx.origin auth');
  assert.ok(ids.has('sol-unchecked-call'), 'detects Solidity unchecked low-level call');
  assert.ok(!ids.has('py-taint-sink'), 'clears Python taint after shlex.quote');
});

test('Real-world gap fixes: YAML comments, .gen.ts skip, ??= return, promise-executor dedupe, nested postMessage origin, and .d.ts Promise indexing', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-realgaps-'));
  await fs.mkdir(path.join(dir, '.github', 'workflows'), { recursive: true });
  await fs.writeFile(path.join(dir, '.github', 'workflows', 'ci.yml'), [
    'on: push',
    '# Note: pull_request_target: is only in this comment',
    'jobs: {}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'sdk.gen.ts'), 'export function f() { return eval("1"); }\n');
  await fs.writeFile(path.join(dir, 'mailer.d.ts'), 'export declare function sendMail(to: string): Promise<void>;\n');
  await fs.writeFile(path.join(dir, 'mailer.js'), 'export function sendMail() { return Promise.resolve(); }\n');
  await fs.writeFile(path.join(dir, 'index.ts'), [
    'import { sendMail } from "./mailer";',
    'export class Client {',
    '  private _sub?: any;',
    '  get sub() { return this._sub ??= {}; }',
    '  notify() { sendMail("a@b.com"); }',
    '}',
    'window.addEventListener("message", (e) => { if (e.data) { if (e.origin !== "https://ok.test") return; } });',
    'export function badPromise() { return new Promise(async (resolve) => { resolve(1); }); }',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Software', { bugsOnly: true });
  const ids = report.findings.map((f) => f.ruleId);
  assert.ok(!ids.includes('exp-yaml-gha-pull-request-target'), 'ignores YAML # comments');
  assert.ok(!ids.includes('yaml-gha-pull-request-target'), 'ignores YAML # comments');
  assert.ok(!report.findings.some((f) => f.file.endsWith('sdk.gen.ts')), 'skips generated .gen.ts files');
  assert.ok(!ids.includes('js-assign-in-return'), 'allows ??= lazy memoization in return');
  assert.ok(!ids.includes('sec-postmessage-no-origin'), 'recognizes nested event.origin guard');
  assert.ok(ids.includes('type-floating-promise'), 'resolves Promise return from .d.ts / module');
  const promiseFindings = report.findings.filter((f) => f.file === 'index.ts' && f.line === 8);
  assert.equal(promiseFindings.length, 1, 'collapses duplicate async-promise-executor rules on same line');
});

test('Expanded framework & polyglot detectors: Next.js Server Actions, SSRF taint, NoSQL injection, Go path traversal, Rust SQL/shell', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-expanded-'));
  await fs.writeFile(path.join(dir, 'actions.ts'), [
    '"use server";',
    'export async function deleteProject(id: string) {',
    '  await prisma.project.delete({ where: { id } });',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'api.js'), [
    'app.post("/api/proxy", async (req, res) => {',
    '  const r = await axios.get(req.body.url);',
    '  const u = await User.findOne(req.body);',
    '  res.json({ r, u });',
    '});',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'handler.go'), [
    'package main',
    'func readDoc(w http.ResponseWriter, r *http.Request) {',
    '  name := r.URL.Query().Get("file")',
    '  data, _ := os.ReadFile("/var/docs/" + name)',
    '  w.Write(data)',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'db.rs'), [
    'pub fn find_user(id: &str) {',
    '  let q = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id));',
    '  Command::new("sh").arg("-c").arg(id);',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('js-server-action-no-auth'), 'detects unauthenticated Next.js Server Action');
  assert.ok(ids.has('js-ssrf-taint') || ids.has('js-ssrf'), 'detects SSRF taint into axios.get(req.body.url)');
  assert.ok(ids.has('js-nosql-injection'), 'detects raw req.body passed to findOne()');
  assert.ok(ids.has('go-path-traversal'), 'detects Go path traversal into os.ReadFile');
  assert.ok(ids.has('rust-sql-format'), 'detects Rust sqlx::query(&format!(...))');
  assert.ok(ids.has('rust-cmd-shell-taint') || ids.has('polyglot-rust-shell'), 'detects Rust Command::new("sh").arg("-c").arg(id)');
});

test('Live Web Auditor checks HTTP headers, cookies, and HTML without data-id or rel-before-target false positives', async () => {
  const http = require('node:http');
  const { scanLiveUrl } = require('../electron/web-auditor.cjs');
  const html = [
    '<!doctype html><html><body>',
    '<a data-id="100" rel="noopener noreferrer" target="_blank" href="https://example.com">Safe</a>',
    '<a data-id="100" href="https://example.com">Also safe</a>',
    '<search role="search"><form method="get" action="/"><input name="q"></form></search>',
    '</body></html>',
  ].join('\n');

  const srv = http.createServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': 'upgrade-insecure-requests',
      'x-powered-by': 'PHP/8.2.35',
      'set-cookie': '_fbp=123; path=/',
    });
    res.end(html);
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = srv.address();
    const report = await scanLiveUrl(`http://127.0.0.1:${port}/`, { bugsOnly: true });
    const ids = new Set(report.findings.map((f) => f.ruleId));
    assert.ok(ids.has('web-weak-csp'), 'detects CSP lacking script-src/default-src');
    assert.ok(ids.has('web-missing-frame-protection'), 'detects missing X-Frame-Options/frame-ancestors');
    assert.ok(ids.has('web-missing-nosniff'), 'detects missing X-Content-Type-Options: nosniff');
    assert.ok(ids.has('web-server-version-leak'), 'detects X-Powered-By header');
    assert.ok(ids.has('web-cookie-no-samesite'), 'detects missing SameSite cookie attribute');
    assert.ok(!ids.has('html-duplicate-id'), 'ignores data-id attributes');
    assert.ok(!ids.has('web-target-blank-no-rel'), 'recognizes rel="noopener" before target="_blank"');
    assert.ok(!ids.has('html-form-get'), 'skips search GET forms in bugsOnly mode');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }
});

test('AST-aware rules eliminate false positives on __proto__ guards and standard window/comparison usage', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ast-noise-'));
  await fs.writeFile(path.join(dir, 'safe.js'), [
    'export function mergeSafe(target, src) {',
    '  for (const key in src) {',
    '    if (key === "__proto__" || key === "constructor") continue;',
    '    if (Object.hasOwn(src, key)) target[key] = src[key];',
    '  }',
    '  if (window.myFlag === true) window.location = "/home";',
    '  window.onload = () => {};',
    '  window.myTemp = undefined;',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'unsafe.js'), [
    'export function bad(target, helper) {',
    '  target.__proto__.admin = true;',
    '  window.myLibHelper = helper;',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Library', { bugsOnly: true });
  const safeFindings = report.findings.filter((f) => f.file === 'safe.js');
  assert.ok(!safeFindings.some((f) => f.ruleId === 'js-prototype-pollution'), 'ignores defensive __proto__ guards');
  assert.ok(!safeFindings.some((f) => f.ruleId === 'lib-global-window-mutation'), 'ignores window comparisons, standard DOM props, and undefined cleanup');

  const unsafeFindings = report.findings.filter((f) => f.file === 'unsafe.js');
  assert.ok(unsafeFindings.some((f) => f.ruleId === 'js-prototype-pollution'), 'still catches actual __proto__ mutation');
  assert.ok(unsafeFindings.some((f) => f.ruleId === 'lib-global-window-mutation'), 'still catches custom window.* global mutation');
});

test('AST-backed interprocedural call graph traces multi-hop taint across Python, Go, and Rust files', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-polyglot-cg-'));
  // Python 2-hop: handler.py -> mid.py -> sink.py
  await fs.writeFile(path.join(dir, 'sink.py'), [
    'def run_query(sql_part):',
    '    cursor.execute("SELECT * FROM t WHERE name = " + sql_part)',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'mid.py'), [
    'def forward_query(val):',
    '    q = val',
    '    return run_query(q)',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'handler.py'), [
    'def endpoint():',
    '    name = request.args.get("name")',
    '    forward_query(name)',
  ].join('\n'));

  // Go 2-hop: handler.go -> mid.go -> sink.go
  await fs.writeFile(path.join(dir, 'sink.go'), [
    'package main',
    'func ExecRaw(q string) {',
    '    db.Exec("SELECT * FROM users WHERE id = " + q)',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'mid.go'), [
    'package main',
    'func ForwardUser(u string) {',
    '    ExecRaw(u)',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'handler.go'), [
    'package main',
    'func UserHandler(w http.ResponseWriter, r *http.Request) {',
    '    id := r.URL.Query().Get("id")',
    '    ForwardUser(id)',
    '}',
  ].join('\n'));

  // Rust cross-file: handler.rs -> db.rs
  await fs.writeFile(path.join(dir, 'db.rs'), [
    'pub fn query_user(name: &str) {',
    '    let q = sqlx::query(&format!("SELECT * FROM users WHERE name = {}", name));',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'handler.rs'), [
    'pub fn handle(req: web::Query<Params>) {',
    '    let name = req.query_string();',
    '    query_user(name);',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('py-crossfile-taint'), 'detects 2-hop Python interprocedural call-graph taint');
  assert.ok(ids.has('go-crossfile-taint'), 'detects 2-hop Go interprocedural call-graph taint');
  assert.ok(ids.has('rust-crossfile-taint'), 'detects Rust interprocedural call-graph taint');
});

test('Expanded Web Auditor detects CORS misconfigurations, Server version, and exposed .git/HEAD & .env', async () => {
  const http = require('node:http');
  const { scanLiveUrl, analyzeHttpHeaders } = require('../electron/web-auditor.cjs');

  // Unit test analyzeHttpHeaders for HTTPS weak HSTS & CORS
  const hdrs = new Headers({
    'strict-transport-security': 'max-age=60',
    'server': 'nginx/1.18.0',
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  const hFindings = analyzeHttpHeaders('https://example.test/', hdrs);
  const hIds = new Set(hFindings.map((f) => f.ruleId));
  assert.ok(hIds.has('web-weak-hsts'), 'detects weak HSTS max-age');
  assert.ok(hIds.has('web-server-header-version'), 'detects Server header version leak');
  assert.ok(hIds.has('web-cors-wildcard-credentials'), 'detects CORS * with credentials');

  const srv = http.createServer((req, res) => {
    if (req.url === '/.git/HEAD') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ref: refs/heads/main\n');
      return;
    }
    if (req.url === '/.env') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('APP_KEY=example_placeholder_value\n');
      return;
    }
    res.writeHead(200, {
      'content-type': 'text/html',
      'access-control-allow-origin': 'null',
    });
    res.end('<!doctype html><html><body>OK</body></html>');
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = srv.address();
    const report = await scanLiveUrl(`http://127.0.0.1:${port}/`, { bugsOnly: true, probeExposedFiles: true });
    const ids = new Set(report.findings.map((f) => f.ruleId));
    assert.ok(ids.has('web-cors-null-origin'), 'detects CORS null origin');
    assert.ok(ids.has('web-exposed-git-head'), 'detects exposed /.git/HEAD');
    assert.ok(ids.has('web-exposed-env-file'), 'detects exposed /.env');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }
});

test('Live Website Fix Generator (generateWebRemediation) and SRI / HttpOnly checks', async () => {
  const http = require('node:http');
  const { scanLiveUrl, generateWebRemediation } = require('../electron/web-auditor.cjs');
  const html = [
    '<!doctype html><html><head>',
    '<script src="https://cdn.example.net/lib.js"></script>',
    '</head><body>Hello</body></html>',
  ].join('\n');

  const srv = http.createServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      'x-powered-by': 'Express',
      'set-cookie': 'session_id=abc123; Path=/',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    });
    res.end(html);
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = srv.address();
    const report = await scanLiveUrl(`http://127.0.0.1:${port}/`, { bugsOnly: true });
    const ids = new Set(report.findings.map((f) => f.ruleId));
    assert.ok(ids.has('web-cookie-no-httponly'), 'detects session cookie missing HttpOnly');
    assert.ok(ids.has('web-missing-sri'), 'detects external script missing SRI');

    const fixPack = generateWebRemediation(report, `https://app.example.com:${port}/`);
    assert.equal(fixPack.url, `https://app.example.com:${port}/`);
    assert.ok(fixPack.issueCount >= 4, 'reports multiple fixable issues');
    assert.ok(fixPack.configs.nginx.includes('proxy_hide_header X-Powered-By;'), 'nginx config hides X-Powered-By');
    assert.ok(fixPack.configs.nginx.includes('proxy_cookie_flags ~ secure httponly samesite=lax;'), 'nginx config hardens cookies');
    assert.ok(fixPack.configs.apache.includes('Header unset X-Powered-By'), 'apache config unsets X-Powered-By');
    assert.ok(fixPack.configs.express.includes("app.disable('x-powered-by')"), 'express config disables x-powered-by');
    assert.ok(fixPack.configs.nextjs.includes('poweredByHeader: false'), 'nextjs config disables poweredByHeader');
    assert.ok(fixPack.configs.vercel.includes('"X-Frame-Options"'), 'vercel config includes X-Frame-Options');
    assert.ok(fixPack.configs.cloudflare.includes("headers.delete('X-Powered-By')"), 'cloudflare worker strips X-Powered-By');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }
});

test('Minified JS skip, CFG loop-shadowing/short-circuit guard, and multi-line Go/Rust AST taint', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-cycle3-'));
  // 1. Minified vendor bundle (>4000 bytes, single long line) should be skipped cleanly
  const minified = 'var a=1;' + 'x=eval("1");'.repeat(400);
  await fs.writeFile(path.join(dir, 'vendor-bundle.js'), minified);

  // 2. CFG loop-shadowing + && short-circuit guard should NOT false-positive
  await fs.writeFile(path.join(dir, 'cfg-safe.ts'), [
    'export function render(items: { offset: { x: number } }[], maybeItem?: { name: string } | null) {',
    '  let item: { offset: { x: number } } | null = null;',
    '  for (const item of items) {',
    '    void item.offset.x;',
    '  }',
    '  if (maybeItem && maybeItem.name.length > 0) {',
    '    return maybeItem.name;',
    '  }',
    '  void item;',
    '  return "";',
    '}',
  ].join('\n'));

  // 3. Multi-line Go & Rust AST taint should be caught
  await fs.writeFile(path.join(dir, 'multi.go'), [
    'package main',
    'func handler(r *http.Request, db *sql.DB) {',
    '  id := r.URL.Query().Get("id")',
    '  db.Query(',
    '    "SELECT * FROM users WHERE id = " + id,',
    '  )',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'multi.rs'), [
    'pub fn run(user_cmd: &str) {',
    '  Command::new("sh")',
    '    .arg("-c")',
    '    .arg(user_cmd);',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'Software', { bugsOnly: true });
  assert.ok(!report.findings.some((f) => f.file === 'vendor-bundle.js'), 'skips minified JS bundles');
  assert.ok(!report.findings.some((f) => f.file === 'cfg-safe.ts' && f.ruleId === 'cfg-null-deref'), 'ignores loop-shadowed vars and && guards in CFG');
  assert.ok(report.findings.some((f) => f.ruleId === 'go-taint-sink'), 'catches multi-line Go AST taint');
  assert.ok(report.findings.some((f) => f.ruleId === 'rust-cmd-shell-taint' || f.ruleId === 'polyglot-rust-shell'), 'catches multi-line Rust AST shell taint');
});

test('Java/PHP AST call graphs, CFG compound || early-return narrowing, and TLS inspector', async () => {
  const { inspectTlsCertificate } = require('../electron/web-auditor.cjs');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-cycle4-'));

  // 1. Java cross-file taint: Controller.java -> Dao.java
  await fs.writeFile(path.join(dir, 'Dao.java'), [
    'class Dao {',
    '  void findByName(String q) {',
    '    stmt.executeQuery("SELECT * FROM users WHERE name = " + q);',
    '  }',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'Controller.java'), [
    'class Controller {',
    '  void handle(HttpServletRequest request, Dao dao) {',
    '    String user = request.getParameter("user");',
    '    dao.findByName(user);',
    '  }',
    '}',
  ].join('\n'));

  // 2. PHP cross-file taint: route.php -> db.php
  await fs.writeFile(path.join(dir, 'db.php'), [
    '<?php',
    'function runLookup($id) {',
    '  mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);',
    '}',
  ].join('\n'));
  await fs.writeFile(path.join(dir, 'route.php'), [
    '<?php',
    'function endpoint() {',
    '  $id = $_GET["id"];',
    '  runLookup($id);',
    '}',
  ].join('\n'));

  // 3. CFG compound || early-return narrowing should NOT flag a or b after `if (!a || !b) return;`
  await fs.writeFile(path.join(dir, 'narrow.ts'), [
    'export function processPair(a?: { id: string } | null, b?: { name: string } | null) {',
    '  if (!a || !b) return "";',
    '  return a.id + ":" + b.name;',
    '}',
  ].join('\n'));

  const report = await scanProjectRoot(dir, 'API / backend', { bugsOnly: true });
  const ids = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ids.has('java-crossfile-taint'), 'detects Java AST call-graph cross-file taint');
  assert.ok(ids.has('php-crossfile-taint'), 'detects PHP AST call-graph cross-file taint');
  assert.ok(!report.findings.some((f) => f.file === 'narrow.ts' && f.ruleId === 'cfg-null-deref'), 'narrows both vars in `if (!a || !b) return;`');

  // 4. TLS inspector returns [] gracefully on http://
  const nonTls = await inspectTlsCertificate('http://127.0.0.1:80/');
  assert.deepEqual(nonTls, []);
});
