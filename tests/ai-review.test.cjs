'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { parseVerdict, getSourceContext, verifyFinding, reviewFindings, checkAiHealth, MODEL } = require('../electron/ai-review.cjs');

test('Oraculum · validates JSON verdicts', () => {
  const parsed = parseVerdict(JSON.stringify({ verdict: 'likely_real', confidence: 150, rationale: 'Evidence found', evidence: 'line 2' }));
  assert.equal(parsed.verdict, 'likely_real');
  assert.equal(parsed.confidence, 100);
  assert.equal(parsed.evidence, 'line 2');
  const fractional = parseVerdict('{"verdict":"uncertain","confidence":0.75,"rationale":"Limited context","evidence":["line 1","line 2"]}');
  assert.equal(fractional.confidence, 50);
  assert.equal(fractional.evidence, 'line 1; line 2');
  assert.throws(() => parseVerdict('{"verdict":"maybe","rationale":"x"}'), /unsupported verdict/);
  assert.throws(() => parseVerdict('{"verdict":"uncertain"}'), /no explanation/);
});

test('Terminus · blocks path traversal & symlinks', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-out-'));
  t.after(() => Promise.all([fs.rm(root, { recursive: true, force: true }), fs.rm(outside, { recursive: true, force: true })]));
  await fs.writeFile(path.join(root, 'app.js'), 'one\ntwo\nthree');
  await fs.writeFile(path.join(outside, 'secret.js'), 'secret');
  assert.match((await getSourceContext(root, 'app.js', 2)).context, /2: two/);
  await assert.rejects(getSourceContext(root, path.relative(root, path.join(outside, 'secret.js')), 1), /outside/);
  try {
    await fs.symlink(path.join(outside, 'secret.js'), path.join(root, 'linked.js'));
    await assert.rejects(getSourceContext(root, 'linked.js', 1), /outside/);
  } catch (error) {
    if (error.code !== 'EPERM' && error.code !== 'ENOTSUP') throw error;
  }
});

test('Minerva · local CPU Ollama chat & parse', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'app.js'), 'const value = input;');
  let request;
  const result = await verifyFinding(root, { file: 'app.js', line: 1, title: 'Unsafe input' }, {
    fetch: async (url, init) => {
      request = { url, body: JSON.parse(init.body) };
      return { ok: true, json: async () => ({ message: { content: '{"verdict":"uncertain","confidence":55,"rationale":"Context is limited"}' } }) };
    },
  });
  assert.equal(request.url, 'http://127.0.0.1:11434/api/chat');
  assert.equal(request.body.model, MODEL);
  assert.equal(request.body.options.temperature, 0);
  assert.equal(request.body.think, false);
  assert.equal(result.verdict, 'uncertain');
  assert.equal(result.confidence, 50);
});

test('Vigilia · snippet-only auto AI review', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = Array.from({ length: 20 }, (_, index) => `const line${index + 1} = 1;`);
  source[0] = 'const firstMarker = 1;';
  source[19] = 'const secondMarker = 2;';
  await fs.writeFile(path.join(root, 'app.js'), source.join('\n'));
  const findings = [
    { file: 'app.js', line: 1, title: 'First finding', excerpt: source[0] },
    { file: 'app.js', line: 20, title: 'Second finding', excerpt: source[19] },
  ];
  const requests = [];
  const summary = await reviewFindings(root, findings, {
    fetch: async (_url, init) => {
      const body = JSON.parse(init.body);
      requests.push(body);
      return { ok: true, json: async () => ({ message: { content: '{"verdict":"uncertain","confidence":99,"rationale":"Not confirmed from this snippet."}' } }) };
    },
  });
  assert.deepEqual(summary, { reviewed: 2, failed: 0 });
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.messages.length === 2));
  assert.match(requests[0].messages[1].content, /firstMarker/);
  assert.doesNotMatch(requests[0].messages[1].content, /secondMarker/);
  assert.match(requests[1].messages[1].content, /secondMarker/);
  assert.doesNotMatch(requests[1].messages[1].content, /firstMarker/);
  assert.ok(findings.every((finding) => finding.aiAssessment.confidence === 50));
});

test('Clausura · circuit-breaks when Ollama offline', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-ai-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'app.js'), 'const a = 1;\nconst b = 2;\nconst c = 3;\n');
  const findings = [
    { file: 'app.js', line: 1, title: 'One' },
    { file: 'app.js', line: 2, title: 'Two' },
    { file: 'app.js', line: 3, title: 'Three' },
  ];
  let calls = 0;
  const summary = await reviewFindings(root, findings, {
    fetch: async () => {
      calls++;
      throw new Error('ECONNREFUSED');
    },
  });
  assert.equal(calls, 1, 'stops calling unreachable endpoint after first connection failure');
  assert.deepEqual(summary, { reviewed: 0, failed: 3 });
  assert.ok(findings.every((f) => /Cannot reach Ollama/.test(f.aiReviewError)));
});

test('Salus · reports AI online & model status', async () => {
  const online = await checkAiHealth({
    fetch: async () => ({
      ok: true,
      json: async () => ({ models: [{ name: MODEL }] }),
    }),
  });
  assert.equal(online.available, true);
  assert.equal(online.modelInstalled, true);

  const offline = await checkAiHealth({
    fetch: async () => { throw new Error('offline'); },
  });
  assert.equal(offline.available, false);
  assert.equal(offline.modelInstalled, false);
});

test('Aether · Cloud Codex health & safe patching', async () => {
  const { generateFindingFix, applyFindingFix, CODEX_MODELS } = require('../electron/ai-review.cjs');
  const noKey = await checkAiHealth({ provider: 'cloud-codex', apiKey: '', codexConnected: false });
  assert.equal(noKey.available, false);
  assert.equal(noKey.provider, 'cloud-codex');

  const withKey = await checkAiHealth({ provider: 'cloud-codex', apiKey: 'sk-test-1234', model: CODEX_MODELS[0] });
  assert.equal(withKey.available, true);
  assert.equal(withKey.modelInstalled, true);

  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'osien-codex-fix-'));
  await fs.writeFile(path.join(root, 'app.js'), 'el.innerHTML = userBio;\n', 'utf8');
  const finding = { id: 'f1', title: 'Direct innerHTML', severity: 'high', cwe: 'CWE-79', ruleId: 'js-innerhtml', file: 'app.js', line: 1, excerpt: 'el.innerHTML = userBio;' };

  const patch = await generateFindingFix(root, finding, {
    provider: 'cloud-codex',
    apiKey: 'sk-test-1234',
    model: CODEX_MODELS[0],
    fetch: async (_url, init) => {
      assert.equal(init.headers.authorization, 'Bearer sk-test-1234');
      return {
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                explanation: 'Use textContent to avoid HTML injection.',
                target: 'el.innerHTML = userBio;',
                replacement: 'el.textContent = userBio;',
              }),
            },
          }],
        }),
      };
    },
  });
  assert.equal(patch.replacement, 'el.textContent = userBio;');

  await applyFindingFix(root, 'app.js', patch.target, patch.replacement);
  const updated = await fs.readFile(path.join(root, 'app.js'), 'utf8');
  assert.equal(updated, 'el.textContent = userBio;\n');

  await assert.rejects(() => applyFindingFix(root, '../outside.js', 'a', 'b'), /escapes/);
});

test('Olympus · Claude, OpenCode & Pi fix generation', async () => {
  const { checkAiHealth: checkHealth, generateFindingFix } = require('../electron/ai-review.cjs');
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'deepcheck-providers-'));
  await fs.writeFile(path.join(root, 'app.js'), 'el.innerHTML = userBio;\n', 'utf8');
  const finding = { id: 'f1', title: 'Direct innerHTML', severity: 'high', cwe: 'CWE-79', ruleId: 'js-innerhtml', file: 'app.js', line: 1, excerpt: 'el.innerHTML = userBio;' };

  // 1. Claude (Anthropic Messages API)
  const claudeHealth = await checkHealth({ provider: 'cloud-claude', apiKey: 'sk-ant-test' });
  assert.equal(claudeHealth.available, true);
  assert.equal(claudeHealth.provider, 'cloud-claude');
  const claudePatch = await generateFindingFix(root, finding, {
    provider: 'cloud-claude',
    apiKey: 'sk-ant-test',
    model: 'claude-sonnet-4-5',
    fetch: async (url, init) => {
      assert.ok(url.includes('api.anthropic.com/v1/messages'));
      assert.equal(init.headers['x-api-key'], 'sk-ant-test');
      return {
        ok: true,
        json: async () => ({
          content: [{
            type: 'text',
            text: JSON.stringify({
              explanation: 'Use textContent instead of innerHTML.',
              target: 'el.innerHTML = userBio;',
              replacement: 'el.textContent = userBio;',
            }),
          }],
        }),
      };
    },
  });
  assert.equal(claudePatch.replacement, 'el.textContent = userBio;');

  // 2. OpenCode
  const ocHealth = await checkAiHealth({ provider: 'cloud-opencode', apiKey: 'oc-test' });
  assert.equal(ocHealth.available, true);
  assert.equal(ocHealth.provider, 'cloud-opencode');
  const ocPatch = await generateFindingFix(root, finding, {
    provider: 'cloud-opencode',
    apiKey: 'oc-test',
    model: 'opencode/big-pickle',
    fetch: async (url, init) => {
      assert.ok(url.includes('opencode.ai'));
      assert.equal(init.headers.authorization, 'Bearer oc-test');
      return {
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                explanation: 'Escape output with textContent.',
                target: 'el.innerHTML = userBio;',
                replacement: 'el.textContent = userBio;',
              }),
            },
          }],
        }),
      };
    },
  });
  assert.equal(ocPatch.replacement, 'el.textContent = userBio;');

  // 3. Pi Agent
  const piHealth = await checkAiHealth({ provider: 'cloud-pi', apiKey: 'pi-test' });
  assert.equal(piHealth.available, true);
  assert.equal(piHealth.provider, 'cloud-pi');
  const piPatch = await generateFindingFix(root, finding, {
    provider: 'cloud-pi',
    apiKey: 'pi-test',
    model: 'gpt-5.2-codex',
    fetch: async (_url, init) => {
      assert.equal(init.headers.authorization, 'Bearer pi-test');
      return {
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                explanation: 'Use textContent safely.',
                target: 'el.innerHTML = userBio;',
                replacement: 'el.textContent = userBio;',
              }),
            },
          }],
        }),
      };
    },
  });
  assert.equal(piPatch.replacement, 'el.textContent = userBio;');
});
