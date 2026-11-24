'use strict';

const {
  detectWebEntry,
  startStaticSandboxServer,
  startNpmSandboxServer,
} = require('./extreme-tester.cjs');

const activeNpcRuns = new Map();

const PERSONA_WEIGHTS = [
  { key: 'browser', label: 'Normal Browser', pct: 0.25 },
  { key: 'rage-multi-clicker', label: 'Rage Multi-Clicker (6x Rapid)', pct: 0.18 },
  { key: 'chaotic-user', label: 'Chaotic / Wrong-Input User', pct: 0.16 },
  { key: 'high-iq-hacker', label: 'High-IQ Red-Team Hacker', pct: 0.16 },
  { key: 'burst-bot', label: 'Burst Spike Bot', pct: 0.12 },
  { key: 'fuzzer', label: 'Edge-Case & Unicode Fuzzer', pct: 0.08 },
  { key: 'slow-mobile', label: 'Slow / Aborting Mobile', pct: 0.05 },
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSIEN-NPC/1.0 Chrome/131.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) OSIEN-NPC/1.0 Mobile/15E148',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) OSIEN-NPC/1.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) OSIEN-NPC/1.0 Firefox/132.0',
];

const STACK_TRACE_RE = /(?:at\s+[A-Za-z0-9_$.]+\s+\([^)]+:\d+:\d+\)|TypeError:|ReferenceError:|SyntaxError:|SQLITE_ERROR|ECONNREFUSED|Traceback \(most recent call last\)|UnhandledPromiseRejection|FATAL ERROR|You have an error in your SQL syntax|MongoServerError)/;
const FUZZ_XSS_MARKER = 'osienNpcProbe7391';
const FUZZ_PAYLOADS = [
  { label: 'xss-probe', query: `?q=<script>${FUZZ_XSS_MARKER}</script>`, body: { input: `<img src=x onerror=${FUZZ_XSS_MARKER}>`, name: 'NPC' } },
  { label: 'unicode-rtl', query: '?q=%E2%80%AE%F0%9F%94%A5%00', body: { input: '👾\u202Ertl-test\u0000', count: -999999 } },
  { label: 'oversized-json', query: `?q=${'A'.repeat(512)}`, body: { input: 'X'.repeat(4096), nested: { a: { b: { c: true } } } } },
  { label: 'empty-malformed', query: '?id=', body: {} },
];

const CHAOTIC_CASES = [
  { label: 'negative-quantity-price', rawJson: false, body: { qty: -100, quantity: -50, amount: -999.99, price: -42 } },
  { label: 'wrong-primitive-types', rawJson: false, body: { qty: 'ten-items', amount: 'free', age: 'twenty', items: 'not-an-array', userId: { nested: null } } },
  { label: 'truncated-corrupt-json', rawJson: true, body: '{"qty": 1, "unclosed": [1, 2, ' },
  { label: 'null-nan-fields', rawJson: false, body: { id: null, name: '', email: '@@@invalid-email', page: -1, limit: 0 } },
];

const PROTO_KEY = ['__pro', 'to__'].join('');
const HACKER_ATTACKS = [
  {
    kind: 'proto-mass-assign',
    label: 'Prototype Pollution & Mass Assignment',
    query: `?${PROTO_KEY}[isAdmin]=true&role=admin`,
    headers: {},
    body: {
      [PROTO_KEY]: { isAdmin: true, role: 'admin' },
      constructor: { prototype: { isAdmin: true } },
      role: 'admin',
      isAdmin: true,
      balance: 9999999,
    },
  },
  {
    kind: 'jwt-none-bypass',
    label: 'Forged alg:none JWT & Header Bypass',
    query: '',
    headers: {
      Authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaXNBZG1pbiI6dHJ1ZX0.',
      'X-Original-URL': '/admin',
      'X-Rewrite-URL': '/admin',
      'X-Custom-IP-Authorization': '127.0.0.1',
    },
    body: { action: 'admin_probe' },
  },
  {
    kind: 'sqli-nosqli',
    label: 'SQLi & NoSQL Operator Injection',
    query: "?id=1' OR '1'='1&user[$ne]=null",
    headers: {},
    body: {
      email: { $ne: null },
      password: { $gt: '' },
      username: "admin' OR '1'='1' --",
    },
  },
  {
    kind: 'path-traversal',
    label: 'Path Traversal & LFI Probe',
    query: '?file=../../../../etc/passwd&path=..%2F..%2Fpackage.json',
    headers: {},
    body: { file: '../../../../etc/passwd', template: '../../package.json' },
  },
  {
    kind: 'ssrf-open-redirect',
    label: 'SSRF Metadata & Open Redirect Probe',
    query: '?url=http://169.254.169.254/latest/meta-data/&redirect=https://evil-npc.test&next=//evil-npc.test',
    headers: { Host: 'evil-npc.test' },
    body: { webhookUrl: 'http://169.254.169.254/latest/meta-data/', callback: 'http://127.0.0.1:22/' },
  },
];

function createNpcRoster(npcCount = 120) {
  const total = Math.max(10, Math.min(1000, Math.round(Number(npcCount) || 120)));
  const npcs = [];
  for (let i = 0; i < total; i++) {
    const ratio = i / total;
    let acc = 0;
    let persona = PERSONA_WEIGHTS[0];
    for (const p of PERSONA_WEIGHTS) {
      acc += p.pct;
      if (ratio < acc) {
        persona = p;
        break;
      }
    }
    const octet3 = (Math.floor(i / 250) % 250) + 1;
    const octet4 = (i % 250) + 1;
    npcs.push({
      id: `npc-${String(i + 1).padStart(3, '0')}`,
      index: i,
      persona: persona.key,
      personaLabel: persona.label,
      ip: `10.200.${octet3}.${octet4}`,
      userAgent: USER_AGENTS[i % USER_AGENTS.length],
    });
  }
  return npcs;
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Math.round(sorted[idx]);
}

function makeNpcFinding({ id, title, severity, cwe, url, hint, reason, excerpt }) {
  return {
    id: `${url}:1:${id}`,
    ruleId: id,
    title,
    severity,
    cwe,
    confidence: 'high',
    file: url,
    line: 1,
    hint,
    reason,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

async function timedFetch(url, options = {}) {
  const timeoutMs = options.timeoutMs || 5000;
  const ctrl = new AbortController();
  const externalSignal = options.signal;
  const onExternalAbort = () => ctrl.abort();
  if (externalSignal) {
    if (externalSignal.aborted) ctrl.abort();
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const start = performance.now();
  try {
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers: options.headers || {},
      body: options.body,
      redirect: options.redirect || 'follow',
      signal: ctrl.signal,
    });
    const text = await res.text();
    const ms = performance.now() - start;
    return { ok: true, status: res.status, headers: res.headers, text, ms };
  } catch (err) {
    const ms = performance.now() - start;
    return {
      ok: false,
      status: 0,
      aborted: err?.name === 'AbortError',
      error: err?.message || 'Request failed',
      text: '',
      ms,
    };
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
  }
}

async function discoverTargetSurface(baseUrl, signal) {
  const origin = new URL(baseUrl).origin;
  const wsOrigin = origin.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');
  const pages = new Set([baseUrl]);
  const apiEndpoints = new Set();
  const wsEndpoints = new Set();
  const forms = [];

  const home = await timedFetch(baseUrl, { signal, timeoutMs: 6000 });
  if (home.ok && home.text) {
    const html = home.text;
    for (const m of html.matchAll(/<a\b[^>]*href=["']([^"'#]+)["']/gi)) {
      try {
        const u = new URL(m[1], baseUrl);
        if (u.origin === origin && pages.size < 8) pages.add(u.href);
      } catch (err) {
        void err;
      }
    }
    for (const m of html.matchAll(/<form\b([^>]*)>/gi)) {
      const attrs = m[1] || '';
      const actionM = attrs.match(/\baction=["']([^"']*)["']/i);
      const methodM = attrs.match(/\bmethod=["']([^"']*)["']/i);
      try {
        const actionUrl = new URL(actionM ? actionM[1] : baseUrl, baseUrl);
        if (actionUrl.origin === origin) {
          forms.push({
            url: actionUrl.href,
            method: (methodM ? methodM[1] : 'POST').toUpperCase(),
          });
        }
      } catch (err) {
        void err;
      }
    }
    for (const m of html.matchAll(/["'`](\/(?:api|v1|v2|trpc|auth|graphql)(?:\/[a-zA-Z0-9_/?=&.-]*)?)["'`]/g)) {
      try {
        apiEndpoints.add(new URL(m[1], origin).href);
      } catch (err) {
        void err;
      }
    }
    for (const m of html.matchAll(/["'`]((?:wss?:\/\/[^"'`\s]+)|\/(?:ws|websocket|realtime|socket)(?:\/[a-zA-Z0-9_/?=&.-]*)?)["'`]/gi)) {
      try {
        const rawWs = m[1];
        const wsUrl = /^wss?:\/\//i.test(rawWs) ? rawWs : `${wsOrigin}${rawWs}`;
        if (new URL(wsUrl).origin === wsOrigin) wsEndpoints.add(wsUrl);
      } catch (err) {
        void err;
      }
    }

    // Stage 2: Deep SPA JS-bundle crawler — fetches referenced same-origin JS bundles
    // so client-rendered React/Vite/Next/Vue API routes and GraphQL/tRPC endpoints are discovered.
    const scriptUrls = [];
    for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi)) {
      try {
        const su = new URL(m[1], baseUrl);
        if (su.origin === origin && scriptUrls.length < 6 && !scriptUrls.includes(su.href)) {
          scriptUrls.push(su.href);
        }
      } catch (err) {
        void err;
      }
    }
    if (scriptUrls.length > 0) {
      const bundles = await Promise.all(scriptUrls.map((u) => timedFetch(u, { signal, timeoutMs: 4000 })));
      for (const b of bundles) {
        if (!b.ok || !b.text) continue;
        const jsText = b.text.slice(0, 350000);
        for (const m of jsText.matchAll(/["'`](\/(?:api|v1|v2|trpc|auth|graphql)(?:\/[a-zA-Z0-9_/?=&.-]*)?)["'`]/g)) {
          try {
            if (apiEndpoints.size < 24) apiEndpoints.add(new URL(m[1], origin).href);
          } catch (err) {
            void err;
          }
        }
        for (const m of jsText.matchAll(/\bpath\s*:\s*["'](\/[a-zA-Z0-9_-]{2,40})["']/g)) {
          try {
            if (pages.size < 12) pages.add(new URL(m[1], origin).href);
          } catch (err) {
            void err;
          }
        }
        for (const m of jsText.matchAll(/["'`]((?:wss?:\/\/[^"'`\s]+)|\/(?:ws|websocket|realtime|socket)(?:\/[a-zA-Z0-9_/?=&.-]*)?)["'`]/gi)) {
          try {
            const rawWs = m[1];
            const wsUrl = /^wss?:\/\//i.test(rawWs) ? rawWs : `${wsOrigin}${rawWs}`;
            if (new URL(wsUrl).origin === wsOrigin && wsEndpoints.size < 6) wsEndpoints.add(wsUrl);
          } catch (err) {
            void err;
          }
        }
      }
    }
  }

  return {
    origin,
    pages: [...pages],
    apiEndpoints: [...apiEndpoints],
    wsEndpoints: [...wsEndpoints],
    forms,
  };
}

async function runWebSocketNpcWave(wsUrl, npcCount, signal, emit = () => {}, addFinding = () => {}) {
  const WS = globalThis.WebSocket;
  if (typeof WS !== 'function' || signal?.aborted) {
    return { supported: false, connected: 0, failed: 0, messagesSent: 0, messagesReceived: 0 };
  }
  const totalSockets = Math.max(4, Math.min(100, Number(npcCount) || 40));
  let connected = 0;
  let failed = 0;
  let messagesSent = 0;
  let messagesReceived = 0;
  let errorLeakSeen = false;

  emit('log', { level: 'info', text: `Launching ${totalSockets} concurrent WebSocket NPCs against ${wsUrl}...` });

  const openOne = (idx) => new Promise((resolve) => {
    if (signal?.aborted) { resolve(); return; }
    let settled = false;
    let opened = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };

    let ws;
    try {
      ws = new WS(wsUrl);
    } catch (err) {
      void err;
      failed++;
      finish();
      return;
    }

    const timer = setTimeout(() => {
      if (!opened) failed++;
      try { ws.close(); } catch (err) { void err; }
      finish();
    }, 2200);

    ws.addEventListener('open', () => {
      opened = true;
      connected++;
      try {
        if (idx % 4 === 0) {
          ws.send('{"broken_ws_json": [1, 2, ');
        } else if (idx % 4 === 1) {
          ws.send(JSON.stringify({ type: 'chat', npcId: `ws-npc-${idx}`, text: 'A'.repeat(1024) }));
        } else {
          ws.send(JSON.stringify({ type: 'ping', npcId: `ws-npc-${idx}`, ts: Date.now() }));
        }
        messagesSent++;
      } catch (err) {
        void err;
      }
      setTimeout(() => {
        try { ws.close(1000, 'npc-done'); } catch (err) { void err; }
        finish();
      }, 180);
    });

    ws.addEventListener('message', (ev) => {
      messagesReceived++;
      const text = typeof ev.data === 'string' ? ev.data : '';
      if (text && STACK_TRACE_RE.test(text) && !errorLeakSeen) {
        errorLeakSeen = true;
        addFinding(makeNpcFinding({
          id: 'npc-websocket-error-leak',
          title: 'WebSocket server leaked internal stack trace / runtime error to connected NPCs',
          severity: 'high',
          cwe: 'CWE-209',
          url: wsUrl,
          hint: 'Wrap WebSocket message JSON.parse/handlers in try-catch and return sanitized error codes only.',
          reason: `Concurrent WebSocket NPC received raw stack/exception text from ${wsUrl}.`,
          excerpt: text.match(STACK_TRACE_RE)?.[0] || text.slice(0, 120),
        }));
      }
    });

    ws.addEventListener('error', () => {
      if (!opened) failed++;
      finish();
    });

    ws.addEventListener('close', () => {
      finish();
    });
  });

  const ids = Array.from({ length: totalSockets }, (_, i) => i);
  await runPool(ids, Math.min(25, totalSockets), signal || { aborted: false }, openOne);

  if (failed > 0 && failed / totalSockets >= 0.25) {
    addFinding(makeNpcFinding({
      id: 'npc-websocket-drop-under-load',
      title: `WebSocket server dropped/rejected ${failed}/${totalSockets} concurrent NPC connections`,
      severity: 'high',
      cwe: 'CWE-400',
      url: wsUrl,
      hint: 'Check WebSocket maxPayload, connection backlog, heartbeat timeouts, and event-loop blocking under concurrent sockets.',
      reason: `${Math.round((failed / totalSockets) * 100)}% of concurrent WebSocket NPCs failed to connect or dropped abnormally.`,
      excerpt: `ws=${wsUrl} connected=${connected} failed=${failed}`,
    }));
  }

  return { supported: true, connected, failed, messagesSent, messagesReceived };
}

function extractSessionAuth(res) {
  let cookie = '';
  let bearer = '';
  let userId = null;
  let resourceUrl = '';
  if (res?.headers) {
    const rawCookie = typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie().join('; ')
      : (res.headers.get('set-cookie') || '');
    if (rawCookie) {
      cookie = rawCookie.split(',').map((c) => c.split(';')[0].trim()).filter(Boolean).join('; ');
    }
  }
  if (res?.text) {
    try {
      const data = JSON.parse(res.text);
      const tok = data.token || data.accessToken || data.jwt || data.sessionToken;
      if (typeof tok === 'string' && tok.length > 4) bearer = tok;
      const uid = data.userId ?? data.id ?? data.user?.id ?? data.account?.id;
      if (uid !== undefined && uid !== null) userId = String(uid);
      if (typeof data.resourceUrl === 'string') resourceUrl = data.resourceUrl;
    } catch (err) {
      void err;
    }
  }
  return { cookie, bearer, userId, resourceUrl };
}

async function runStatefulAuthJourney(baseUrl, surface, signal, recordResult, addFinding) {
  if (signal.aborted) return;
  const authNpcA = { id: 'npc-auth-alice', persona: 'high-iq-hacker', personaLabel: 'Stateful Session Chainer' };
  const authNpcB = { id: 'npc-auth-bob', persona: 'high-iq-hacker', personaLabel: 'Stateful Session Chainer' };

  const authCandidates = surface.apiEndpoints.filter((u) => /register|signup|login|signin|auth|session|users/i.test(u));
  if (authCandidates.length === 0) return;
  const authUrl = authCandidates.find((u) => /register|signup|login|signin|auth|session/i.test(u)) || authCandidates[0];

  const loginUser = async (npc, username, email) => {
    const res = await timedFetch(authUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-NPC-Id': npc.id },
      body: JSON.stringify({ username, email, password: 'NpcTestPass!99' }),
      signal,
    });
    recordResult(npc, res);
    return { res, auth: extractSessionAuth(res) };
  };

  const [alice, bob] = await Promise.all([
    loginUser(authNpcA, 'alice_npc', 'alice@npc.osien.test'),
    loginUser(authNpcB, 'bob_npc', 'bob@npc.osien.test'),
  ]);

  const aliceHeaders = { 'X-NPC-Id': authNpcA.id };
  if (alice.auth.cookie) aliceHeaders.Cookie = alice.auth.cookie;
  if (alice.auth.bearer) aliceHeaders.Authorization = `Bearer ${alice.auth.bearer}`;
  const hasAliceSession = Boolean(alice.auth.cookie || alice.auth.bearer);

  // 1. Authenticated Cross-User Horizontal IDOR: Alice uses her real session to access Bob's resource
  const bobId = bob.auth.userId || '2';
  const userBase = surface.apiEndpoints.find((u) => /\/users\b|\/profile\b|\/account\b|\/orders\b/i.test(u));
  if (hasAliceSession && userBase) {
    const cleanBase = userBase.replace(/\/\d+$/, '');
    const bobTargetUrl = bob.auth.resourceUrl
      ? new URL(bob.auth.resourceUrl, surface.origin).href
      : `${cleanBase}/${bobId}`;
    const idorRes = await timedFetch(bobTargetUrl, {
      method: 'GET',
      headers: aliceHeaders,
      signal,
    });
    recordResult(authNpcA, idorRes);
    if (
      idorRes.ok
      && idorRes.status === 200
      && (/bob@npc\.osien\.test|bob_npc/i.test(idorRes.text) || (bob.auth.userId && idorRes.text.includes(`"id":${bob.auth.userId}`)))
    ) {
      addFinding(makeNpcFinding({
        id: 'npc-authenticated-horizontal-idor',
        title: 'Authenticated horizontal IDOR: User A session accessed User B private record',
        severity: 'critical',
        cwe: 'CWE-639',
        url: bobTargetUrl,
        hint: 'Verify that the authenticated session owner (req.user.id) matches the requested resource owner ID on every read/write.',
        reason: `Stateful session chainer logged in as alice_npc and used Alice's session token/cookie to read bob_npc's private resource at ${bobTargetUrl}.`,
        excerpt: `GET ${bobTargetUrl} (as alice_npc) -> 200 ${idorRes.text.slice(0, 100)}`,
      }));
    }
  }

  // 2. Multi-Step Stateful Checkout / Workflow Price Tampering
  const checkoutUrl = surface.apiEndpoints.find((u) => /checkout|order|payment|cart|purchase/i.test(u))
    || surface.forms[0]?.url;
  if (checkoutUrl) {
    const tamperRes = await timedFetch(checkoutUrl, {
      method: 'POST',
      headers: { ...aliceHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        step: 'confirm',
        itemId: 'pro-plan',
        qty: 1,
        price: 0,
        total: 0,
        discountPercent: 100,
        status: 'paid',
      }),
      signal,
    });
    recordResult(authNpcA, tamperRes);
    if (
      tamperRes.ok
      && tamperRes.status === 200
      && /"(?:total|amountPaid|finalPrice|price)"\s*:\s*0\b|"discountPercent"\s*:\s*100\b/i.test(tamperRes.text)
    ) {
      addFinding(makeNpcFinding({
        id: 'npc-stateful-workflow-tamper',
        title: 'Stateful checkout workflow accepted client-tampered zero price / 100% discount',
        severity: 'high',
        cwe: 'CWE-840',
        url: checkoutUrl,
        hint: 'Recompute item prices, discounts, and order totals strictly on the server from authoritative catalog records.',
        reason: `Stateful session chainer submitted price=0 / discountPercent=100 during checkout confirmation and received a 200 zero-cost confirmation.`,
        excerpt: `POST ${checkoutUrl} {price:0, discountPercent:100} -> 200 ${tamperRes.text.slice(0, 100)}`,
      }));
    }
  }
}

async function resolveTargetUrl(project, emit) {
  const root = String(project?.root || '').trim();
  if (/^https?:\/\//i.test(root)) {
    return { url: root, server: null };
  }
  const entry = await detectWebEntry(root);
  if (entry.mode === 'missing-deps') {
    throw new Error('node_modules is missing for this local project. Install dependencies first or test a live URL.');
  }
  if (entry.mode === 'npm') {
    emit('log', { level: 'info', text: `Booting local app server (${entry.command}) for NPC swarm...` });
    const server = await startNpmSandboxServer(root, entry.scriptName);
    return { url: server.url, server };
  }
  emit('log', { level: 'info', text: `Booting static sandbox server from ${entry.entryDir}...` });
  const server = await startStaticSandboxServer(entry.entryDir);
  return { url: server.url, server };
}

async function runPool(items, concurrency, signal, workerFn) {
  let idx = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    while (idx < items.length && !signal.aborted) {
      const cur = items[idx++];
      await workerFn(cur);
    }
  });
  await Promise.all(runners);
}

async function runNpcSwarmTest(project, options = {}, onEvent = () => {}) {
  const projectId = project?.id || project?.root || 'npc-target';
  if (activeNpcRuns.has(projectId)) {
    throw new Error('An NPC Swarm test is already running for this target.');
  }

  const npcCount = Math.max(10, Math.min(1000, Number(options.npcCount) || 120));
  const concurrency = Math.max(4, Math.min(48, Number(options.concurrency) || 32));
  const ctrl = new AbortController();
  const state = { cancelled: false, ctrl, server: null };
  activeNpcRuns.set(projectId, state);

  const emit = (type, payload = {}) => {
    try {
      onEvent({ projectId, type, ...payload });
    } catch (err) {
      void err;
    }
  };

  const startedAt = Date.now();
  const latencies = [];
  const findingsMap = new Map();
  const addFinding = (f) => {
    const key = `${f.ruleId}:${f.file}`;
    if (!findingsMap.has(key)) {
      findingsMap.set(key, f);
      emit('finding', { finding: f });
    }
  };

  const stats = {
    totalNpcs: npcCount,
    completedNpcs: 0,
    totalRequests: 0,
    ok2xx3xx: 0,
    status4xx: 0,
    status429: 0,
    status5xx: 0,
    timeouts: 0,
    p50Ms: 0,
    p95Ms: 0,
    p99Ms: 0,
    rps: 0,
    findings: 0,
  };

  const personaCounts = {};
  for (const p of PERSONA_WEIGHTS) personaCounts[p.key] = { label: p.label, npcs: 0, requests: 0, errors: 0 };

  try {
    const resolved = await resolveTargetUrl(project, emit);
    state.server = resolved.server;
    const baseUrl = resolved.url;
    emit('started', { projectName: project?.name || baseUrl, targetUrl: baseUrl, npcCount });
    emit('log', { level: 'info', text: `Discovering routes, forms, and API surface at ${baseUrl}...` });

    const surface = await discoverTargetSurface(baseUrl, ctrl.signal);
    const roster = createNpcRoster(npcCount);
    emit('log', {
      level: 'info',
      text: `Deploying ${roster.length} NPCs across ${PERSONA_WEIGHTS.length} personas (normal, 6x rage-clickers, chaotic users, high-IQ hackers, burst bots, fuzzers, slow mobile)...`,
    });

    const recordResult = (npc, res) => {
      stats.totalRequests++;
      personaCounts[npc.persona].requests++;
      latencies.push(res.ms);
      if (!res.ok) {
        stats.timeouts++;
        if (!res.aborted || npc.persona !== 'slow-mobile') {
          personaCounts[npc.persona].errors++;
        }
      } else if (res.status >= 500) {
        stats.status5xx++;
        personaCounts[npc.persona].errors++;
      } else if (res.status === 429) {
        stats.status429++;
      } else if (res.status >= 400) {
        stats.status4xx++;
      } else {
        stats.ok2xx3xx++;
      }

      if (res.ok && res.text && STACK_TRACE_RE.test(res.text)) {
        addFinding(makeNpcFinding({
          id: 'npc-stack-trace-leak',
          title: 'Internal stack trace or database error leaked under NPC load/attack',
          severity: 'high',
          cwe: 'CWE-209',
          url: baseUrl,
          hint: 'Return generic error responses in production and log stack traces server-side only.',
          reason: `NPC ${npc.id} (${npc.personaLabel}) triggered an error response exposing internal stack/runtime details.`,
          excerpt: res.text.match(STACK_TRACE_RE)?.[0] || 'Stack trace in response',
        }));
      }
    };

    const mutationTargets = [
      ...surface.forms,
      ...surface.apiEndpoints.map((u) => ({ url: u, method: 'POST' })),
    ];

    // Run Stateful Two-User Session Chaining (Register/Login -> Cookie/JWT capture -> Horizontal IDOR & Checkout Tampering)
    await runStatefulAuthJourney(baseUrl, surface, ctrl.signal, recordResult, addFinding);

    // Run Concurrent WebSocket NPC Wave if any ws:// / wss:// / /ws endpoints were discovered
    let wsSummary = null;
    if (surface.wsEndpoints && surface.wsEndpoints.length > 0 && !ctrl.signal.aborted) {
      wsSummary = await runWebSocketNpcWave(surface.wsEndpoints[0], Math.min(npcCount, 60), ctrl.signal, emit, addFinding);
    }

    await runPool(roster, concurrency, ctrl.signal, async (npc) => {
      if (state.cancelled || ctrl.signal.aborted) return;
      personaCounts[npc.persona].npcs++;
      const headers = {
        'User-Agent': npc.userAgent,
        'X-Forwarded-For': npc.ip,
        'X-NPC-Id': npc.id,
        'X-NPC-Persona': npc.persona,
      };
      const pageUrl = surface.pages[npc.index % surface.pages.length];

      if (npc.persona === 'browser') {
        const res = await timedFetch(pageUrl, { headers, signal: ctrl.signal });
        recordResult(npc, res);
      } else if (npc.persona === 'rage-multi-clicker') {
        // Simulates an impatient user mashing a submit/buy button 5x simultaneously
        const target = mutationTargets.length > 0
          ? mutationTargets[npc.index % mutationTargets.length]
          : { url: pageUrl, method: 'POST' };
        const reqOpts = {
          method: target.method,
          headers: { ...headers, 'Content-Type': 'application/json', 'X-Idempotency-Key': `rage-${npc.id}` },
          body: target.method === 'GET' ? undefined : JSON.stringify({ npcId: npc.id, action: 'submit', qty: 1 }),
          signal: ctrl.signal,
        };
        const clicks = await Promise.all([
          timedFetch(target.url, reqOpts),
          timedFetch(target.url, reqOpts),
          timedFetch(target.url, reqOpts),
          timedFetch(target.url, reqOpts),
          timedFetch(target.url, reqOpts),
        ]);
        for (const r of clicks) recordResult(npc, r);
        const statuses = clicks.filter((r) => r.ok).map((r) => r.status);
        const has5xx = statuses.some((s) => s >= 500);
        const nonRateStatuses = statuses.filter((s) => s !== 429 && s !== 409 && s !== 423);
        const hasSuccess = nonRateStatuses.some((s) => s >= 200 && s < 300);
        const hasUnexpectedErr = nonRateStatuses.some((s) => s >= 400);
        if (has5xx || (hasSuccess && hasUnexpectedErr)) {
          addFinding(makeNpcFinding({
            id: 'npc-race-condition-anomaly',
            title: 'Rage multi-click race condition / inconsistent concurrent state',
            severity: 'high',
            cwe: 'CWE-362',
            url: target.url,
            hint: 'Enforce idempotency keys, atomic DB transactions, or row locking on concurrent multi-click submissions.',
            reason: `Rage multi-clicker ${npc.id} fired 5 simultaneous requests and got inconsistent/error statuses [${statuses.join(', ')}].`,
            excerpt: `${target.method} ${target.url} -> [${statuses.join(', ')}]`,
          }));
        }
      } else if (npc.persona === 'chaotic-user') {
        // Simulates a confused/chaotic user entering negative numbers, strings in numeric fields, or broken JSON
        const cCase = CHAOTIC_CASES[npc.index % CHAOTIC_CASES.length];
        const target = mutationTargets.length > 0
          ? mutationTargets[npc.index % mutationTargets.length]
          : { url: surface.apiEndpoints[0] || pageUrl, method: 'POST' };
        const res = await timedFetch(target.url, {
          method: target.method === 'GET' ? 'POST' : target.method,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: cCase.rawJson ? cCase.body : JSON.stringify(cCase.body),
          signal: ctrl.signal,
        });
        recordResult(npc, res);
        if (res.ok && res.status >= 500) {
          addFinding(makeNpcFinding({
            id: 'npc-invalid-type-crash',
            title: `Unhandled 5xx crash when chaotic user submits ${cCase.label}`,
            severity: 'high',
            cwe: 'CWE-20',
            url: target.url,
            hint: 'Validate request JSON syntax and field types/ranges before business logic and return 400/422 on invalid input.',
            reason: `Chaotic user ${npc.id} submitted ${cCase.label} and crashed the endpoint with HTTP ${res.status}.`,
            excerpt: `${cCase.label} -> HTTP ${res.status}`,
          }));
        } else if (
          res.ok
          && res.status === 200
          && cCase.label === 'negative-quantity-price'
          && mutationTargets.length > 0
          && /"ok"\s*:\s*true|"stock"|"balance"|"orderId"|"success"\s*:\s*true/i.test(res.text)
        ) {
          addFinding(makeNpcFinding({
            id: 'npc-negative-value-accepted',
            title: 'Business logic flaw: endpoint accepted negative quantity/amount with 200 OK',
            severity: 'high',
            cwe: 'CWE-840',
            url: target.url,
            hint: 'Reject negative or zero quantities, prices, and transfer amounts at the schema validation boundary.',
            reason: `Chaotic user ${npc.id} submitted negative qty/amount (-100 / -999.99) and received a 200 success payload.`,
            excerpt: `POST ${target.url} {qty:-100, amount:-999.99} -> 200 ${res.text.slice(0, 80)}`,
          }));
        }
      } else if (npc.persona === 'high-iq-hacker') {
        // Simulates a sophisticated attacker probing prototype pollution, JWT alg:none, SQLi/NoSQLi, LFI, CORS, .env, and unauth APIs
        const origin = surface.origin;
        const slot = npc.index % 7;
        if (slot < HACKER_ATTACKS.length) {
          const atk = HACKER_ATTACKS[slot];
          const epIdx = Math.floor(npc.index / 7) % Math.max(1, mutationTargets.length);
          const baseTarget = mutationTargets[epIdx]?.url || surface.apiEndpoints[epIdx] || pageUrl;
          const targetUrl = atk.query ? `${baseTarget}${baseTarget.includes('?') ? '&' : '?'}${atk.query.replace(/^\?/, '')}` : baseTarget;
          const res = await timedFetch(targetUrl, {
            method: surface.apiEndpoints.length || mutationTargets.length ? 'POST' : 'GET',
            headers: { ...headers, ...atk.headers, 'Content-Type': 'application/json' },
            body: surface.apiEndpoints.length || mutationTargets.length ? JSON.stringify(atk.body) : undefined,
            redirect: 'manual',
            signal: ctrl.signal,
          });
          recordResult(npc, res);

          if (atk.kind === 'proto-mass-assign' && res.ok && res.status === 200 && /"isAdmin"\s*:\s*true|"role"\s*:\s*"admin"/i.test(res.text)) {
            addFinding(makeNpcFinding({
              id: 'npc-mass-assignment-escalation',
              title: 'Mass-assignment / prototype pollution privilege escalation accepted',
              severity: 'critical',
              cwe: 'CWE-915',
              url: targetUrl,
              hint: 'Allowlist writable user fields explicitly and strip prototype keys, constructor, role, isAdmin, and balance from request bodies.',
              reason: `High-IQ hacker ${npc.id} injected role:admin/prototype fields and received admin confirmation in response.`,
              excerpt: res.text.slice(0, 140),
            }));
          }
          if (atk.kind === 'path-traversal' && res.ok && res.status === 200 && (/root:x:0:0:/i.test(res.text) || /"dependencies"\s*:\s*\{/.test(res.text))) {
            addFinding(makeNpcFinding({
              id: 'npc-path-traversal-leak',
              title: 'Path traversal / LFI exposed sensitive local file contents',
              severity: 'critical',
              cwe: 'CWE-22',
              url: targetUrl,
              hint: 'Resolve paths with path.resolve() and verify they remain inside the allowed base directory.',
              reason: `High-IQ hacker ${npc.id} retrieved system/package file contents via traversal parameters.`,
              excerpt: res.text.slice(0, 140),
            }));
          }
          if (atk.kind === 'ssrf-open-redirect' && res.ok && res.status >= 300 && res.status < 400) {
            const loc = res.headers.get('location') || '';
            if (/evil-npc\.test/i.test(loc)) {
              addFinding(makeNpcFinding({
                id: 'npc-open-redirect',
                title: 'Open redirect to attacker-controlled external domain',
                severity: 'high',
                cwe: 'CWE-601',
                url: targetUrl,
                hint: 'Allow only relative paths starting with a single "/" (not "//") or validate redirect hosts against an allowlist.',
                reason: `High-IQ hacker ${npc.id} triggered a 3xx redirect to ${loc}.`,
                excerpt: `Location: ${loc}`,
              }));
            }
          }
        } else if (slot === 5) {
          const corsRes = await timedFetch(pageUrl, {
            headers: { ...headers, Origin: 'https://evil-npc.test' },
            signal: ctrl.signal,
          });
          recordResult(npc, corsRes);
          if (corsRes.ok && corsRes.headers.get('access-control-allow-origin') === 'https://evil-npc.test') {
            addFinding(makeNpcFinding({
              id: 'npc-cors-reflection',
              title: 'Arbitrary Origin reflected in Access-Control-Allow-Origin',
              severity: 'high',
              cwe: 'CWE-942',
              url: pageUrl,
              hint: 'Validate Origin against an explicit allowlist instead of reflecting arbitrary request origins.',
              reason: `High-IQ hacker ${npc.id} sent Origin: https://evil-npc.test and received matching ACAO header.`,
              excerpt: 'Access-Control-Allow-Origin: https://evil-npc.test',
            }));
          }
        } else {
          const [envRes, apiRes] = await Promise.all([
            timedFetch(`${origin}/.env`, { headers, signal: ctrl.signal }),
            surface.apiEndpoints.length > 0
              ? timedFetch(surface.apiEndpoints[npc.index % surface.apiEndpoints.length], { headers, signal: ctrl.signal })
              : Promise.resolve(null),
          ]);
          recordResult(npc, envRes);
          if (envRes.ok && envRes.status === 200 && /^[A-Z0-9_]{3,}\s*=/m.test(envRes.text)) {
            addFinding(makeNpcFinding({
              id: 'npc-exposed-sensitive-file',
              title: 'Exposed .env secrets file accessible to external attackers',
              severity: 'critical',
              cwe: 'CWE-200',
              url: `${origin}/.env`,
              hint: 'Block dotfiles (.env, .git) at the web server or reverse proxy.',
              reason: `High-IQ hacker ${npc.id} fetched /.env and received key=value environment data.`,
              excerpt: `${origin}/.env -> HTTP 200`,
            }));
          }
          if (apiRes) {
            recordResult(npc, apiRes);
            const apiUrl = surface.apiEndpoints[npc.index % surface.apiEndpoints.length];
            if (apiRes.ok && apiRes.status === 200 && /user|account|admin|order|profile|token/i.test(apiUrl)) {
              addFinding(makeNpcFinding({
                id: 'npc-unauth-api-access',
                title: 'Sensitive API route returned 200 OK without authentication',
                severity: 'high',
                cwe: 'CWE-306',
                url: apiUrl,
                hint: 'Enforce session/JWT authentication middleware on protected API endpoints.',
                reason: `Unauthenticated hacker ${npc.id} received HTTP 200 from ${apiUrl}.`,
                excerpt: `GET ${apiUrl} -> HTTP 200`,
              }));
            }
          }
        }
      } else if (npc.persona === 'burst-bot') {
        const targetUrl = surface.apiEndpoints[0] || pageUrl;
        const burst = await Promise.all([
          timedFetch(targetUrl, { headers, signal: ctrl.signal }),
          timedFetch(targetUrl, { headers, signal: ctrl.signal }),
          timedFetch(targetUrl, { headers, signal: ctrl.signal }),
        ]);
        for (const r of burst) recordResult(npc, r);
      } else if (npc.persona === 'fuzzer') {
        const fuzz = FUZZ_PAYLOADS[npc.index % FUZZ_PAYLOADS.length];
        const targetUrl = surface.apiEndpoints[0] || `${pageUrl}${pageUrl.includes('?') ? '&' : '?'}${fuzz.query.replace(/^\?/, '')}`;
        const res = await timedFetch(targetUrl, {
          method: surface.apiEndpoints.length ? 'POST' : 'GET',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: surface.apiEndpoints.length ? JSON.stringify(fuzz.body) : undefined,
          signal: ctrl.signal,
        });
        recordResult(npc, res);
        if (res.ok && res.status >= 500) {
          addFinding(makeNpcFinding({
            id: 'npc-fuzz-crash',
            title: `Server 5xx crash on edge-case payload (${fuzz.label})`,
            severity: 'high',
            cwe: 'CWE-20',
            url: targetUrl,
            hint: 'Validate and sanitize input schema/types before processing and catch malformed edge cases with 400 Bad Request.',
            reason: `Fuzzer ${npc.id} triggered HTTP ${res.status} with ${fuzz.label}.`,
            excerpt: `Payload=${fuzz.label} -> HTTP ${res.status}`,
          }));
        }
        if (res.ok && res.text && fuzz.label === 'xss-probe' && res.text.includes(`<script>${FUZZ_XSS_MARKER}</script>`)) {
          addFinding(makeNpcFinding({
            id: 'npc-xss-reflection',
            title: 'Unescaped XSS payload reflected in HTML response under NPC fuzzing',
            severity: 'critical',
            cwe: 'CWE-79',
            url: targetUrl,
            hint: 'HTML-escape all reflected query/form parameters and enforce a strict Content-Security-Policy.',
            reason: `Fuzzer ${npc.id} sent a script probe and found it reflected unescaped in the response body.`,
            excerpt: `<script>${FUZZ_XSS_MARKER}</script>`,
          }));
        }
      } else {
        // slow-mobile: tight timeout simulating flaky mobile drop-offs
        const res = await timedFetch(pageUrl, { headers, signal: ctrl.signal, timeoutMs: 220 });
        recordResult(npc, res);
      }

      stats.completedNpcs++;
      if (stats.completedNpcs % 10 === 0 || stats.completedNpcs === roster.length) {
        const sorted = [...latencies].sort((a, b) => a - b);
        const elapsedSec = Math.max(0.1, (Date.now() - startedAt) / 1000);
        stats.p50Ms = percentile(sorted, 50);
        stats.p95Ms = percentile(sorted, 95);
        stats.p99Ms = percentile(sorted, 99);
        stats.rps = Math.round((stats.totalRequests / elapsedSec) * 10) / 10;
        stats.findings = findingsMap.size;
        emit('progress', { stats: { ...stats }, personaCounts });
      }
    });

    const sorted = [...latencies].sort((a, b) => a - b);
    const elapsedSec = Math.max(0.1, (Date.now() - startedAt) / 1000);
    stats.p50Ms = percentile(sorted, 50);
    stats.p95Ms = percentile(sorted, 95);
    stats.p99Ms = percentile(sorted, 99);
    stats.rps = Math.round((stats.totalRequests / elapsedSec) * 10) / 10;

    if (stats.status5xx > 0) {
      addFinding(makeNpcFinding({
        id: 'npc-server-5xx-under-load',
        title: `App returned ${stats.status5xx} HTTP 5xx server errors under ${npcCount}-NPC load`,
        severity: 'high',
        cwe: 'CWE-755',
        url: baseUrl,
        hint: 'Inspect server error handlers, database connection pooling, and unhandled promise rejections under concurrent load.',
        reason: `${stats.status5xx} out of ${stats.totalRequests} NPC requests failed with 5xx.`,
        excerpt: `5xx=${stats.status5xx} / total=${stats.totalRequests} (${npcCount} NPCs)`,
      }));
    }
    if (stats.p95Ms >= 1500 || stats.p99Ms >= 3000) {
      addFinding(makeNpcFinding({
        id: 'npc-latency-degradation',
        title: `Severe tail latency under ${npcCount}-NPC load (p95=${stats.p95Ms}ms, p99=${stats.p99Ms}ms)`,
        severity: 'medium',
        cwe: 'CWE-400',
        url: baseUrl,
        hint: 'Add caching, database indexes, pagination, and async queue offloading to prevent tail-latency spikes.',
        reason: `Response times degraded sharply under concurrent NPC traffic.`,
        excerpt: `p50=${stats.p50Ms}ms, p95=${stats.p95Ms}ms, p99=${stats.p99Ms}ms`,
      }));
    }
    if ((surface.apiEndpoints.length > 0 || surface.forms.length > 0) && stats.status429 === 0 && stats.totalRequests >= 100) {
      addFinding(makeNpcFinding({
        id: 'npc-missing-rate-limit',
        title: `No rate limiting (0 HTTP 429 responses) observed across ${stats.totalRequests} rapid NPC requests`,
        severity: 'medium',
        cwe: 'CWE-770',
        url: surface.apiEndpoints[0] || surface.forms[0].url,
        hint: 'Enforce per-IP / per-user rate limiting (e.g. express-rate-limit, Upstash, or reverse-proxy limits) on API and form endpoints.',
        reason: `Burst-bot, rage-clicker, and hacker NPCs sent ${stats.totalRequests} requests without triggering HTTP 429 throttling.`,
        excerpt: `requests=${stats.totalRequests}, 429_responses=0`,
      }));
    }

    stats.findings = findingsMap.size;
    const findings = [...findingsMap.values()];
    const durationMs = Date.now() - startedAt;
    emit('done', { cancelled: state.cancelled, targetUrl: baseUrl, durationMs, stats: { ...stats }, personaCounts, findings });
    return { cancelled: state.cancelled, projectId, targetUrl: baseUrl, npcCount, durationMs, stats, personaCounts, wsSummary, findings };
  } finally {
    if (state.server) {
      try {
        await state.server.close();
      } catch (err) {
        void err;
      }
    }
    activeNpcRuns.delete(projectId);
  }
}

async function stopNpcSwarmTest(projectId) {
  const state = activeNpcRuns.get(projectId);
  if (!state) return false;
  state.cancelled = true;
  state.ctrl.abort();
  if (state.server) {
    try {
      await state.server.close();
    } catch (err) {
      void err;
    }
  }
  activeNpcRuns.delete(projectId);
  return true;
}

module.exports = {
  PERSONA_WEIGHTS,
  createNpcRoster,
  runNpcSwarmTest,
  runWebSocketNpcWave,
  stopNpcSwarmTest,
};
