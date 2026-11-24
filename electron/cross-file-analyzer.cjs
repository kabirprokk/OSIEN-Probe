'use strict';

const path = require('node:path');
const fs = require('node:fs/promises');
const { parse } = require('@babel/parser');

const REQUEST_TAINT_RE = /(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params|headers|cookies)|searchParams\.|URLSearchParams|location\.(?:search|hash)|event\.target\.value|e\.target\.value)/i;
const SANITIZER_RE = /\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|escapeRegExp|encodeURIComponent|encodeURI|Number|parseInt|parseFloat|Boolean|validator\.escape|path\.basename|pick|omit|isWithin)\s*\(/;
const FILE_SINKS = new Set(['readFile', 'readFileSync', 'createReadStream', 'sendFile', 'download', 'writeFile', 'writeFileSync', 'unlink', 'unlinkSync', 'open', 'openSync', 'copyFile', 'rename']);
const SQL_SINKS = new Set(['query', 'execute', 'raw']);
const SHELL_SINKS = new Set(['exec', 'execSync', 'spawn', 'spawnSync']);
const AUTH_MW_RE = /(?:auth|authenticate|requireAuth|ensureAuth|isAuthenticated|verifyToken|verifySession|checkAuth|protect|requireUser|requireAdmin|jwt)/i;
const PUBLIC_ROUTE_RE = /\/(?:login|signin|sign-in|signup|sign-up|register|auth|oauth|webhook|callback|health|ping|public|reset-password|forgot-password)\b/i;

function parseJsAst(raw, extName) {
  const plugins = ['jsx', 'decorators-legacy', 'classProperties', 'dynamicImport', 'optionalChaining', 'nullishCoalescingOperator', 'topLevelAwait'];
  if (extName === '.ts' || extName === '.tsx') plugins.push('typescript');
  try {
    return parse(raw, { sourceType: 'unambiguous', errorRecovery: true, plugins });
  } catch {
    return null;
  }
}

function walk(node, fn, parent = null) {
  if (!node || typeof node !== 'object') return;
  fn(node, parent);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) {
        if (item && typeof item.type === 'string') walk(item, fn, node);
      }
    } else if (val && typeof val.type === 'string') {
      walk(val, fn, node);
    }
  }
}

function memberTail(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    return node.property?.name || '';
  }
  return '';
}

function memberPath(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const obj = memberPath(node.object);
    const prop = node.property?.name || '';
    return obj && prop ? `${obj}.${prop}` : prop || obj;
  }
  return '';
}

async function loadAliasPrefixes(scanRoot) {
  const aliases = [
    { prefix: '@/', target: 'src/' },
    { prefix: '~/', target: '' },
  ];
  if (!scanRoot) return aliases;
  try {
    const raw = await fs.readFile(path.join(scanRoot, 'tsconfig.json'), 'utf8');
    const cleaned = raw.replace(/\/\*[\s\S]*?\*\/|^\s*\/\/.*$/gm, '');
    const parsed = JSON.parse(cleaned);
    const pathsCfg = parsed?.compilerOptions?.paths || {};
    for (const [key, vals] of Object.entries(pathsCfg)) {
      if (!Array.isArray(vals) || !vals[0]) continue;
      const prefix = key.replace(/\*$/, '');
      const target = String(vals[0]).replace(/^\.\//, '').replace(/\*$/, '');
      if (prefix) aliases.unshift({ prefix, target });
    }
  } catch {
    // tsconfig.json is optional; default @/ and ~/ aliases still apply.
  }
  return aliases;
}

function resolveImportPath(fromRel, spec, aliasPrefixes = []) {
  if (!spec) return '';
  if (spec.startsWith('./') || spec.startsWith('../')) {
    const dir = path.posix.dirname(fromRel.replace(/\\/g, '/'));
    const joined = path.posix.normalize(path.posix.join(dir, spec));
    return joined.replace(/\.(?:js|jsx|ts|tsx|mjs|cjs)$/, '');
  }
  for (const { prefix, target } of aliasPrefixes) {
    if (spec.startsWith(prefix)) {
      const rest = spec.slice(prefix.length);
      return path.posix.normalize(`${target}${rest}`).replace(/\.(?:js|jsx|ts|tsx|mjs|cjs)$/, '');
    }
  }
  return '';
}

function stripExt(rel) {
  return rel.replace(/\\/g, '/').replace(/\.(?:js|jsx|ts|tsx|mjs|cjs)$/, '');
}

function paramNamesOf(fnNode) {
  const names = [];
  for (const p of fnNode?.params || []) {
    if (p.type === 'Identifier') names.push(p.name);
    else if (p.type === 'AssignmentPattern' && p.left?.type === 'Identifier') names.push(p.left.name);
    else names.push(null);
  }
  return names;
}

function inspectFunctionBody(fnNode, raw) {
  const params = paramNamesOf(fnNode);
  const paramSinkHits = [];
  const forwardCalls = [];
  if (!fnNode?.body) return { isAsync: Boolean(fnNode?.async), paramSinkHits, forwardCalls };

  walk(fnNode.body, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression') return;
    const calleeName = memberTail(node.callee);
    let sinkKind = '';
    if (FILE_SINKS.has(calleeName)) sinkKind = `filesystem (${calleeName})`;
    else if (SQL_SINKS.has(calleeName)) sinkKind = `SQL (${calleeName})`;
    else if (SHELL_SINKS.has(calleeName)) sinkKind = `command execution (${calleeName})`;
    else if (calleeName === 'eval') sinkKind = 'eval()';
    else if (calleeName === 'redirect') sinkKind = 'HTTP redirect';

    (node.arguments || []).forEach((arg, argIdx) => {
      const argSrc = raw.slice(arg.start, arg.end);
      if (SANITIZER_RE.test(argSrc)) return;
      params.forEach((pName, idx) => {
        if (!pName) return;
        const re = new RegExp(`\\b${pName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
        if (re.test(argSrc)) {
          if (sinkKind) {
            paramSinkHits.push({ paramIndex: idx, paramName: pName, sinkKind, line: node.loc?.start.line || 1 });
          } else if (node.callee?.type === 'Identifier') {
            forwardCalls.push({ calleeName: node.callee.name, argIndex: argIdx, callerParamIndex: idx, callerParamName: pName, line: node.loc?.start.line || 1 });
          }
        }
      });
    });
  });

  return { isAsync: Boolean(fnNode?.async), paramSinkHits, forwardCalls };
}

async function analyzeCrossFileProject(jsFiles, helpers, scanRoot = '') {
  const { makeFinding, parseSuppressions, isSuppressed } = helpers;
  const findings = [];
  let checksRun = 0;
  const safeJsFiles = Array.isArray(jsFiles) ? jsFiles : [];
  if (safeJsFiles.length === 0 && !scanRoot) return { findings, checksRun };
  const aliasPrefixes = await loadAliasPrefixes(scanRoot);

  // 1. Parse all JS/TS files once and index exports, routes, API calls, and module-level state.
  const parsedFiles = [];
  const exportIndex = new Map(); // moduleKey -> Map<exportName, { file, line, isAsync, paramSinkHits }>
  const backendRoutes = new Map(); // routePath -> { file, line, bodyKeys: Set<string> }
  const frontendCalls = []; // { file, line, routePath, keys: string[] }

  for (const entry of safeJsFiles) {
    const ast = parseJsAst(entry.raw, entry.extName);
    if (!ast) continue;
    const relNorm = entry.rel.replace(/\\/g, '/');
    const modKey = stripExt(relNorm);
    const suppressions = parseSuppressions(entry.raw.split(/\r?\n/));
    const fileExports = new Map();
    const localFns = new Map();

    // Collect top-level function declarations & variable arrow/function expressions.
    for (const stmt of ast.program?.body || []) {
      if (stmt.type === 'FunctionDeclaration' && stmt.id?.name) {
        localFns.set(stmt.id.name, { node: stmt, line: stmt.loc?.start.line || 1 });
      } else if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          if (decl.id?.type === 'Identifier' && decl.init && (decl.init.type === 'ArrowFunctionExpression' || decl.init.type === 'FunctionExpression')) {
            localFns.set(decl.id.name, { node: decl.init, line: decl.loc?.start.line || 1 });
          }
        }
      } else if (stmt.type === 'ExportNamedDeclaration') {
        if (stmt.declaration?.type === 'FunctionDeclaration' && stmt.declaration.id?.name) {
          const info = inspectFunctionBody(stmt.declaration, entry.raw);
          fileExports.set(stmt.declaration.id.name, { file: entry.rel, line: stmt.declaration.loc?.start.line || 1, ...info });
        } else if (stmt.declaration?.type === 'VariableDeclaration') {
          for (const decl of stmt.declaration.declarations || []) {
            if (decl.id?.type === 'Identifier' && decl.init && (decl.init.type === 'ArrowFunctionExpression' || decl.init.type === 'FunctionExpression')) {
              const info = inspectFunctionBody(decl.init, entry.raw);
              fileExports.set(decl.id.name, { file: entry.rel, line: decl.loc?.start.line || 1, ...info });
            }
          }
        }
      } else if (stmt.type === 'ExportDefaultDeclaration' && stmt.declaration) {
        const d = stmt.declaration;
        if (d.type === 'FunctionDeclaration' || d.type === 'ArrowFunctionExpression' || d.type === 'FunctionExpression') {
          const info = inspectFunctionBody(d, entry.raw);
          fileExports.set('default', { file: entry.rel, line: d.loc?.start.line || 1, ...info });
        } else if (d.type === 'Identifier' && localFns.has(d.name)) {
          const fn = localFns.get(d.name);
          fileExports.set('default', { file: entry.rel, line: fn.line, ...inspectFunctionBody(fn.node, entry.raw) });
        }
      }
    }

    // Also index CommonJS module.exports = { ... } and exports.foo = ...
    walk(ast, (node) => {
      if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression') {
        const leftStr = memberPath(node.left);
        if (leftStr === 'module.exports' && node.right?.type === 'ObjectExpression') {
          for (const prop of node.right.properties || []) {
            if (prop.type !== 'ObjectProperty') continue;
            const keyName = prop.key?.name || prop.key?.value;
            if (!keyName) continue;
            if (prop.value?.type === 'Identifier' && localFns.has(prop.value.name)) {
              const fn = localFns.get(prop.value.name);
              fileExports.set(keyName, { file: entry.rel, line: fn.line, ...inspectFunctionBody(fn.node, entry.raw) });
            } else if (prop.value?.type === 'FunctionExpression' || prop.value?.type === 'ArrowFunctionExpression') {
              fileExports.set(keyName, { file: entry.rel, line: prop.loc?.start.line || 1, ...inspectFunctionBody(prop.value, entry.raw) });
            }
          }
        } else if ((leftStr.startsWith('exports.') || leftStr.startsWith('module.exports.')) && node.right) {
          const keyName = node.left.property?.name;
          if (!keyName) return;
          if (node.right.type === 'Identifier' && localFns.has(node.right.name)) {
            const fn = localFns.get(node.right.name);
            fileExports.set(keyName, { file: entry.rel, line: fn.line, ...inspectFunctionBody(fn.node, entry.raw) });
          } else if (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression') {
            fileExports.set(keyName, { file: entry.rel, line: node.loc?.start.line || 1, ...inspectFunctionBody(node.right, entry.raw) });
          }
        }
      }
    });

    exportIndex.set(modKey, fileExports);
    parsedFiles.push({ entry, ast, relNorm, modKey, suppressions });
  }

  // Helper to emit a finding while honoring inline suppressions.
  const pushFinding = (pf, spec, line, excerpt, reason) => {
    if (isSuppressed(pf.suppressions, line, spec.id)) return;
    findings.push(makeFinding(spec, pf.entry.rel, line, excerpt, reason));
  };

  // Pre-compute importedSymbols for every file so we can propagate multi-hop taint before emitting findings.
  for (const pf of parsedFiles) {
    const importedSymbols = new Map();
    for (const stmt of pf.ast.program?.body || []) {
      if (stmt.type === 'ImportDeclaration' && stmt.source?.value) {
        const targetMod = resolveImportPath(pf.relNorm, stmt.source.value, aliasPrefixes);
        const modExports = exportIndex.get(targetMod) || exportIndex.get(`${targetMod}/index`);
        if (!modExports) continue;
        for (const sp of stmt.specifiers || []) {
          if (sp.type === 'ImportSpecifier') {
            const expName = sp.imported?.name;
            if (expName && modExports.has(expName)) importedSymbols.set(sp.local.name, modExports.get(expName));
          } else if (sp.type === 'ImportDefaultSpecifier' && modExports.has('default')) {
            importedSymbols.set(sp.local.name, modExports.get('default'));
          }
        }
      } else if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          const init = decl.init;
          if (init?.type === 'CallExpression' && init.callee?.name === 'require' && init.arguments?.[0]?.type === 'StringLiteral') {
            const targetMod = resolveImportPath(pf.relNorm, init.arguments[0].value, aliasPrefixes);
            const modExports = exportIndex.get(targetMod) || exportIndex.get(`${targetMod}/index`);
            if (!modExports) continue;
            if (decl.id?.type === 'ObjectPattern') {
              for (const prop of decl.id.properties || []) {
                const keyName = prop.key?.name;
                const localName = prop.value?.name || keyName;
                if (keyName && localName && modExports.has(keyName)) importedSymbols.set(localName, modExports.get(keyName));
              }
            } else if (decl.id?.type === 'Identifier' && modExports.has('default')) {
              importedSymbols.set(decl.id.name, modExports.get('default'));
            }
          }
        }
      }
    }
    pf.importedSymbols = importedSymbols;
  }

  // Multi-hop fixed-point taint propagation (up to 4 hops across files).
  for (let hop = 0; hop < 4; hop++) {
    let changed = false;
    for (const pf of parsedFiles) {
      const modExports = exportIndex.get(pf.modKey);
      if (!modExports) continue;
      for (const expMeta of modExports.values()) {
        for (const fc of expMeta.forwardCalls || []) {
          const targetMeta = pf.importedSymbols.get(fc.calleeName) || modExports.get(fc.calleeName);
          if (!targetMeta?.paramSinkHits?.length) continue;
          for (const sinkHit of targetMeta.paramSinkHits) {
            if (sinkHit.paramIndex !== fc.argIndex) continue;
            const already = expMeta.paramSinkHits.some((h) => h.paramIndex === fc.callerParamIndex && h.sinkKind === sinkHit.sinkKind);
            if (!already) {
              expMeta.paramSinkHits.push({
                paramIndex: fc.callerParamIndex,
                paramName: fc.callerParamName,
                sinkKind: sinkHit.sinkKind,
                line: sinkHit.line,
              });
              changed = true;
            }
          }
        }
      }
    }
    if (!changed) break;
  }

  // 2. Second pass: cross-file call graph checks, route auth & IDOR checks, shared async state, TOCTOU, and API contracts.
  for (const pf of parsedFiles) {
    const { entry, ast, relNorm, importedSymbols } = pf;
    const raw = entry.raw;
    const lines = raw.split(/\r?\n/);
    const isTestOrScript = /(?:^|\/)(?:test|tests|__tests__|spec|scripts)\//i.test(relNorm) || /\.(?:test|spec)\./i.test(relNorm);

    // 2a. Cross-file taint & unawaited async checks.
    checksRun += 2;
    if (importedSymbols.size > 0) {
      walk(ast, (node, parent) => {
        if (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression') return;
        if (node.callee?.type !== 'Identifier') return;
        const targetMeta = importedSymbols.get(node.callee.name);
        if (!targetMeta) return;
        const line = node.loc?.start.line || 1;
        const excerpt = lines[line - 1] || '';

        // Interprocedural taint check
        if (targetMeta.paramSinkHits?.length) {
          for (const hit of targetMeta.paramSinkHits) {
            const arg = node.arguments?.[hit.paramIndex];
            if (!arg) continue;
            const argSrc = raw.slice(arg.start, arg.end);
            if (!SANITIZER_RE.test(argSrc) && REQUEST_TAINT_RE.test(argSrc)) {
              pushFinding(pf, {
                id: 'js-crossfile-taint',
                title: `Cross-file untrusted input reaches ${hit.sinkKind}`,
                severity: 'high',
                cwe: 'CWE-20',
                confidence: 'high',
                hint: `Validate or sanitize input before passing it to "${node.callee.name}" (${targetMeta.file}:${hit.line}).`,
              }, line, excerpt, `Request input is passed to "${node.callee.name}", which forwards parameter "${hit.paramName}" into ${hit.sinkKind} at ${targetMeta.file}:${hit.line}.`);
            }
          }
        }

        // Unawaited async cross-file call
        if (targetMeta.isAsync && parent?.type === 'ExpressionStatement') {
          pushFinding(pf, {
            id: 'js-crossfile-unawaited-async',
            title: `Imported async function "${node.callee.name}" called without await`,
            severity: 'medium',
            cwe: 'CWE-252',
            confidence: 'medium',
            hint: `Await "${node.callee.name}(...)" or attach .catch() so rejections and ordering bugs are handled.`,
          }, line, excerpt, `"${node.callee.name}" is declared async in ${targetMeta.file}:${targetMeta.line} but invoked here without await or rejection handling.`);
        }
      });
    }

    // 2b. Express/Fastify route missing auth middleware + backend API route body keys.
    checksRun++;
    // Collect router-level / app-level auth middleware & webhook HMAC checks
    const fileRouterUseAuth = [];
    const globalAuthPrefixes = [];
    const WEBHOOK_SIG_RE = /(?:createHmac|timingSafeEqual|verifySignature|x-hub-signature|stripe-signature|svix-signature|webhook.*secret)/i;

    for (const other of parsedFiles.values()) {
      walk(other.ast, (n) => {
        if (n.type !== 'CallExpression') return;
        const cal = n.callee;
        if (cal?.type === 'MemberExpression' && cal.property?.name === 'use' && ['app', 'router', 'server', 'api'].includes(cal.object?.name)) {
          const args = n.arguments || [];
          const firstStr = args[0]?.type === 'StringLiteral' ? args[0].value : null;
          const restSrc = args.slice(firstStr ? 1 : 0).map((a) => other.entry.raw.slice(a.start, a.end)).join(' ');
          if (AUTH_MW_RE.test(restSrc)) {
            if (other.entry.rel === entry.rel) {
              fileRouterUseAuth.push({ prefix: firstStr || '/', line: n.loc?.start.line || 1 });
            } else if (firstStr) {
              globalAuthPrefixes.push(firstStr);
            }
          }
        }
      });
    }

    const routesInFile = [];
    walk(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const callee = node.callee;
      if (callee?.type !== 'MemberExpression' || callee.object?.type !== 'Identifier' || callee.property?.type !== 'Identifier') return;
      const objName = callee.object.name;
      const method = callee.property.name.toLowerCase();
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) return;
      if (!['app', 'router', 'server', 'api'].includes(objName)) return;
      const routeArg = node.arguments?.[0];
      if (!routeArg || routeArg.type !== 'StringLiteral' || !routeArg.value.startsWith('/')) return;

      const middlewares = node.arguments.slice(1, -1).map((a) => raw.slice(a.start, a.end));
      const handler = node.arguments[node.arguments.length - 1];
      const line = node.loc?.start.line || 1;
      const handlerFullSrc = handler ? raw.slice(handler.start, handler.end) : '';
      const coveredByRouterUse = fileRouterUseAuth.some((u) => u.line < line && routeArg.value.startsWith(u.prefix))
        || globalAuthPrefixes.some((pfx) => routeArg.value.startsWith(pfx));
      const hasWebhookSig = WEBHOOK_SIG_RE.test(handlerFullSrc);
      const hasAuth = coveredByRouterUse
        || hasWebhookSig
        || middlewares.some((m) => AUTH_MW_RE.test(m))
        || (handler && AUTH_MW_RE.test(raw.slice(handler.start, Math.min(handler.end, handler.start + 300))));
      routesInFile.push({ objName, method, routePath: routeArg.value, hasAuth, line, excerpt: lines[line - 1] || '' });

      // Exploit Reachability: unauthenticated route flowing tainted req.* directly into shell/SQL/path sink
      if (!isTestOrScript && !hasAuth && !PUBLIC_ROUTE_RE.test(routeArg.value) && handler) {
        const hasReqInput = REQUEST_TAINT_RE.test(handlerFullSrc);
        const hasDangerousSink = /\b(?:exec|execSync|spawnSync)\s*\(|\.(?:query|raw)\s*\(\s*`[^`]*\$\{|\bfs\.(?:readFile|writeFile|unlink)\s*\(/.test(handlerFullSrc);
        if (hasReqInput && hasDangerousSink && !SANITIZER_RE.test(handlerFullSrc)) {
          pushFinding(pf, {
            id: 'js-reachable-unauth-sink',
            title: `Reachable unauthenticated sink on ${method.toUpperCase()} ${routeArg.value}`,
            severity: 'critical',
            cwe: 'CWE-306',
            confidence: 'high',
            hint: 'Add authentication middleware and sanitize/parameterize request input before passing it to the sink.',
          }, line, lines[line - 1] || '', `Public route ${method.toUpperCase()} ${routeArg.value} has no auth middleware and passes request input toward a high-risk sink.`);
        }
      }

      if (['post', 'put', 'patch'].includes(method) && handler) {
        const bodyKeys = new Set();
        const handlerSrc = raw.slice(handler.start, handler.end);
        for (const m of handlerSrc.matchAll(/\breq\.body\.([a-zA-Z_][a-zA-Z0-9_]*)\b/g)) {
          bodyKeys.add(m[1]);
        }
        if (bodyKeys.size > 0) {
          backendRoutes.set(routeArg.value, { file: entry.rel, line, bodyKeys });
        }
      }

      // IDOR check: authenticated delete/put/patch route mutating by req.params.* without referencing user/owner scope.
      if (!isTestOrScript && hasAuth && ['delete', 'put', 'patch'].includes(method) && /\/:[a-zA-Z_]\w*/.test(routeArg.value) && handler) {
        const handlerSrc = raw.slice(handler.start, handler.end);
        const usesParamId = /\b(?:req|request|r)\.params\./.test(handlerSrc);
        const mutatesDb = /\.(?:delete|remove|destroy|update|findByIdAndDelete|findByIdAndUpdate|deleteOne|updateOne)\s*\(/.test(handlerSrc);
        const checksOwnership = /\b(?:req\.user|userId|user_id|ownerId|owner_id|authorId|author_id|session\.user|auth\.uid)\b/.test(handlerSrc);
        if (usesParamId && mutatesDb && !checksOwnership) {
          pushFinding(pf, {
            id: 'js-idor-missing-ownership',
            title: `Potential IDOR on ${method.toUpperCase()} ${routeArg.value}: missing ownership check`,
            severity: 'high',
            cwe: 'CWE-639',
            confidence: 'medium',
            hint: 'Scope the update/delete query by the authenticated user ID (e.g. req.user.id / user_id) so users cannot modify other accounts\' records.',
          }, line, lines[line - 1] || '', `Route ${method.toUpperCase()} ${routeArg.value} mutates a record using req.params without scoping to user/owner identity.`);
        }
      }
    });

    if (!isTestOrScript && routesInFile.length >= 3) {
      const authCount = routesInFile.filter((r) => r.hasAuth).length;
      if (authCount >= 2) {
        for (const r of routesInFile) {
          if (!r.hasAuth && ['post', 'put', 'patch', 'delete'].includes(r.method) && !PUBLIC_ROUTE_RE.test(r.routePath)) {
            pushFinding(pf, {
              id: 'js-route-missing-auth',
              title: `Mutating route ${r.method.toUpperCase()} ${r.routePath} lacks auth middleware`,
              severity: 'high',
              cwe: 'CWE-862',
              confidence: 'medium',
              hint: 'Add the authentication/authorization middleware used by sibling routes unless this endpoint is intentionally public.',
            }, r.line, r.excerpt, `${authCount} sibling routes in this file enforce auth middleware, but ${r.method.toUpperCase()} ${r.routePath} has none.`);
          }
        }
      }
    }

    // Collect frontend fetch('/api/...') JSON body keys for cross-file contract matching.
    walk(ast, (node) => {
      if (node.type !== 'CallExpression' || node.callee?.name !== 'fetch') return;
      const urlArg = node.arguments?.[0];
      const optsArg = node.arguments?.[1];
      if (!urlArg || urlArg.type !== 'StringLiteral' || !urlArg.value.startsWith('/api/')) return;
      if (!optsArg || optsArg.type !== 'ObjectExpression') return;
      const optsSrc = raw.slice(optsArg.start, optsArg.end);
      const jsonMatch = optsSrc.match(/JSON\.stringify\s*\(\s*\{([\s\S]{1,400})\}\s*\)/);
      if (!jsonMatch) return;
      const keys = [];
      for (const km of jsonMatch[1].matchAll(/(?:^|[,{])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::|,|$)/g)) {
        keys.push(km[1]);
      }
      if (keys.length > 0) {
        frontendCalls.push({ pf, line: node.loc?.start.line || 1, excerpt: lines[(node.loc?.start.line || 1) - 1] || '', routePath: urlArg.value, keys });
      }
    });

    // 2c. Module-level mutable `let` shared state race across `await` boundaries.
    checksRun++;
    if (!isTestOrScript) {
      const moduleLetVars = new Set();
      for (const stmt of ast.program?.body || []) {
        if (stmt.type === 'VariableDeclaration' && stmt.kind === 'let') {
          for (const d of stmt.declarations || []) {
            if (d.id?.type === 'Identifier') moduleLetVars.add(d.id.name);
          }
        }
      }
      if (moduleLetVars.size > 0) {
        walk(ast, (node) => {
          if ((node.type !== 'FunctionDeclaration' && node.type !== 'FunctionExpression' && node.type !== 'ArrowFunctionExpression') || !node.async || !node.body) return;
          // Look for await followed later in the same function by an assignment to a module-level `let` that was read before the await.
          const events = [];
          walk(node.body, (inner) => {
            if (inner.type === 'AwaitExpression') {
              events.push({ kind: 'await', pos: inner.start });
            } else if (inner.type === 'AssignmentExpression' && inner.left?.type === 'Identifier' && moduleLetVars.has(inner.left.name)) {
              events.push({ kind: 'write', name: inner.left.name, pos: inner.start, line: inner.loc?.start.line || 1 });
            } else if (inner.type === 'Identifier' && moduleLetVars.has(inner.name)) {
              events.push({ kind: 'read', name: inner.name, pos: inner.start });
            }
          });
          const firstAwait = events.find((e) => e.kind === 'await');
          if (!firstAwait) return;
          for (const vName of moduleLetVars) {
            const readBefore = events.some((e) => e.kind === 'read' && e.name === vName && e.pos < firstAwait.pos);
            const writeAfter = events.find((e) => e.kind === 'write' && e.name === vName && e.pos > firstAwait.pos);
            if (readBefore && writeAfter) {
              pushFinding(pf, {
                id: 'js-shared-state-async-race',
                title: `Module-level "${vName}" read before await and mutated after await`,
                severity: 'medium',
                cwe: 'CWE-362',
                confidence: 'medium',
                hint: `Concurrent async calls can interleave across the await and overwrite "${vName}". Keep state request-scoped or guard with a mutex/queue.`,
              }, writeAfter.line, lines[writeAfter.line - 1] || '', `Shared module variable "${vName}" is read before an await and written afterward inside an async function.`);
            }
          }
        });
      }
    }

    // 2d. TOCTOU fs.existsSync check-then-use in non-test, non-CLI-script code.
    checksRun++;
    if (!isTestOrScript) {
      walk(ast, (node) => {
        if (node.type !== 'IfStatement' || !node.consequent) return;
        const testSrc = raw.slice(node.test.start, node.test.end);
        const existsMatch = testSrc.match(/\b(?:fs\.)?existsSync\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\)/);
        if (!existsMatch) return;
        const targetVar = existsMatch[1];
        const bodySrc = raw.slice(node.consequent.start, node.consequent.end);
        const escaped = targetVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp(`\\b(?:fs\\.)?(?:readFileSync|writeFileSync|unlinkSync|rmSync|openSync)\\s*\\(\\s*${escaped}\\b`).test(bodySrc)) {
          const line = node.loc?.start.line || 1;
          pushFinding(pf, {
            id: 'js-toctou-fs',
            title: 'Time-of-check to time-of-use (TOCTOU) on filesystem path',
            severity: 'medium',
            cwe: 'CWE-367',
            confidence: 'medium',
            hint: 'Avoid existsSync() before read/write/unlink; perform the operation directly (or with O_EXCL / try-catch ENOENT) to avoid race conditions.',
          }, line, lines[line - 1] || '', `Checks existsSync(${targetVar}) before a synchronous file operation on the same path.`);
        }
      });
    }
  }

  // 3. Cross-file Frontend <-> Backend API contract mismatch check.
  checksRun++;
  for (const call of frontendCalls) {
    const backend = backendRoutes.get(call.routePath);
    if (!backend) continue;
    const normMap = new Map();
    for (const bk of backend.bodyKeys) {
      normMap.set(bk.toLowerCase().replace(/_/g, ''), bk);
    }
    for (const fk of call.keys) {
      if (backend.bodyKeys.has(fk)) continue;
      const norm = fk.toLowerCase().replace(/_/g, '');
      const matchingBackendKey = normMap.get(norm);
      if (matchingBackendKey && matchingBackendKey !== fk) {
        pushFinding(call.pf, {
          id: 'js-api-contract-mismatch',
          title: `API payload field "${fk}" mismatches backend "${matchingBackendKey}"`,
          severity: 'medium',
          cwe: 'CWE-684',
          confidence: 'high',
          hint: `Frontend sends "${fk}" to ${call.routePath}, but ${backend.file}:${backend.line} reads req.body.${matchingBackendKey}. Align the field names.`,
        }, call.line, call.excerpt, `Frontend sends "${fk}" while backend route ${backend.file}:${backend.line} expects "${matchingBackendKey}".`);
      }
    }
  }

  // 4. Next.js 'use server' Server Actions missing auth, SSRF taint, and NoSQL operator injection.
  const SERVER_ACTION_MUTATE_RE = /\b(?:prisma\.\w+\.(?:create|update|delete|upsert)|db\.(?:insert|update|delete)|supabase\.from\([^)]*\)\.(?:insert|update|delete|upsert)|fs\.(?:writeFile|unlink|rm))\b/;
  const SERVER_ACTION_AUTH_RE = /\b(?:auth|getSession|getServerSession|currentUser|getUser|requireAuth|verifySession|authenticate|checkAuth)\s*\(/i;
  const SSRF_CALL_RE = /\b(?:fetch|axios\.(?:get|post|put|delete|request)|got)\s*\(\s*([^,)]+)/;
  const NOSQL_CALL_RE = /\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|countDocuments)\s*\(\s*(req\.(?:body|query)|request\.(?:body|query))\s*[,)]/;

  for (const pf of parsedFiles) {
    const raw = pf.entry.raw;
    const lines = raw.split(/\r?\n/);
    const isTest = /(?:^|\/)(?:tests?|__tests__|spec|scripts?)\/|\.(?:test|spec)\./i.test(pf.relNorm);
    if (isTest) continue;

    // 4a. Next.js 'use server' exported async mutations without session/auth check
    const hasUseServer = /^\s*['"]use server['"]\s*;?/m.test(raw.slice(0, 300));
    if (hasUseServer) {
      checksRun++;
      walk(pf.ast, (node) => {
        if (node.type === 'ExportNamedDeclaration' && node.declaration?.type === 'FunctionDeclaration' && node.declaration.async) {
          const fn = node.declaration;
          const fnName = fn.id?.name || 'action';
          if (/^(?:login|signin|signup|register|resetPassword)/i.test(fnName)) return;
          const fnSrc = raw.slice(fn.start, fn.end);
          if (SERVER_ACTION_MUTATE_RE.test(fnSrc) && !SERVER_ACTION_AUTH_RE.test(fnSrc)) {
            const line = fn.loc?.start.line || 1;
            pushFinding(pf, {
              id: 'js-server-action-no-auth',
              title: `Next.js Server Action "${fnName}()" mutates data without auth/session check`,
              severity: 'high',
              cwe: 'CWE-306',
              confidence: 'high',
              hint: `Verify the authenticated user (e.g. await auth() / getSession()) at the top of "${fnName}()" before mutating state.`,
            }, line, lines[line - 1] || '', `'use server' action "${fnName}" performs a DB/file mutation without calling an auth/session helper.`);
          }
        }
      });
    }

    // 4b. SSRF taint & NoSQL operator injection
    checksRun++;
    for (let i = 0; i < lines.length; i++) {
      const lineStr = lines[i];
      const ssrfM = SSRF_CALL_RE.exec(lineStr);
      if (ssrfM && REQUEST_TAINT_RE.test(ssrfM[1]) && !/ALLOWED_HOSTS|hostname\s*===|startsWith\s*\(\s*['"]https:\/\//.test(raw.slice(Math.max(0, raw.indexOf(lineStr) - 300), raw.indexOf(lineStr) + lineStr.length))) {
        pushFinding(pf, {
          id: 'js-ssrf-taint',
          title: 'Potential SSRF: request-controlled URL passed to outbound HTTP client',
          severity: 'high',
          cwe: 'CWE-918',
          confidence: 'high',
          hint: 'Validate the URL scheme (https:) and allowlist permitted hostnames before calling fetch/axios.',
        }, i + 1, lineStr, 'User-controlled request input flows directly into an outbound HTTP fetch/axios call.');
      }
      if (NOSQL_CALL_RE.test(lineStr)) {
        pushFinding(pf, {
          id: 'js-nosql-injection',
          title: 'Potential NoSQL operator injection: raw req.body/req.query passed to DB query',
          severity: 'high',
          cwe: 'CWE-943',
          confidence: 'high',
          hint: 'Pick explicit scalar fields (e.g. { email: String(req.body.email) }) instead of passing raw req.body/req.query to Mongoose/Mongo.',
        }, i + 1, lineStr, 'Passing raw req.body/req.query allows attackers to inject $ne, $gt, or $regex operators.');
      }
    }
  }

  // 5. Real-world 100+ concurrent user & production scalability/race detectors
  const ATOMIC_GUARD_RE = /(?:\$transaction|\.transaction\s*\(|FOR\s+UPDATE|\$inc\b|\.increment\s*\(|\.decrement\s*\(|BEGIN\s+(?:IMMEDIATE|TRANSACTION)|serializable|optimistic|version\b|etag\b)/i;
  const RATE_LIMIT_RE = /(?:rateLimit|rateLimiter|limiter|slowDown|throttle|ratelimit|Upstash|turnstile|hcaptcha|recaptcha|429)/i;
  const AUTH_ENDPOINT_RE = /['"`]\/(?:api\/)?(?:login|signin|sign-in|register|signup|sign-up|otp|verify|reset-password|forgot-password)['"`]/i;
  const UNBOUNDED_DB_FIND_RE = /\.\s*(?:findMany|find|findAll)\s*\(\s*(?:\{\s*\})?\s*\)/;
  const PAGINATION_RE = /\b(?:take|limit|page|perPage|pageSize|range|slice|offset|cursor)\b/i;

  for (const pf of parsedFiles) {
    const raw = pf.entry.raw;
    const lines = raw.split(/\r?\n/);
    const isTest = /(?:^|\/)(?:tests?|__tests__|spec|scripts?|electron|bin)\/|\.(?:test|spec)\./i.test(pf.relNorm);
    if (isTest) continue;

    // 5a. Non-atomic read-modify-write across await (double-spend / oversell race under 100+ users)
    checksRun++;
    walk(pf.ast, (node) => {
      if ((node.type !== 'FunctionDeclaration' && node.type !== 'FunctionExpression' && node.type !== 'ArrowFunctionExpression') || !node.async || !node.body) return;
      const fnSrc = raw.slice(node.start, node.end);
      if (ATOMIC_GUARD_RE.test(fnSrc)) return;
      const readM = fnSrc.match(/await\s+[^\n;]*\.(?:findOne|findUnique|findFirst|get|select|query)\s*\([^)]*\)[^\n]*[\r\n]+[\s\S]{0,400}?\b(?:balance|stock|inventory|credits|seats|qty|quantity|count|wallet|points)\b[^\n;]*(?:[-+]|-=|\+=)[\s\S]{0,400}?await\s+[^\n;]*\.(?:update|save|set|query)\s*\(/i);
      if (readM) {
        const line = node.loc?.start.line || 1;
        pushFinding(pf, {
          id: 'js-non-atomic-read-modify-write',
          title: 'Non-atomic read-modify-write across await (race condition under concurrent users)',
          severity: 'high',
          cwe: 'CWE-362',
          confidence: 'high',
          hint: 'Wrap read-modify-write balance/inventory updates in a database transaction ($transaction / FOR UPDATE) or use atomic $inc/decrement operations.',
        }, line, lines[line - 1] || '', 'Reads mutable balance/stock before await and writes computed result afterward without a transaction or atomic update.');
      }
    });

    // 5b. Unbounded module-level Map/Set cache mutated per request/user without eviction
    checksRun++;
    const cacheNames = new Set();
    for (const stmt of pf.ast.program?.body || []) {
      if (stmt.type === 'VariableDeclaration') {
        for (const d of stmt.declarations || []) {
          if (d.id?.type === 'Identifier' && d.init?.type === 'NewExpression' && /^(?:Map|Set)$/.test(d.init.callee?.name || '')) {
            cacheNames.add(d.id.name);
          }
        }
      }
    }
    if (cacheNames.size > 0 && !/\b(?:LRUCache|maxSize|MAX_|ttl|TTL|evict|\.clear\s*\()/.test(raw)) {
      for (const cName of cacheNames) {
        const escaped = cName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const mutRe = new RegExp(`\\b${escaped}\\.(?:set|add)\\s*\\(\\s*(?:req\\.|request\\.|userId|ip|sessionId|token|key|id\\b)`);
        const delRe = new RegExp(`\\b${escaped}\\.delete\\s*\\(`);
        if (!delRe.test(raw)) {
          for (let i = 0; i < lines.length; i++) {
            if (mutRe.test(lines[i])) {
              pushFinding(pf, {
                id: 'js-unbounded-memory-map',
                title: `Unbounded in-memory ${cName} grows per user/request without eviction`,
                severity: 'medium',
                cwe: 'CWE-400',
                confidence: 'medium',
                hint: `Add a maxSize/TTL eviction policy (or use Redis / LRUCache) so "${cName}" does not OOM under 100+ / 10,000+ users.`,
              }, i + 1, lines[i], `Module-level "${cName}" stores per-user/request keys without delete/eviction/maxSize.`);
              break;
            }
          }
        }
      }
    }

    // 5c. Missing rate limiting on auth/OTP/password-reset route handlers
    checksRun++;
    if (/(?:app|router|fastify)\.(?:post|all)\s*\(/i.test(raw) && !RATE_LIMIT_RE.test(raw)) {
      for (let i = 0; i < lines.length; i++) {
        if (/(?:app|router|fastify)\.(?:post|all)\s*\(/.test(lines[i]) && AUTH_ENDPOINT_RE.test(lines[i])) {
          pushFinding(pf, {
            id: 'js-missing-rate-limit-auth',
            title: 'Auth / credential endpoint lacks rate limiting against brute-force or bot bursts',
            severity: 'medium',
            cwe: 'CWE-307',
            confidence: 'medium',
            hint: 'Attach rate-limiting middleware (e.g. express-rate-limit) to login, signup, OTP, and password-reset endpoints.',
          }, i + 1, lines[i], 'Authentication/OTP route handler has no rate-limiter middleware in scope.');
        }
      }
    }

    // 5d. Unbounded DB findMany/find/findAll inside route handlers (no limit/take/pagination)
    checksRun++;
    if (/(?:app|router|fastify)\.(?:get|post)\s*\(/i.test(raw)) {
      for (let i = 0; i < lines.length; i++) {
        if (UNBOUNDED_DB_FIND_RE.test(lines[i])) {
          const ctx = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 4)).join('\n');
          if (!PAGINATION_RE.test(ctx)) {
            pushFinding(pf, {
              id: 'js-missing-db-pagination',
              title: 'Unbounded database query without limit/take/pagination',
              severity: 'medium',
              cwe: 'CWE-770',
              confidence: 'medium',
              hint: 'Pass explicit take/limit/pagination parameters to avoid loading entire tables under concurrent user traffic.',
            }, i + 1, lines[i], 'Database find/findMany/findAll called without limit, take, or pagination bounds.');
          }
        }
      }
    }

    // 5e. Unthrottled Promise.all(arr.map(...)) in request handlers (connection pool exhaustion)
    checksRun++;
    if (/(?:req\.|request\.|app\.|router\.|export\s+async\s+function\s+(?:GET|POST|PUT|DELETE))/.test(raw) && !/\b(?:pLimit|pMap|chunk|batch|CONCURRENCY|Promise\.allSettled)\b/.test(raw)) {
      for (let i = 0; i < lines.length; i++) {
        if (/Promise\.all\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.]*\.map\s*\(/.test(lines[i])) {
          pushFinding(pf, {
            id: 'js-unhandled-concurrent-promise-all',
            title: 'Unbounded Promise.all(items.map(...)) can exhaust pools or fail-fast under load',
            severity: 'medium',
            cwe: 'CWE-755',
            confidence: 'medium',
            hint: 'Cap concurrency (e.g. p-limit / batching) or use Promise.allSettled when fanning out per-item async work.',
          }, i + 1, lines[i], 'Unbounded Promise.all(.map(...)) in request/API code without concurrency limit or allSettled.');
        }
      }
    }
    // 5f. Drizzle ORM schema checks (float money columns & missing unique on idempotencyKey)
    if (/\b(?:pgTable|mysqlTable|sqliteTable)\s*\(/.test(raw)) {
      checksRun++;
      for (let i = 0; i < lines.length; i++) {
        if (/\b(?:real|doublePrecision|float)\s*\(\s*['"](?:balance|amount|price|credit|credits|total|fee|payout)['"]/i.test(lines[i])) {
          pushFinding(pf, {
            id: 'schema-float-money-column',
            title: 'ORM schema stores monetary column as floating-point (real/doublePrecision/float)',
            severity: 'medium',
            cwe: 'CWE-682',
            confidence: 'high',
            hint: 'Use integer cents (integer/bigint) or exact decimal/numeric columns for currency and balance fields.',
          }, i + 1, lines[i], 'Floating-point currency columns cause IEEE-754 rounding drift under concurrent transactions.');
        }
        if (/['"](?:idempotency_key|idempotencyKey)['"]/.test(lines[i]) && !/\.unique\s*\(|uniqueIndex/.test(lines.slice(i, Math.min(lines.length, i + 3)).join(' '))) {
          pushFinding(pf, {
            id: 'schema-missing-unique-constraint',
            title: 'Schema idempotencyKey column lacks a unique constraint (.unique())',
            severity: 'medium',
            cwe: 'CWE-362',
            confidence: 'high',
            hint: 'Add .unique() to idempotencyKey so concurrent duplicate requests are rejected atomically by the database.',
          }, i + 1, lines[i], 'idempotencyKey column without a unique index cannot prevent race-condition duplicate inserts.');
        }
      }
    }
  }

  // 6. Prisma Schema (schema.prisma) & OpenAPI (openapi.json) concurrency/security cross-checks
  if (scanRoot) {
    for (const relCandidate of ['prisma/schema.prisma', 'schema.prisma']) {
      try {
        const prismaRaw = await fs.readFile(path.join(scanRoot, relCandidate), 'utf8');
        const pLines = prismaRaw.split(/\r?\n/);
        const pSup = parseSuppressions ? parseSuppressions(pLines) : new Map();
        checksRun++;

        for (const m of prismaRaw.matchAll(/model\s+([A-Za-z0-9_]+)\s*\{([\s\S]*?)\n\}/g)) {
          const modelName = m[1];
          const body = m[2];
          const startLine = prismaRaw.slice(0, m.index).split(/\r?\n/).length;
          const bodyLines = body.split(/\r?\n/);

          for (let idx = 0; idx < bodyLines.length; idx++) {
            const bLine = bodyLines[idx];
            const absLine = startLine + idx;
            // 6a. Float money column in Prisma model
            if (/^\s*(?:balance|amount|price|credit|credits|total|fee|payout)\s+Float\b/i.test(bLine)) {
              if (!isSuppressed || !isSuppressed(pSup, absLine, 'schema-float-money-column')) {
                findings.push({
                  ...makeFinding({
                    id: 'schema-float-money-column',
                    title: `Prisma model "${modelName}" stores monetary field as Float instead of Decimal/Int`,
                    severity: 'medium',
                    cwe: 'CWE-682',
                    hint: 'Use Decimal (@db.Decimal) or Int (minor currency units/cents) for financial fields in schema.prisma.',
                  }, relCandidate, absLine, bLine),
                  confidence: 'high',
                  reason: `Monetary field in model "${modelName}" uses IEEE-754 Float.`,
                });
              }
            }
            // 6b. idempotencyKey / eventId without @unique or @@unique
            if (/^\s*(?:idempotencyKey|webhookEventId|txHash)\s+String\b/.test(bLine) && !/@unique\b/.test(bLine) && !/@@unique\s*\([^)]*(?:idempotencyKey|webhookEventId|txHash)/.test(body)) {
              if (!isSuppressed || !isSuppressed(pSup, absLine, 'schema-missing-unique-constraint')) {
                findings.push({
                  ...makeFinding({
                    id: 'schema-missing-unique-constraint',
                    title: `Prisma model "${modelName}" defines idempotency/event key without @unique`,
                    severity: 'medium',
                    cwe: 'CWE-362',
                    hint: 'Mark idempotencyKey / webhookEventId / txHash with @unique to enforce database-level race protection.',
                  }, relCandidate, absLine, bLine),
                  confidence: 'high',
                  reason: `Idempotency field in model "${modelName}" lacks @unique / @@unique constraint.`,
                });
              }
            }
            // 6c. onDelete: Cascade on financial/audit ledger models
            if (/^(?:Order|Payment|Transaction|Ledger|Invoice|AuditLog|Payout)s?$/i.test(modelName) && /onDelete\s*:\s*Cascade\b/.test(bLine)) {
              if (!isSuppressed || !isSuppressed(pSup, absLine, 'schema-cascade-delete-ledger')) {
                findings.push({
                  ...makeFinding({
                    id: 'schema-cascade-delete-ledger',
                    title: `Prisma financial/audit model "${modelName}" uses onDelete: Cascade`,
                    severity: 'medium',
                    cwe: 'CWE-284',
                    hint: 'Use onDelete: Restrict or SetNull on financial and audit ledger relations so deleting a user preserves records.',
                  }, relCandidate, absLine, bLine),
                  confidence: 'high',
                  reason: `onDelete: Cascade on "${modelName}" can silently destroy financial/audit records.`,
                });
              }
            }
          }
        }
        break;
      } catch (err) {
        void err;
      }
    }
  }

  return { findings, checksRun };
}

module.exports = { analyzeCrossFileProject };
