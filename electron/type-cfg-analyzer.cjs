'use strict';

// Type-Inference & Real Basic-Block Control-Flow Graph (CFG) Analyzer for JS/TS.
// - Cross-file Promise / Array / Nullable / Crypto-vs-ORM type resolution
// - Basic-block CFG with forward fixed-point nullability dataflow & branch narrowing

const fs = require('node:fs/promises');
const path = require('node:path');
const { parse } = require('@babel/parser');

async function indexDtsPromiseFns(scanRoot, jsFiles) {
  const pkgPromiseFns = new Map(); // "pkg" -> Set<fnName>
  const dtsRe = /export\s+(?:declare\s+)?function\s+([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*:\s*Promise\s*</g;

  // 1. Project-local .d.ts files
  const localDts = new Map();
  for (const f of jsFiles) {
    if (!f.rel.endsWith('.d.ts')) continue;
    const set = new Set();
    for (const m of f.raw.matchAll(dtsRe)) set.add(m[1]);
    if (set.size > 0) localDts.set(f.rel, set);
  }

  // 2. Direct dependencies in package.json -> node_modules/<pkg>/*.d.ts or @types/<pkg>/index.d.ts
  if (scanRoot) {
    try {
      const pkgRaw = await fs.readFile(path.join(scanRoot, 'package.json'), 'utf8');
      const pkg = JSON.parse(pkgRaw);
      const deps = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }).slice(0, 40);
      for (const dep of deps) {
        const cleanDep = dep.replace(/^@/, '').replace('/', '__');
        const candidates = [
          path.join(scanRoot, 'node_modules', dep, 'index.d.ts'),
          path.join(scanRoot, 'node_modules', dep, 'dist', 'index.d.ts'),
          path.join(scanRoot, 'node_modules', '@types', cleanDep, 'index.d.ts'),
        ];
        for (const c of candidates) {
          try {
            const raw = await fs.readFile(c, 'utf8');
            const set = new Set();
            for (const m of raw.matchAll(dtsRe)) set.add(m[1]);
            if (set.size > 0) { pkgPromiseFns.set(dep, set); break; }
          } catch {
            // Optional .d.ts candidate
          }
        }
      }
    } catch {
      // package.json optional
    }
  }
  return { localDts, pkgPromiseFns };
}

function parseAst(raw, extName) {
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

function inferTypeFromTsAnnotation(tsNode) {
  if (!tsNode) return 'unknown';
  const t = tsNode.typeAnnotation || tsNode;
  if (!t) return 'unknown';
  if (t.type === 'TSArrayType' || t.type === 'TSTupleType') return 'array';
  if (t.type === 'TSTypeReference') {
    const name = memberPath(t.typeName);
    if (name === 'Promise') return 'promise';
    if (name === 'Array' || name === 'ReadonlyArray') return 'array';
    if (name === 'Record' || name === 'Map' || name === 'Set') return 'object';
  }
  if (t.type === 'TSUnionType') {
    const hasNull = t.types.some((m) => m.type === 'TSNullKeyword' || m.type === 'TSUndefinedKeyword' || m.type === 'TSVoidKeyword');
    if (hasNull) return 'nullable';
    if (t.types.some((m) => inferTypeFromTsAnnotation(m) === 'promise')) return 'promise';
    if (t.types.some((m) => inferTypeFromTsAnnotation(m) === 'array')) return 'array';
  }
  if (t.type === 'TSTypeLiteral') return 'object';
  return 'unknown';
}

function inferExprType(node, localTypes) {
  if (!node) return 'unknown';
  if (node.type === 'ArrayExpression') return 'array';
  if (node.type === 'ObjectExpression') return 'object';
  if (node.type === 'NullLiteral') return 'nullable';
  if (node.type === 'Identifier') {
    if (node.name === 'undefined') return 'nullable';
    return localTypes.get(node.name) || 'unknown';
  }
  if (node.type === 'NewExpression') {
    const cal = memberPath(node.callee);
    if (cal === 'Promise') return 'promise';
    if (cal === 'Array') return 'array';
    if (cal === 'Map' || cal === 'Set' || cal === 'Object') return 'object';
  }
  if (node.type === 'CallExpression') {
    const cal = memberPath(node.callee);
    if (['fetch', 'Promise.resolve', 'Promise.reject', 'Promise.all', 'Promise.allSettled', 'Promise.race'].includes(cal)) {
      return 'promise';
    }
    if (/^(?:crypto\.)?create(?:Hmac|Hash|Cipheriv|Decipheriv)$/.test(cal)) return 'crypto';
    if (['Array.from', 'Object.keys', 'Object.values', 'Object.entries'].includes(cal)) return 'array';
    if (localTypes.get(`fn:${cal}`) === 'promise') return 'promise';
    if (localTypes.get(`fn:${cal}`) === 'array') return 'array';
    if (localTypes.get(`fn:${cal}`) === 'nullable') return 'nullable';
  }
  if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') {
    if (node.async) return 'fn:promise';
    const ann = inferTypeFromTsAnnotation(node.returnType);
    if (ann !== 'unknown') return `fn:${ann}`;
  }
  return 'unknown';
}

function resolveImportTarget(source, fromFile, fileSet) {
  if (!source || !source.startsWith('.')) return null;
  const dir = path.posix.dirname(fromFile);
  const base = path.posix.normalize(path.posix.join(dir, source));
  const candidates = [
    base,
    `${base}.js`, `${base}.ts`, `${base}.jsx`, `${base}.tsx`, `${base}.mjs`, `${base}.cjs`,
    `${base}/index.js`, `${base}/index.ts`, `${base}/index.jsx`, `${base}/index.tsx`,
  ];
  for (const cand of candidates) {
    if (fileSet.has(cand)) return cand;
  }
  return null;
}

// --- Real Basic-Block CFG for Path-Sensitive Nullability Dataflow ---
const STATE_NON_NULL = 'NON_NULL';
const STATE_NULLISH = 'NULLISH';
const STATE_MAYBE = 'MAYBE_NULL';

function joinState(a, b) {
  if (!a) return b || STATE_MAYBE;
  if (!b) return a;
  if (a === b) return a;
  return STATE_MAYBE;
}

function joinEnv(envA, envB) {
  if (!envA) return new Map(envB);
  if (!envB) return new Map(envA);
  const out = new Map();
  const keys = new Set([...envA.keys(), ...envB.keys()]);
  for (const k of keys) {
    const va = envA.get(k);
    const vb = envB.get(k);
    if (va && vb) out.set(k, joinState(va, vb));
    else out.set(k, va || vb);
  }
  return out;
}

function cloneEnv(env) {
  return new Map(env);
}

function envEquals(a, b) {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    if (b.get(k) !== v) return false;
  }
  return true;
}

// Extract null-check condition: returns { name, isNullWhenTrue } or null
function parseNullTest(testNode) {
  if (!testNode) return null;
  if (testNode.type === 'AssignmentExpression' && testNode.left?.type === 'Identifier') {
    return { name: testNode.left.name, isNullWhenTrue: false };
  }
  if (testNode.type === 'UnaryExpression' && testNode.operator === '!' && testNode.argument?.type === 'Identifier') {
    return { name: testNode.argument.name, isNullWhenTrue: true };
  }
  if (testNode.type === 'Identifier') {
    return { name: testNode.name, isNullWhenTrue: false };
  }
  if (testNode.type === 'BinaryExpression' && ['==', '===', '!=', '!=='].includes(testNode.operator)) {
    const isEq = testNode.operator === '==' || testNode.operator === '===';
    const checkSide = (a, b) => {
      const targetName = a?.type === 'Identifier'
        ? a.name
        : (a?.type === 'AssignmentExpression' && a.left?.type === 'Identifier' ? a.left.name : null);
      if (targetName && (b?.type === 'NullLiteral' || (b?.type === 'Identifier' && b.name === 'undefined'))) {
        return { name: targetName, isNullWhenTrue: isEq };
      }
      return null;
    };
    return checkSide(testNode.left, testNode.right) || checkSide(testNode.right, testNode.left);
  }
  if (testNode.type === 'LogicalExpression' && testNode.operator === '||') {
    const left = parseNullTest(testNode.left);
    if (left && left.isNullWhenTrue) return { name: left.name, isNullWhenTrue: true, compoundOr: true };
  }
  if (testNode.type === 'LogicalExpression' && testNode.operator === '&&') {
    const left = parseNullTest(testNode.left);
    if (left && !left.isNullWhenTrue) return { name: left.name, isNullWhenTrue: false, compoundAnd: true };
  }
  return null;
}

function applyGuard(env, guard, truthy) {
  if (!guard) return env;
  const next = cloneEnv(env);
  if (truthy) {
    if (guard.isNullWhenTrue && !guard.compoundOr) next.set(guard.name, STATE_NULLISH);
    else if (!guard.isNullWhenTrue) next.set(guard.name, STATE_NON_NULL);
  } else {
    if (guard.isNullWhenTrue) next.set(guard.name, STATE_NON_NULL);
    else if (!guard.compoundAnd) next.set(guard.name, STATE_NULLISH);
  }
  return next;
}

function buildCfgForBody(stmts) {
  const blocks = [];
  const newBlock = () => {
    const b = { id: blocks.length, stmts: [], succs: [], terminated: false, testNode: null };
    blocks.push(b);
    return b;
  };

  function compileList(list, current) {
    let cur = current;
    for (const stmt of list) {
      if (!stmt || cur.terminated) break;
      if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement' || stmt.type === 'ContinueStatement' || stmt.type === 'BreakStatement') {
        cur.stmts.push(stmt);
        cur.terminated = true;
        break;
      }
      if (stmt.type === 'IfStatement') {
        const guard = parseNullTest(stmt.test);
        cur.stmts.push({ type: 'CfgTest', expr: stmt.test, loc: stmt.loc });
        const thenEntry = newBlock();
        const elseEntry = newBlock();
        const joinBlock = newBlock();
        cur.succs.push({ target: thenEntry.id, guard, truthy: true });
        cur.succs.push({ target: elseEntry.id, guard, truthy: false });

        const thenStmts = stmt.consequent?.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent];
        const thenEnd = compileList(thenStmts, thenEntry);
        if (!thenEnd.terminated) thenEnd.succs.push({ target: joinBlock.id });

        let elseEnd = elseEntry;
        if (stmt.alternate) {
          const altStmts = stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate];
          elseEnd = compileList(altStmts, elseEntry);
        }
        if (!elseEnd.terminated) elseEnd.succs.push({ target: joinBlock.id });

        cur = joinBlock;
        continue;
      }
      if (stmt.type === 'BlockStatement') {
        cur = compileList(stmt.body, cur);
        continue;
      }
      if (stmt.type === 'WhileStatement' || stmt.type === 'ForStatement') {
        const guard = parseNullTest(stmt.test);
        const bodyEntry = newBlock();
        const afterLoop = newBlock();
        cur.succs.push({ target: bodyEntry.id, guard, truthy: true });
        cur.succs.push({ target: afterLoop.id, guard, truthy: false });
        const bodyStmts = stmt.body?.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
        const bodyEnd = compileList(bodyStmts, bodyEntry);
        if (!bodyEnd.terminated) bodyEnd.succs.push({ target: afterLoop.id });
        cur = afterLoop;
        continue;
      }
      if (stmt.type === 'TryStatement') {
        const tryEnd = compileList(stmt.block?.body || [], cur);
        if (stmt.handler?.body) {
          const catchEntry = newBlock();
          cur.succs.push({ target: catchEntry.id });
          const catchEnd = compileList(stmt.handler.body.body || [], catchEntry);
          const joinBlock = newBlock();
          if (!tryEnd.terminated) tryEnd.succs.push({ target: joinBlock.id });
          if (!catchEnd.terminated) catchEnd.succs.push({ target: joinBlock.id });
          cur = stmt.finalizer ? compileList(stmt.finalizer.body || [], joinBlock) : joinBlock;
        } else {
          cur = stmt.finalizer ? compileList(stmt.finalizer.body || [], tryEnd) : tryEnd;
        }
        continue;
      }
      cur.stmts.push(stmt);
    }
    return cur;
  }

  const entry = newBlock();
  compileList(stmts || [], entry);
  return blocks;
}

function collectGuardedNamesInExpr(expr, outSet) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.type === 'Identifier') { outSet.add(expr.name); return; }
  if (expr.type === 'BinaryExpression' && (expr.operator === '!==' || expr.operator === '!=')) {
    if (expr.left?.type === 'Identifier' && (expr.right?.type === 'NullLiteral' || (expr.right?.type === 'Identifier' && expr.right.name === 'undefined'))) {
      outSet.add(expr.left.name);
    }
    return;
  }
  if (expr.type === 'LogicalExpression' && expr.operator === '&&') {
    collectGuardedNamesInExpr(expr.left, outSet);
    collectGuardedNamesInExpr(expr.right, outSet);
  }
}

function collectDerefsInStmt(stmt, out, guarded = new Set()) {
  function scan(node, parent, activeGuarded) {
    if (!node || typeof node !== 'object') return;
    if (node !== stmt && (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression')) {
      return;
    }
    if (node.type === 'LogicalExpression' && node.operator === '&&') {
      scan(node.left, node, activeGuarded);
      const nextGuarded = new Set(activeGuarded);
      collectGuardedNamesInExpr(node.left, nextGuarded);
      scan(node.right, node, nextGuarded);
      return;
    }
    if (node.type === 'ConditionalExpression') {
      scan(node.test, node, activeGuarded);
      const nextGuarded = new Set(activeGuarded);
      collectGuardedNamesInExpr(node.test, nextGuarded);
      scan(node.consequent, node, nextGuarded);
      scan(node.alternate, node, activeGuarded);
      return;
    }
    if (node.type === 'MemberExpression' && !node.optional && node.object?.type === 'Identifier') {
      if (!activeGuarded.has(node.object.name)) {
        out.push({ name: node.object.name, line: node.loc?.start?.line || stmt.loc?.start?.line || 1, node });
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra') continue;
      const val = node[key];
      if (Array.isArray(val)) {
        for (const item of val) {
          if (item && typeof item.type === 'string') scan(item, node, activeGuarded);
        }
      } else if (val && typeof val.type === 'string') {
        scan(val, node, activeGuarded);
      }
    }
    void parent;
  }
  scan(stmt, null, guarded);
}

function transferStmt(stmt, env, nullRisks) {
  if (stmt.type === 'ForOfStatement' || stmt.type === 'ForInStatement') {
    const loopVar = stmt.left?.type === 'VariableDeclaration'
      ? stmt.left.declarations?.[0]?.id?.name
      : stmt.left?.type === 'Identifier' ? stmt.left.name : null;
    if (loopVar) env.delete(loopVar);
  }
  // Check derefs BEFORE statement mutations if stmt is not an assignment to the variable itself
  const derefs = [];
  collectDerefsInStmt(stmt, derefs);
  for (const d of derefs) {
    const st = env.get(d.name);
    if (st === STATE_NULLISH || st === STATE_MAYBE) {
      // Avoid duplicate on same line
      if (!nullRisks.some((r) => r.name === d.name && r.line === d.line)) {
        nullRisks.push({ name: d.name, line: d.line, state: st });
      }
    }
  }

  // Update environment from declarations / assignments
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id?.type !== 'Identifier') continue;
      if (!decl.init || decl.init.type === 'NullLiteral' || (decl.init.type === 'Identifier' && decl.init.name === 'undefined')) {
        env.set(decl.id.name, STATE_NULLISH);
      } else if (decl.init.type === 'ObjectExpression' || decl.init.type === 'ArrayExpression' || decl.init.type === 'NewExpression' || decl.init.type === 'StringLiteral' || decl.init.type === 'NumericLiteral') {
        env.set(decl.id.name, STATE_NON_NULL);
      } else {
        // Could be nullable if annotated or returned from find/get
        const ann = inferTypeFromTsAnnotation(decl.id.typeAnnotation);
        if (ann === 'nullable') env.set(decl.id.name, STATE_MAYBE);
        else env.delete(decl.id.name);
      }
    }
  } else if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'AssignmentExpression' && stmt.expression.left?.type === 'Identifier') {
    const rhs = stmt.expression.right;
    const name = stmt.expression.left.name;
    if (rhs?.type === 'NullLiteral' || (rhs?.type === 'Identifier' && rhs.name === 'undefined')) {
      env.set(name, STATE_NULLISH);
    } else if (rhs) {
      env.set(name, STATE_NON_NULL);
    }
  }
}

function analyzeFunctionCfg(fnNode, rel, lines, makeFinding, isSuppressed, suppressions) {
  const body = fnNode.body;
  if (!body || body.type !== 'BlockStatement') return [];
  const blocks = buildCfgForBody(body.body);
  const inEnvs = blocks.map(() => null);
  const outEnvs = blocks.map(() => null);
  const initEnv = new Map();

  // Seed nullable TS parameters
  for (const p of fnNode.params || []) {
    if (p.type === 'Identifier' && inferTypeFromTsAnnotation(p.typeAnnotation) === 'nullable') {
      initEnv.set(p.name, STATE_MAYBE);
    }
  }
  inEnvs[0] = initEnv;

  const worklist = [0];
  let steps = 0;
  while (worklist.length > 0 && steps++ < 500) {
    const id = worklist.shift();
    const block = blocks[id];
    const curEnv = cloneEnv(inEnvs[id] || new Map());
    const dummyRisks = [];
    for (const stmt of block.stmts) {
      transferStmt(stmt, curEnv, dummyRisks);
    }
    outEnvs[id] = curEnv;
    for (const edge of block.succs) {
      const edgeEnv = edge.guard ? applyGuard(curEnv, edge.guard, edge.truthy) : cloneEnv(curEnv);
      const prevIn = inEnvs[edge.target];
      const merged = prevIn ? joinEnv(prevIn, edgeEnv) : edgeEnv;
      if (!prevIn || !envEquals(prevIn, merged)) {
        inEnvs[edge.target] = merged;
        if (!worklist.includes(edge.target)) worklist.push(edge.target);
      }
    }
  }

  // Final pass to collect confirmed null-deref risks
  const findings = [];
  const seen = new Set();
  for (let i = 0; i < blocks.length; i++) {
    if (!inEnvs[i]) continue;
    const env = cloneEnv(inEnvs[i]);
    const risks = [];
    for (const stmt of blocks[i].stmts) {
      transferStmt(stmt, env, risks);
    }
    for (const r of risks) {
      const key = `${r.name}:${r.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (isSuppressed && isSuppressed(suppressions, r.line, 'cfg-null-deref')) continue;
      findings.push(makeFinding({
        id: 'cfg-null-deref',
        title: `Path-sensitive null/undefined dereference of "${r.name}"`,
        severity: 'high',
        cwe: 'CWE-476',
        confidence: 'high',
        reason: `CFG dataflow proves "${r.name}" can be null/undefined on a reachable control-flow path at line ${r.line}.`,
        hint: `Guard "${r.name}" with an early return, throw, fallback assignment, or optional chaining (?.).`,
      }, rel, r.line, lines[r.line - 1] || ''));
    }
  }
  return findings;
}

async function analyzeTypeAndCfgProject(jsFiles, helpers, scanRoot) {
  const { makeFinding, parseSuppressions, isSuppressed } = helpers;
  const findings = [];
  if (!Array.isArray(jsFiles) || jsFiles.length === 0) return { findings, suppressRegexIds: new Map() };

  const dtsIndex = await indexDtsPromiseFns(scanRoot, jsFiles);
  const parsedFiles = new Map();
  const fileSet = new Set(jsFiles.map((f) => f.rel));
  const exportedTypes = new Map(); // file -> Map<exportName, type>
  const suppressRegexIds = new Map(); // "rel:line" -> Set<ruleId> (to suppress regex FPs proved safe by type checker)

  // Pass 1: Parse & collect exported function/variable types across all project files
  for (const f of jsFiles) {
    const ext = path.extname(f.rel).toLowerCase();
    const ast = parseAst(f.raw, ext);
    if (!ast) continue;
    parsedFiles.set(f.rel, { ...f, ast, lines: f.raw.split(/\r?\n/) });

    const fileExports = new Map();
    walk(ast.program, (node) => {
      if (node.type === 'ExportNamedDeclaration') {
        const decl = node.declaration;
        if (decl?.type === 'FunctionDeclaration' && decl.id?.name) {
          const ann = inferTypeFromTsAnnotation(decl.returnType);
          const ret = decl.async ? 'promise' : ann;
          if (ret !== 'unknown') fileExports.set(decl.id.name, ret);
        } else if (decl?.type === 'VariableDeclaration') {
          for (const d of decl.declarations) {
            if (d.id?.type === 'Identifier' && d.init) {
              const t = inferExprType(d.init, new Map());
              if (t.startsWith('fn:')) fileExports.set(d.id.name, t.slice(3));
              else if (t !== 'unknown') fileExports.set(d.id.name, t);
            }
          }
        }
      }
      if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression') {
        const lp = memberPath(node.left);
        if (lp.startsWith('module.exports.') || lp.startsWith('exports.')) {
          const name = lp.split('.').pop();
          if (node.right?.async) fileExports.set(name, 'promise');
        }
      }
    });
    exportedTypes.set(f.rel, fileExports);
  }

  // Pass 2: Type-aware checks + CFG nullability per file
  for (const [rel, info] of parsedFiles) {
    const { ast, lines } = info;
    const suppressions = parseSuppressions ? parseSuppressions(lines) : null;
    const localTypes = new Map();

    // Resolve imported symbol types (from project files, local .d.ts, and node_modules .d.ts)
    for (const stmt of ast.program.body) {
      if (stmt.type === 'ImportDeclaration') {
        const src = stmt.source?.value || '';
        const target = resolveImportTarget(src, rel, fileSet);
        const exp = target ? exportedTypes.get(target) : null;
        const pkgDts = !src.startsWith('.') ? dtsIndex.pkgPromiseFns.get(src) : null;
        const localDts = target ? dtsIndex.localDts.get(target.replace(/\.[cm]?[jt]sx?$/, '.d.ts')) : null;
        for (const spec of stmt.specifiers) {
          const importedName = spec.imported?.name || spec.local?.name;
          const localName = spec.local?.name;
          if (!localName) continue;
          const t = exp?.get(importedName);
          if (t) localTypes.set(`fn:${localName}`, t);
          else if (pkgDts?.has(importedName) || localDts?.has(importedName)) {
            localTypes.set(`fn:${localName}`, 'promise');
          }
        }
      }
    }

    // Collect local variable & function types
    walk(ast.program, (node) => {
      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        const ann = inferTypeFromTsAnnotation(node.returnType);
        const ret = node.async ? 'promise' : ann;
        if (ret !== 'unknown') localTypes.set(`fn:${node.id.name}`, ret);
      }
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
        const ann = inferTypeFromTsAnnotation(node.id.typeAnnotation);
        const initT = inferExprType(node.init, localTypes);
        const resolved = ann !== 'unknown' ? ann : initT;
        if (resolved.startsWith('fn:')) localTypes.set(`fn:${node.id.name}`, resolved.slice(3));
        else if (resolved !== 'unknown') localTypes.set(node.id.name, resolved);
      }
    });

    // Type-aware checks:
    walk(ast.program, (node, parent) => {
      // 1. Type-verified Floating Promise (across imported & local async functions)
      if (node.type === 'ExpressionStatement' && node.expression?.type === 'CallExpression') {
        const call = node.expression;
        const calPath = memberPath(call.callee);
        const isPromiseCall = localTypes.get(`fn:${calPath}`) === 'promise';
        const line = call.loc?.start?.line || 1;
        if (isPromiseCall && !(isSuppressed && isSuppressed(suppressions, line, 'type-floating-promise'))) {
          findings.push(makeFinding({
            id: 'type-floating-promise',
            title: `Unawaited Promise call "${calPath}()"`,
            severity: 'high',
            cwe: 'CWE-252',
            confidence: 'high',
            reason: `Type inference confirms "${calPath}()" returns a Promise, but its result is neither awaited, returned, nor handled with .catch().`,
            hint: `Await "${calPath}()" or handle its Promise rejection explicitly.`,
          }, rel, line, lines[line - 1] || ''));
        }
      }

      // 2. Type-verified delete arr[idx] vs plain object delete obj[key]
      if (node.type === 'UnaryExpression' && node.operator === 'delete' && node.argument?.type === 'MemberExpression') {
        const obj = node.argument.object;
        const line = node.loc?.start?.line || 1;
        const objType = obj?.type === 'Identifier' ? localTypes.get(obj.name) : 'unknown';
        if (objType === 'array') {
          if (!(isSuppressed && isSuppressed(suppressions, line, 'type-delete-array-element'))) {
            findings.push(makeFinding({
              id: 'type-delete-array-element',
              title: 'Using delete on a typed Array creates a sparse hole',
              severity: 'medium',
              cwe: 'CWE-665',
              confidence: 'high',
              reason: `Variable "${obj.name}" is typed/initialized as an Array; delete leaves an undefined hole instead of removing the element.`,
              hint: 'Use .splice(index, 1) or .filter() to remove array items cleanly.',
            }, rel, line, lines[line - 1] || ''));
          }
        } else if (objType === 'object') {
          const key = `${rel}:${line}`;
          if (!suppressRegexIds.has(key)) suppressRegexIds.set(key, new Set());
          suppressRegexIds.get(key).add('exp-logic-delete-array-index');
        }
      }

      // 3. Crypto HMAC/Hash .update(req.body) suppression for regex/ORM mass assignment
      if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression' && node.callee.property?.name === 'update') {
        const rootObj = node.callee.object;
        const objType = rootObj?.type === 'Identifier' ? localTypes.get(rootObj.name) : inferExprType(rootObj, localTypes);
        if (objType === 'crypto') {
          const line = node.loc?.start?.line || 1;
          const key = `${rel}:${line}`;
          if (!suppressRegexIds.has(key)) suppressRegexIds.set(key, new Set());
          suppressRegexIds.get(key).add('js-mass-assignment-db');
        }
      }
      void parent;
    });

    // Real CFG Nullability Analysis per function
    walk(ast.program, (node) => {
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
        findings.push(...analyzeFunctionCfg(node, rel, lines, makeFinding, isSuppressed, suppressions));
      }
    });
  }

  return { findings, suppressRegexIds };
}

module.exports = {
  analyzeTypeAndCfgProject,
  buildCfgForBody,
  parseNullTest,
};
