'use strict';

const { parse } = require('@babel/parser');

const USER_INPUT = /(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params|headers|cookies)|searchParams\.|URLSearchParams|location\.(?:search|hash)|event\.target\.value|e\.target\.value|stdin|userInput|user_input|untrusted|payload|message)/i;
const SANITIZER = /\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|escapeRegExp|encodeURIComponent|encodeURI|Number|parseInt|parseFloat|Boolean|validator\.escape|path\.basename|pick|omit|html\.escape|shlex\.quote|ast\.literal_eval)\s*\(/;
const SENSITIVE_NAME = /(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|jwt|credential|auth[_-]?header|session[_-]?id)/i;
const SECRET_FN_NAME = /(?:token|secret|password|salt|nonce|key|session|otp|auth|csrf|uuid)/i;
const FILE_SINKS = new Set(['readFile', 'readFileSync', 'createReadStream', 'sendFile', 'download', 'writeFile', 'writeFileSync', 'unlink', 'unlinkSync', 'open', 'openSync', 'copyFile', 'rename']);
const KNOWN_GLOBALS = new Set([
  'window', 'document', 'console', 'process', 'require', 'module', 'exports', 'global', 'globalThis',
  'Buffer', 'URL', 'URLSearchParams', 'FormData', 'fetch', 'setTimeout', 'setInterval', 'clearTimeout',
  'clearInterval', 'setImmediate', 'clearImmediate', 'queueMicrotask', 'Promise', 'Error', 'TypeError',
  'RangeError', 'SyntaxError', 'ReferenceError', 'JSON', 'Math', 'Object', 'Array', 'String', 'Number',
  'Boolean', 'Date', 'RegExp', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Symbol', 'BigInt', 'Int8Array',
  'Uint8Array', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent', 'decodeURIComponent',
  'encodeURI', 'decodeURI', 'atob', 'btoa', 'navigator', 'location', 'history', 'localStorage',
  'sessionStorage', 'alert', 'confirm', 'prompt', 'performance', 'crypto', 'AbortController',
  'AbortSignal', 'Headers', 'Request', 'Response', 'Event', 'CustomEvent', 'HTMLElement', 'Node',
  'Element', 'describe', 'it', 'test', 'expect', 'beforeEach', 'afterEach', 'beforeAll', 'afterAll',
  'vi', 'jest', 'arguments', 'undefined', 'NaN', 'Infinity', 'eval', 'Function', 'Reflect', 'Proxy',
  'Intl', 'WebAssembly', 'this', 'super', '__dirname', '__filename',
  'getComputedStyle', 'requestAnimationFrame', 'cancelAnimationFrame', 'requestIdleCallback',
  'cancelIdleCallback', 'matchMedia', 'IntersectionObserver', 'ResizeObserver', 'MutationObserver',
  'XMLHttpRequest', 'FileReader', 'Blob', 'File', 'TextEncoder', 'TextDecoder', 'structuredClone',
  'EventTarget', 'NodeList', 'DOMParser', 'XMLSerializer', 'getSelection', 'scrollTo', 'scrollBy',
  'Float32Array', 'Float64Array', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'Uint8ClampedArray',
  'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'indexedDB', 'Image', 'Audio', 'Option',
  'HTMLCanvasElement', 'HTMLImageElement', 'HTMLVideoElement', 'HTMLAudioElement', 'HTMLInputElement', 'HTMLMediaElement',
  'MediaRecorder', 'MediaStream', 'AudioContext', 'OfflineAudioContext', 'AudioBuffer', 'WebSocket', 'EventSource',
  'Worker', 'SharedWorker', 'BroadcastChannel', 'Notification', 'Storage', 'screen', 'devicePixelRatio', 'CSS',
  'createImageBitmap', 'OffscreenCanvas', 'Path2D', 'FontFace', 'PerformanceObserver', 'ResizeObserver', 'IntersectionObserver', 'MutationObserver',
]);

function staticText(node) {
  return node?.type === 'StringLiteral'
    || node?.type === 'NumericLiteral'
    || (node?.type === 'TemplateLiteral' && node.expressions.length === 0);
}

function memberName(node) {
  if (node?.type !== 'MemberExpression' && node?.type !== 'OptionalMemberExpression') return '';
  if (!node.computed && node.property?.type === 'Identifier') return node.property.name;
  if (node.computed && node.property?.type === 'StringLiteral') return node.property.value;
  return '';
}

function identifierName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') return memberName(node);
  return '';
}

function walkSubtree(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (visitor(node) === false) return;
  for (const [key, value] of Object.entries(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra' || key === 'errors' || key === 'comments' || key === 'tokens') continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === 'object' && typeof item.type === 'string') walkSubtree(item, visitor);
      }
    } else if (value && typeof value === 'object' && typeof value.type === 'string') {
      walkSubtree(value, visitor);
    }
  }
}

function collectIdentifierNames(node, out = new Set()) {
  walkSubtree(node, (sub) => {
    if (sub.type === 'Identifier') out.add(sub.name);
  });
  return out;
}

function collectAssignedTargets(node, out = new Set()) {
  walkSubtree(node, (sub) => {
    if (sub.type === 'AssignmentExpression' && sub.left?.type === 'Identifier') out.add(sub.left.name);
    if (sub.type === 'UpdateExpression' && sub.argument?.type === 'Identifier') out.add(sub.argument.name);
  });
  return out;
}

function isSimpleBody(block) {
  return Array.isArray(block?.body) ? block.body : block ? [block] : [];
}

function collectPatternBindings(pattern, out) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') { out.add(pattern.name); return; }
  if (pattern.type === 'AssignmentPattern') { collectPatternBindings(pattern.left, out); return; }
  if (pattern.type === 'RestElement') { collectPatternBindings(pattern.argument, out); return; }
  if (pattern.type === 'ArrayPattern') { for (const el of pattern.elements) collectPatternBindings(el, out); return; }
  if (pattern.type === 'ObjectPattern') {
    for (const prop of pattern.properties) {
      if (prop.type === 'RestElement') collectPatternBindings(prop.argument, out);
      else if (prop.type === 'ObjectProperty') collectPatternBindings(prop.value, out);
    }
  }
}

function collectScopeBindings(statements, out) {
  for (const stmt of statements || []) {
    if (!stmt) continue;
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) collectPatternBindings(decl.id, out);
    } else if (stmt.type === 'FunctionDeclaration' || stmt.type === 'ClassDeclaration') {
      if (stmt.id?.name) out.add(stmt.id.name);
    } else if (stmt.type === 'ImportDeclaration') {
      for (const spec of stmt.specifiers || []) {
        if (spec.local?.name) out.add(spec.local.name);
      }
    } else if (stmt.type === 'ExportNamedDeclaration' || stmt.type === 'ExportDefaultDeclaration') {
      collectScopeBindings([stmt.declaration], out);
    }
  }
}

function checkBlockStatements(statements, emit) {
  let terminated = false;
  for (const stmt of statements) {
    if (terminated && stmt.type !== 'FunctionDeclaration' && stmt.type !== 'EmptyStatement') {
      emit({
        ruleId: 'js-unreachable-code',
        title: 'Unreachable code',
        severity: 'low',
        cwe: 'CWE-561',
        hint: 'Remove dead statements after return, throw, break, or continue.',
      }, stmt, 'high', 'Statement follows an unconditional control-flow exit in the same block.');
      terminated = false;
    }
    if (['ReturnStatement', 'ThrowStatement', 'BreakStatement', 'ContinueStatement'].includes(stmt.type)) {
      terminated = true;
    }
  }
}

const VALID_TYPEOF = new Set(['undefined', 'object', 'boolean', 'number', 'bigint', 'string', 'symbol', 'function']);
const NUMERIC_MEMBER = new Set(['length', 'size', 'count', 'index', 'byteLength']);

function isNumericExpr(node, numericVars) {
  if (!node) return false;
  if (node.type === 'NumericLiteral') return true;
  if (node.type === 'Identifier') return numericVars.has(node.name);
  if (node.type === 'MemberExpression' && NUMERIC_MEMBER.has(memberName(node))) return true;
  if (node.type === 'UnaryExpression' && ['+', '-', '~'].includes(node.operator)) return isNumericExpr(node.argument, numericVars);
  if (node.type === 'BinaryExpression' && ['+', '-', '*', '/', '%', '**'].includes(node.operator)) {
    return isNumericExpr(node.left, numericVars) && isNumericExpr(node.right, numericVars);
  }
  if (node.type === 'CallExpression') {
    const name = node.callee?.type === 'Identifier' ? node.callee.name : memberName(node.callee);
    if (['Number', 'parseInt', 'parseFloat'].includes(name)) return true;
    if (node.callee?.object?.name === 'Math') return true;
  }
  return false;
}

function isSafeHtmlValue(node, numericVars, safeHtmlVars) {
  if (!node) return false;
  if (staticText(node) || isNumericExpr(node, numericVars)) return true;
  if (node.type === 'Identifier') return safeHtmlVars.has(node.name);
  if (node.type === 'TemplateLiteral') {
    return node.expressions.every((expr) => isSafeHtmlValue(expr, numericVars, safeHtmlVars));
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isSafeHtmlValue(node.left, numericVars, safeHtmlVars) && isSafeHtmlValue(node.right, numericVars, safeHtmlVars);
  }
  if (node.type === 'ConditionalExpression') {
    return isSafeHtmlValue(node.consequent, numericVars, safeHtmlVars) && isSafeHtmlValue(node.alternate, numericVars, safeHtmlVars);
  }
  return false;
}

function analyzeJavaScriptAst(raw, file, catalog, taint, suppressions, makeFinding, suppressed, options = {}) {
  const lineOffset = options.lineOffset || 0;
  let ast;
  try {
    ast = parse(raw, {
      sourceType: 'unambiguous',
      errorRecovery: true,
      plugins: ['jsx', 'typescript'],
    });
  } catch {
    return [];
  }

  const rules = new Map(catalog.map((rule) => [rule.id, rule]));
  const lines = raw.split(/\r?\n/);
  const findings = [];
  const emitted = new Set();

  const markSafeRuleLine = (ruleId, nodeOrLine) => {
    if (!options.safeRuleLines) return;
    const localLine = typeof nodeOrLine === 'number' ? nodeOrLine : nodeOrLine?.loc?.start.line;
    if (!localLine) return;
    let set = options.safeRuleLines.get(ruleId);
    if (!set) {
      set = new Set();
      options.safeRuleLines.set(ruleId, set);
    }
    set.add(localLine + lineOffset);
  };

  const emit = (ruleOrId, nodeOrLine, confidence = 'medium', reason) => {
    const rule = typeof ruleOrId === 'string' ? rules.get(ruleOrId) : ruleOrId;
    const localLine = typeof nodeOrLine === 'number' ? nodeOrLine : nodeOrLine?.loc?.start.line;
    if (!rule || !localLine || !lines[localLine - 1]) return;
    const reportLine = localLine + lineOffset;
    if (suppressed(suppressions, reportLine, rule.id) || emitted.has(`${rule.id}:${reportLine}`)) return;
    emitted.add(`${rule.id}:${reportLine}`);
    findings.push(makeFinding(rule, file, reportLine, lines[localLine - 1], {
      confidence,
      reason: reason || 'Syntax-aware match; validate the surrounding code.',
    }));
  };

  if (Array.isArray(ast.errors)) {
    for (const err of ast.errors.slice(0, 10)) {
      const localLine = err.loc?.line;
      if (localLine) {
        emit({
          id: 'js-syntax-error',
          title: 'JavaScript/TypeScript syntax error',
          severity: 'medium',
          cwe: 'CWE-1077',
          hint: 'Fix the syntax error reported by the parser.',
        }, localLine, 'high', err.message ? err.message.split(' (')[0] : 'Parser reported a syntax error.');
      }
    }
  }

  const isDynamicSql = (node) => {
    if (!node) return false;
    const sqlClause = /(?:\bSELECT\b[\s\S]{1,80}\bFROM\b|\bINSERT\b[\s\S]{1,40}\bINTO\b|\bUPDATE\b[\s\S]{1,40}\bSET\b|\bDELETE\b[\s\S]{1,40}\bFROM\b)/i;
    if (node.type === 'TemplateLiteral') return node.expressions.length > 0 && sqlClause.test(raw.slice(node.start, node.end));
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const source = raw.slice(node.start, node.end);
      return sqlClause.test(source) && (node.left.type !== 'StringLiteral' || node.right.type !== 'StringLiteral');
    }
    return false;
  };

  const containsInput = (node) => {
    if (!node) return false;
    const source = raw.slice(node.start, node.end);
    if (SANITIZER.test(source)) return false;
    if (USER_INPUT.test(source)) return true;
    const names = taint.byLine[(node.loc?.start.line || 1) - 1] || new Set();
    return [...names].some((name) => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(^|[^\\w$])${escaped}(?=$|[^\\w$])`).test(source);
    });
  };

  const fnStack = [];
  const scopeStack = [];
  const topScope = new Set();
  collectScopeBindings(ast.program?.body, topScope);
  scopeStack.push(topScope);
  const declaredGlobals = new Set(topScope);
  const isDeclared = (name) => KNOWN_GLOBALS.has(name) || scopeStack.some((s) => s.has(name));

  // Pre-collect numeric variables, safe-HTML accumulators, and async function names.
  const numericVars = new Set();
  const safeHtmlVars = new Set();
  const asyncFnNames = new Set();
  const unsafeHtmlVars = new Set();
  walkSubtree(ast, (n) => {
    if ((n.type === 'FunctionDeclaration' || n.type === 'VariableDeclarator') && n.async && n.id?.name) {
      asyncFnNames.add(n.id.name);
    }
    if (n.type === 'FunctionDeclaration' && n.async && n.id?.name) asyncFnNames.add(n.id.name);
    if (n.type === 'ForStatement' && n.init?.type === 'VariableDeclaration') {
      for (const d of n.init.declarations) {
        if (d.id?.type === 'Identifier' && isNumericExpr(d.init, numericVars)) numericVars.add(d.id.name);
      }
    }
    if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier' && n.init) {
      if (isNumericExpr(n.init, numericVars)) numericVars.add(n.id.name);
      else if (staticText(n.init)) safeHtmlVars.add(n.id.name);
    }
    if (n.type === 'BinaryExpression' && ['<=', '<', '>', '>=', '!==', '===', '==', '!='].includes(n.operator)) {
      if (n.left?.type === 'Identifier' && isNumericExpr(n.right, numericVars)) numericVars.add(n.left.name);
      if (n.right?.type === 'Identifier' && isNumericExpr(n.left, numericVars)) numericVars.add(n.right.name);
    }
  });
  walkSubtree(ast, (n) => {
    if (n.type === 'AssignmentExpression' && n.left?.type === 'Identifier') {
      const name = n.left.name;
      if (n.operator === '+=' && safeHtmlVars.has(name)) {
        if (!isSafeHtmlValue(n.right, numericVars, safeHtmlVars)) unsafeHtmlVars.add(name);
      } else if (n.operator === '=') {
        if (!isSafeHtmlValue(n.right, numericVars, safeHtmlVars)) unsafeHtmlVars.add(name);
      }
    }
  });
  for (const name of unsafeHtmlVars) safeHtmlVars.delete(name);

  const visit = (node, parent, parentKey, inReexport = false) => {
    if (!node || typeof node !== 'object') return;
    const line = node.loc?.start.line;

    if (node.type === 'Program' || node.type === 'BlockStatement') {
      checkBlockStatements(node.body || [], (meta, stmt, conf, reason) => {
        emit({ id: meta.ruleId, ...meta }, stmt, conf, reason);
      });
    }

    let pushedBlockScope = false;
    if (node.type === 'BlockStatement') {
      const blockScope = new Set();
      collectScopeBindings(node.body, blockScope);
      scopeStack.push(blockScope);
      pushedBlockScope = true;
    } else if (node.type === 'ForStatement' || node.type === 'ForInStatement' || node.type === 'ForOfStatement') {
      const loopScope = new Set();
      const decl = node.init || node.left;
      if (decl?.type === 'VariableDeclaration') {
        for (const d of decl.declarations) collectPatternBindings(d.id, loopScope);
      }
      scopeStack.push(loopScope);
      pushedBlockScope = true;
    } else if (node.type === 'CatchClause' && node.param) {
      const catchScope = new Set();
      collectPatternBindings(node.param, catchScope);
      scopeStack.push(catchScope);
      pushedBlockScope = true;
    }

    const isFn = node.type === 'FunctionDeclaration'
      || node.type === 'FunctionExpression'
      || node.type === 'ArrowFunctionExpression'
      || node.type === 'ObjectMethod'
      || node.type === 'ClassMethod';
    let fnName = '';
    if (isFn) {
      fnName = node.id?.name || '';
      const fnScope = new Set();
      if (fnName) fnScope.add(fnName);
      for (const p of node.params || []) collectPatternBindings(p, fnScope);
      if (node.body?.type === 'BlockStatement') collectScopeBindings(node.body.body, fnScope);
      scopeStack.push(fnScope);
      fnStack.push({ name: fnName, async: Boolean(node.async), body: node.body, params: new Set(node.params.filter((p) => p.type === 'Identifier').map((p) => p.name)) });

      // Detect fetch() response consumed without checking res.ok or res.status.
      if (node.async && node.body?.type === 'BlockStatement') {
        const bodySrc = raw.slice(node.body.start, node.body.end);
        if (/\bfetch\s*\(/.test(bodySrc) && /\.\s*(?:json|text|arrayBuffer|blob)\s*\(/.test(bodySrc) && !/\.(?:ok|status)\b/.test(bodySrc)) {
          let fetchNode = null;
          walkSubtree(node.body, (sub) => {
            if (!fetchNode && sub.type === 'CallExpression' && sub.callee?.type === 'Identifier' && sub.callee.name === 'fetch') fetchNode = sub;
          });
          if (fetchNode) {
            emit({
              id: 'js-fetch-no-ok-check',
              title: 'fetch() response parsed without status check',
              severity: 'low',
              cwe: 'CWE-252',
              hint: 'Check "if (!res.ok) throw new Error(...)" before calling res.json().',
            }, fetchNode, 'medium', 'fetch() rejects only on network failure; HTTP 4xx/5xx responses are not checked via res.ok.');
          }
        }
      }

      // Detect unconditional self-recursion (missing base-case guard).
      if (fnName && node.body?.type === 'BlockStatement') {
        let hasBranch = false;
        let selfCall = null;
        walkSubtree(node.body, (sub) => {
          if (sub !== node && (sub.type === 'FunctionDeclaration' || sub.type === 'FunctionExpression' || sub.type === 'ArrowFunctionExpression')) return false;
          if (['IfStatement', 'ConditionalExpression', 'SwitchStatement', 'LogicalExpression', 'ForStatement', 'WhileStatement', 'DoWhileStatement', 'TryStatement'].includes(sub.type)) {
            hasBranch = true;
          }
          if (!selfCall && sub.type === 'CallExpression' && sub.callee?.type === 'Identifier' && sub.callee.name === fnName) {
            selfCall = sub;
          }
        });
        if (selfCall && !hasBranch) {
          emit({
            id: 'js-unbounded-recursion',
            title: `Unconditional recursion in "${fnName}()"`,
            severity: 'high',
            cwe: 'CWE-674',
            hint: 'Add a base-case condition before recursing to avoid a RangeError stack overflow.',
          }, selfCall, 'high', `Function "${fnName}" calls itself without any conditional base-case guard.`);
        }
      }

      // Detect async read-modify-write race condition on outer/shared variables.
      if (node.async && node.body?.type === 'BlockStatement') {
        const stmts = node.body.body || [];
        let firstAwaitIdx = -1;
        for (let idx = 0; idx < stmts.length; idx++) {
          let hasAwait = false;
          walkSubtree(stmts[idx], (sub) => { if (sub.type === 'AwaitExpression') hasAwait = true; });
          if (hasAwait) { firstAwaitIdx = idx; break; }
        }
        if (firstAwaitIdx >= 0) {
          const readBeforeAwait = new Map();
          for (let idx = 0; idx < firstAwaitIdx; idx++) {
            const stmt = stmts[idx];
            if (stmt.type === 'VariableDeclaration') {
              for (const decl of stmt.declarations) {
                if (decl.id?.type === 'Identifier' && decl.init?.type === 'Identifier' && declaredGlobals.has(decl.init.name)) {
                  readBeforeAwait.set(decl.id.name, decl.init.name);
                }
              }
            }
          }
          for (let idx = firstAwaitIdx + 1; idx < stmts.length; idx++) {
            walkSubtree(stmts[idx], (sub) => {
              if (sub.type === 'AssignmentExpression' && sub.left?.type === 'Identifier' && declaredGlobals.has(sub.left.name)) {
                const rhsNames = collectIdentifierNames(sub.right);
                for (const [alias, shared] of readBeforeAwait.entries()) {
                  if (shared === sub.left.name && rhsNames.has(alias)) {
                    emit({
                      id: 'js-async-race-condition',
                      title: 'Async read-modify-write race condition',
                      severity: 'medium',
                      cwe: 'CWE-362',
                      hint: 'Re-read shared state after await or serialize concurrent writes.',
                    }, sub, 'high', `Shared variable "${shared}" is read before await and written afterwards using stale "${alias}".`);
                  }
                }
              }
            });
          }
        }
      }

      // Detect inverted parity check in isEven / isOdd functions.
      if (/^(?:isEven|isOdd)$/i.test(fnName)) {
        const expectOdd = /isOdd$/i.test(fnName);
        walkSubtree(node.body, (sub) => {
          if (sub.type === 'ReturnStatement' && sub.argument?.type === 'BinaryExpression') {
            const { operator, left, right } = sub.argument;
            if (['==', '===', '!=', '!=='].includes(operator) && left.type === 'BinaryExpression' && left.operator === '%' && left.right?.value === 2 && right?.type === 'NumericLiteral') {
              const checksOne = right.value === 1;
              const isNegated = operator.startsWith('!');
              const effectiveOdd = isNegated ? !checksOne : checksOne;
              if (effectiveOdd !== expectOdd) {
                emit({
                  id: 'js-suspicious-parity',
                  title: `Inverted parity check in ${fnName}`,
                  severity: 'medium',
                  cwe: 'CWE-670',
                  hint: `${fnName} checks the opposite remainder; verify "% 2 === ${expectOdd ? 1 : 0}".`,
                }, sub, 'high', `Function "${fnName}" returns ${effectiveOdd ? 'true for odd' : 'true for even'} numbers.`);
              }
            }
          }
        });
      }
    }

    // Off-by-one loop condition (<= .length) when the loop actually indexes targetObj[loopVar].
    if (node.type === 'ForStatement') {
      if (node.test?.type === 'BinaryExpression' && node.test.operator === '<=' && memberName(node.test.right) === 'length') {
        const targetObj = raw.slice(node.test.right.object.start, node.test.right.object.end);
        const loopVar = node.test.left?.type === 'Identifier' ? node.test.left.name : '';
        let indexesTargetDirectly = !loopVar;
        if (loopVar) {
          indexesTargetDirectly = false;
          walkSubtree(node.body, (sub) => {
            if (sub.type === 'MemberExpression' && sub.computed && sub.property?.type === 'Identifier' && sub.property.name === loopVar) {
              const objSrc = raw.slice(sub.object.start, sub.object.end);
              if (objSrc === targetObj) indexesTargetDirectly = true;
            }
          });
        }
        if (indexesTargetDirectly) {
          emit({
            id: 'js-off-by-one-loop',
            title: 'Off-by-one loop bound (<= .length)',
            severity: 'medium',
            cwe: 'CWE-193',
            hint: 'Use "< .length" instead of "<= .length" to avoid reading past the end.',
          }, node.test, 'high', `Loop condition "<= ${targetObj}.length" iterates one element past the valid index range.`);
        }
      }
      if (node.update?.type === 'UpdateExpression' && node.update.operator === '++' && node.update.argument?.type === 'Identifier') {
        const indexVar = node.update.argument.name;
        const bodyStmts = isSimpleBody(node.body);
        const decrementsIndex = collectAssignedTargets(node.body).has(indexVar);
        if (!decrementsIndex) {
          for (const stmt of bodyStmts) {
            walkSubtree(stmt, (sub) => {
              if (sub.type === 'CallExpression' && memberName(sub.callee) === 'splice' && sub.arguments[0]?.type === 'Identifier' && sub.arguments[0].name === indexVar) {
                emit({
                  id: 'js-array-splice-in-loop',
                  title: 'Array mutated with splice during forward loop',
                  severity: 'medium',
                  cwe: 'CWE-670',
                  hint: 'Iterate backwards, decrement the index after splice, or use Array.prototype.filter.',
                }, sub, 'high', `Splicing at "${indexVar}" while incrementing "${indexVar}++" skips the next element.`);
              }
            });
          }
        }
      }
    }

    // Prototype pollution via unguarded for..in merge.
    if (node.type === 'ForInStatement' && node.left) {
      const keyName = node.left.type === 'VariableDeclaration'
        ? node.left.declarations[0]?.id?.name
        : node.left.type === 'Identifier' ? node.left.name : '';
      if (keyName) {
        const bodyText = raw.slice(node.body.start, node.body.end);
        const hasGuard = new RegExp(`hasOwnProperty|Object\\.hasOwn|__proto${'__'}|constructor|prototype`).test(bodyText);
        if (!hasGuard) {
          let writesComputed = null;
          walkSubtree(node.body, (sub) => {
            if (sub.type === 'AssignmentExpression' && sub.left?.type === 'MemberExpression' && sub.left.computed && sub.left.property?.type === 'Identifier' && sub.left.property.name === keyName) {
              writesComputed = sub;
            }
          });
          if (writesComputed) {
            emit('js-prototype-pollution', writesComputed, 'high', `Unguarded "for..in" assigns dynamic key "${keyName}" without checking Object.hasOwn or __proto__.`);
          }
        }
      }
    }

    // Duplicate keys in object literal.
    if (node.type === 'ObjectExpression' && Array.isArray(node.properties)) {
      const seenKeys = new Set();
      for (const prop of node.properties) {
        if (prop.type !== 'ObjectProperty' || prop.computed) continue;
        const k = prop.key?.type === 'Identifier' ? prop.key.name : prop.key?.type === 'StringLiteral' ? prop.key.value : '';
        if (!k) continue;
        if (seenKeys.has(k)) {
          emit({
            id: 'js-duplicate-key',
            title: 'Duplicate object property key',
            severity: 'medium',
            cwe: 'CWE-670',
            hint: 'Remove or rename the duplicate property so the earlier value is not silently overwritten.',
          }, prop, 'high', `Property "${k}" is defined more than once in the same object literal.`);
        }
        seenKeys.add(k);
      }
    }

    // Switch statement: duplicate case values & unintentional fallthrough.
    if (node.type === 'SwitchStatement' && Array.isArray(node.cases)) {
      const seenCases = new Set();
      for (let cIdx = 0; cIdx < node.cases.length; cIdx++) {
        const sc = node.cases[cIdx];
        if (sc.test && staticText(sc.test)) {
          const val = `${sc.test.type}:${sc.test.value ?? raw.slice(sc.test.start, sc.test.end)}`;
          if (seenCases.has(val)) {
            emit({
              id: 'js-duplicate-case',
              title: 'Duplicate switch case',
              severity: 'medium',
              cwe: 'CWE-670',
              hint: 'Remove or merge the unreachable duplicate case branch.',
            }, sc, 'high', 'This switch case matches a value already handled by an earlier case.');
          }
          seenCases.add(val);
        }
        if (sc.consequent?.length && cIdx < node.cases.length - 1) {
          let lastStmt = sc.consequent[sc.consequent.length - 1];
          if (lastStmt.type === 'BlockStatement' && lastStmt.body.length) {
            lastStmt = lastStmt.body[lastStmt.body.length - 1];
          }
          const exits = ['BreakStatement', 'ReturnStatement', 'ThrowStatement', 'ContinueStatement'].includes(lastStmt.type);
          const caseText = raw.slice(sc.start, sc.end);
          if (!exits && !/fall\s*through/i.test(caseText)) {
            emit({
              id: 'js-switch-fallthrough',
              title: 'Switch case falls through without break',
              severity: 'low',
              cwe: 'CWE-484',
              hint: 'Add break, return, or a // fallthrough comment if intentional.',
            }, sc, 'medium', 'Non-empty switch case falls through into the next case.');
          }
        }
      }
    }

    // Unsafe return or throw inside finally block.
    if (node.type === 'TryStatement' && node.finalizer) {
      walkSubtree(node.finalizer, (sub) => {
        if (sub.type === 'FunctionDeclaration' || sub.type === 'FunctionExpression' || sub.type === 'ArrowFunctionExpression') return false;
        if (sub.type === 'ReturnStatement' || sub.type === 'ThrowStatement') {
          emit({
            id: 'js-return-in-finally',
            title: `${sub.type === 'ReturnStatement' ? 'return' : 'throw'} inside finally block`,
            severity: 'high',
            cwe: 'CWE-584',
            hint: 'Avoid return/throw in finally; it silently overrides try/catch return values and exceptions.',
          }, sub, 'high', 'Control-flow exit in finally discards exceptions thrown in try/catch.');
        }
      });
    }

    // new Promise(async (...) => ...) swallows async rejections.
    if (node.type === 'NewExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'Promise' && node.arguments[0]?.async) {
      emit({
        id: 'js-async-promise-executor',
        title: 'Async Promise executor function',
        severity: 'high',
        cwe: 'CWE-391',
        hint: 'Use an async function directly instead of wrapping it in new Promise(async ...).',
      }, node, 'high', 'Errors thrown inside an async Promise executor are not caught by the Promise.');
    }

    // Comma operator inside if/while/for/switch/return/index (e.g. arr[1, 2] or if (a, b)).
    if (node.type === 'SequenceExpression' && parent && (
      ['IfStatement', 'WhileStatement', 'ReturnStatement'].includes(parent.type)
      || (parent.type === 'MemberExpression' && parentKey === 'property' && parent.computed)
    )) {
      emit({
        id: 'js-comma-operator',
        title: 'Suspicious comma operator expression',
        severity: 'medium',
        cwe: 'CWE-480',
        hint: 'Avoid comma expressions here; only the last value is used.',
      }, node, 'high', 'Comma operator evaluates and discards earlier expressions, keeping only the last.');
    }

    // Calling Map(), Set(), WeakMap(), WeakSet(), or Promise() without `new`.
    if (node.type === 'CallExpression' && node.callee?.type === 'Identifier'
      && ['Map', 'Set', 'WeakMap', 'WeakSet', 'Promise'].includes(node.callee.name)) {
      emit({
        id: 'js-missing-new',
        title: `Missing "new" before ${node.callee.name}()`,
        severity: 'high',
        cwe: 'CWE-670',
        hint: `Use "new ${node.callee.name}(...)" — calling it without new throws a TypeError at runtime.`,
      }, node, 'high', `${node.callee.name}() requires "new" and throws TypeError when invoked as a function.`);
    }

    // String literal containing ${declaredVar} instead of backtick template literal.
    if (node.type === 'StringLiteral' && /\$\{([A-Za-z_$][\w$]*)\}/.test(node.value)
      && parent?.type !== 'ImportDeclaration' && parent?.type !== 'ExportNamedDeclaration') {
      const m = node.value.match(/\$\{([A-Za-z_$][\w$]*)\}/);
      if (m && scopeStack.some((s) => s.has(m[1]))) {
        emit({
          id: 'js-template-in-string',
          title: 'Template interpolation ${...} inside regular quotes',
          severity: 'medium',
          cwe: 'CWE-670',
          hint: `Use backticks (\`...\`) so \${${m[1]}} is interpolated instead of treated as literal text.`,
        }, node, 'high', `String literal contains "\${${m[1]}}" matching in-scope variable "${m[1]}", but uses quotes instead of backticks.`);
      }
    }

    // Loop counter moving in the wrong direction (< with --, or >/>= with ++ from > 0).
    if (node.type === 'ForStatement' && node.test?.type === 'BinaryExpression' && node.update?.type === 'UpdateExpression') {
      const testVar = node.test.left?.type === 'Identifier' ? node.test.left.name : '';
      const updVar = node.update.argument?.type === 'Identifier' ? node.update.argument.name : '';
      if (testVar && testVar === updVar) {
        if ((node.test.operator === '<' || node.test.operator === '<=') && node.update.operator === '--') {
          emit({
            id: 'js-for-direction',
            title: 'Loop counter moves in wrong direction',
            severity: 'high',
            cwe: 'CWE-835',
            hint: `Loop checks "${testVar} ${node.test.operator} ..." while decrementing "${testVar}--", causing an infinite or skipped loop.`,
          }, node.update, 'high', `Counter "${testVar}" decrements while upper bound uses "${node.test.operator}".`);
        }
      }
    }

    // Unparenthesized assignment in return statement: return x = y (skip ??=, ||=, &&= lazy memoization).
    if (node.type === 'ReturnStatement' && node.argument?.type === 'AssignmentExpression' && node.argument.operator === '=' && !node.argument.extra?.parenthesized) {
      emit({
        id: 'js-assign-in-return',
        title: 'Assignment inside return statement',
        severity: 'low',
        cwe: 'CWE-481',
        hint: 'Did you mean "===" instead of "=", or assign on a separate line before returning?',
      }, node.argument, 'medium', 'Return statement performs an unparenthesized assignment.');
    }

    // O(n^2) object spread inside Array.prototype.reduce.
    if (node.type === 'CallExpression' && memberName(node.callee) === 'reduce' && node.arguments[0]) {
      const cb = node.arguments[0];
      const accName = cb.params?.[0]?.type === 'Identifier' ? cb.params[0].name : '';
      if (accName) {
        let spreadNode = null;
        walkSubtree(cb.body, (sub) => {
          if (sub.type === 'SpreadElement' && sub.argument?.type === 'Identifier' && sub.argument.name === accName) {
            spreadNode = sub;
          }
        });
        if (spreadNode) {
          emit({
            id: 'js-spread-in-reduce',
            title: 'O(n²) accumulator spread inside .reduce()',
            severity: 'low',
            cwe: 'CWE-407',
            hint: 'Mutate the fresh accumulator object directly inside .reduce() instead of cloning with ...acc on every iteration.',
          }, spreadNode, 'medium', `Spreading accumulator "...${accName}" inside .reduce() allocates a new copy on every element.`);
        }
      }
    }

    // Duplicate module import in the same file.
    if (node.type === 'Program' && Array.isArray(node.body)) {
      const seenImports = new Set();
      for (const stmt of node.body) {
        if (stmt.type === 'ImportDeclaration' && stmt.source?.value) {
          const allTypeSpecs = Array.isArray(stmt.specifiers) && stmt.specifiers.length > 0 && stmt.specifiers.every((sp) => sp.importKind === 'type');
          const importKind = (stmt.importKind === 'type' || allTypeSpecs) ? 'type' : 'value';
          const isNamespace = Array.isArray(stmt.specifiers) && stmt.specifiers.some((sp) => sp.type === 'ImportNamespaceSpecifier');
          const isSideEffect = !stmt.specifiers || stmt.specifiers.length === 0;
          const importKey = `${importKind}:${isNamespace ? 'ns' : (isSideEffect ? 'side' : 'named')}:${stmt.source.value}`;
          if (seenImports.has(importKey)) {
            emit({
              id: 'js-duplicate-import',
              title: `Duplicate import "${stmt.source.value}"`,
              severity: 'low',
              cwe: 'CWE-710',
              hint: 'Merge duplicate imports from the same module into a single import statement.',
            }, stmt, 'high', `Module "${stmt.source.value}" is imported more than once.`);
          }
          seenImports.add(importKey);
        }
      }
    }

    // Operator precedence bug: !x in obj or !x instanceof Class.
    if (node.type === 'BinaryExpression' && (node.operator === 'in' || node.operator === 'instanceof')
      && node.left?.type === 'UnaryExpression' && node.left.operator === '!' && !node.left.extra?.parenthesized) {
      emit({
        id: 'js-negated-in-instanceof',
        title: `Negation precedence bug with "${node.operator}"`,
        severity: 'high',
        cwe: 'CWE-783',
        hint: `Wrap the expression in parentheses: !(x ${node.operator} y).`,
      }, node, 'high', `"!x ${node.operator} y" is parsed as "(!x) ${node.operator} y", not "!(x ${node.operator} y)".`);
    }

    // Non-constant-time secret/HMAC/signature comparison (timing side-channel).
    if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.operator)) {
      const isLit = (n) => !n || ['StringLiteral', 'NumericLiteral', 'BooleanLiteral', 'NullLiteral'].includes(n.type);
      const TIMING_SECRET_RE = /\b(?:hmac|signature|webhookSecret|signingKey|expectedSig|actualSig|computedSig)\b/i;
      if (!isLit(node.left) && !isLit(node.right)
        && (TIMING_SECRET_RE.test(identifierName(node.left)) || TIMING_SECRET_RE.test(identifierName(node.right)))) {
        emit({
          id: 'js-timing-unsafe-secret-cmp',
          title: 'Non-constant-time secret/signature comparison',
          severity: 'high',
          cwe: 'CWE-208',
          hint: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) to prevent timing side-channel attacks.',
        }, node, 'high', 'Comparing cryptographic signatures or webhook secrets with === leaks length/prefix timing.');
      }
    }

    // Promise returned by known async function used directly in if/while/negation/ternary condition without await.
    const testExpr = node.type === 'UnaryExpression' && node.operator === '!' ? node.argument
      : (node.type === 'IfStatement' || node.type === 'WhileStatement' || node.type === 'ConditionalExpression') ? node.test : null;
    if (testExpr?.type === 'CallExpression' && testExpr.callee?.type === 'Identifier' && asyncFnNames.has(testExpr.callee.name)) {
      emit({
        id: 'js-promise-in-condition',
        title: `Async function "${testExpr.callee.name}()" tested without await`,
        severity: 'high',
        cwe: 'CWE-480',
        hint: `Add "await" before ${testExpr.callee.name}(); a Promise object is always truthy.`,
      }, testExpr, 'high', `Calling async "${testExpr.callee.name}()" without await returns a Promise, which is always truthy.`);
    }

    // Throwing a string/number literal instead of an Error object loses stack trace.
    if (node.type === 'ThrowStatement' && (node.argument?.type === 'StringLiteral' || node.argument?.type === 'NumericLiteral' || node.argument?.type === 'TemplateLiteral')) {
      emit({
        id: 'js-throw-literal',
        title: 'Throwing a primitive literal instead of Error',
        severity: 'low',
        cwe: 'CWE-397',
        hint: 'Throw new Error(...) so callers receive a stack trace and Error instance.',
      }, node, 'high', 'Throwing a non-Error literal omits the stack trace.');
    }

    // Stateful /g RegExp literal tested inside a loop.
    if ((node.type === 'WhileStatement' || node.type === 'ForStatement') && node.test) {
      walkSubtree(node.test, (sub) => {
        if (sub.type === 'CallExpression' && memberName(sub.callee) === 'test' && sub.callee?.object?.type === 'RegExpLiteral' && sub.callee.object.flags?.includes('g')) {
          emit({
            id: 'js-global-regex-in-loop',
            title: 'Stateful /g RegExp.test() in loop condition',
            severity: 'medium',
            cwe: 'CWE-670',
            hint: 'Remove the /g flag from .test() or reset lastIndex; /g mutates lastIndex on every call.',
          }, sub, 'high', 'RegExp with /g flag advances lastIndex on each .test() call, causing alternating misses.');
        }
      });
    }

    // Constant condition in if statement & duplicate else-if conditions.
    if (node.type === 'IfStatement') {
      if (node.test?.type === 'BooleanLiteral' || node.test?.type === 'NumericLiteral' || node.test?.type === 'StringLiteral') {
        emit({
          id: 'js-constant-condition',
          title: 'Constant condition in if statement',
          severity: 'medium',
          cwe: 'CWE-570',
          hint: 'Replace the constant literal condition with a real runtime check or remove dead branch.',
        }, node.test, 'high', 'if() condition is a constant literal that never changes at runtime.');
      }
      if (parent?.type !== 'IfStatement') {
        const seenBranches = new Set([raw.slice(node.test.start, node.test.end).trim()]);
        let cur = node.alternate;
        while (cur?.type === 'IfStatement') {
          const condSrc = raw.slice(cur.test.start, cur.test.end).trim();
          if (seenBranches.has(condSrc)) {
            emit({
              id: 'js-duplicate-else-if',
              title: 'Duplicate condition in else-if chain',
              severity: 'medium',
              cwe: 'CWE-561',
              hint: 'Remove or fix the unreachable duplicate else-if condition.',
            }, cur.test, 'high', `Condition "${condSrc}" was already checked in an earlier branch.`);
          }
          seenBranches.add(condSrc);
          cur = cur.alternate;
        }
      }
    }

    // Sparse array holes ([1, , 3]) and delete on a bare variable.
    if (node.type === 'ArrayExpression' && node.elements?.some((el) => el === null)) {
      emit({
        id: 'js-sparse-array-hole',
        title: 'Sparse array literal with empty slot',
        severity: 'low',
        cwe: 'CWE-670',
        hint: 'Remove the extra comma or use explicit undefined if intentional.',
      }, node, 'high', 'Double comma in array literal creates an empty slot (undefined hole).');
    }
    if (node.type === 'UnaryExpression' && node.operator === 'delete' && node.argument?.type === 'Identifier') {
      emit({
        id: 'js-delete-var',
        title: 'delete applied to a variable identifier',
        severity: 'medium',
        cwe: 'CWE-670',
        hint: 'delete only removes object properties; it throws a SyntaxError in strict mode on variables.',
      }, node, 'high', `delete ${node.argument.name} is invalid in strict mode and ineffective on local bindings.`);
    }

    // ReDoS-prone nested quantifier regex literal.
    if (node.type === 'RegExpLiteral' && /\([^)]*[+*][^)]*\)[+*]/.test(node.pattern)) {
      emit({
        id: 'js-redos-regex',
        title: 'Nested quantifier in RegExp (ReDoS risk)',
        severity: 'medium',
        cwe: 'CWE-1333',
        hint: 'Avoid nested quantifiers like (a+)+ that can cause exponential backtracking.',
      }, node, 'high', `RegExp /${node.pattern}/ contains nested quantifiers.`);
    }

    // Missing await on known async function call used as a standalone statement,
    // or discarded return value of pure/immutable string/array methods.
    if (node.type === 'ExpressionStatement' && node.expression?.type === 'CallExpression') {
      const callee = node.expression.callee;
      if (callee?.type === 'Identifier') {
        const called = callee.name;
        const activeFn = fnStack[fnStack.length - 1];
        if (activeFn?.async && asyncFnNames.has(called)) {
          emit({
            id: 'js-missing-await',
            title: `Missing await on async call "${called}()"`,
            severity: 'medium',
            cwe: 'CWE-252',
            hint: `Await ${called}() or handle its returned Promise so errors and ordering are not lost.`,
          }, node, 'high', `Async function "${called}" is called inside an async function without await or .catch().`);
        }
      } else {
        const method = memberName(callee);
        if (['trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'slice', 'concat', 'filter'].includes(method)
          && callee?.object?.type === 'Identifier'
          && !['res', 'response', 'app', 'router', 'fs', 'path', 'console'].includes(callee.object.name)) {
          emit({
            id: 'js-ignored-immutable-return',
            title: `Return value of .${method}() is ignored`,
            severity: 'medium',
            cwe: 'CWE-252',
            hint: `.${method}() does not mutate in place; assign or return its result.`,
          }, node, 'high', `Calling "${callee.object.name}.${method}()" without using its return value is a no-op.`);
        }
      }
    }

    // Assignment inside if/while condition without extra parentheses.
    if ((node.type === 'IfStatement' || node.type === 'WhileStatement') && node.test?.type === 'AssignmentExpression' && !node.test.extra?.parenthesized) {
      emit({
        id: 'js-assign-in-condition',
        title: 'Assignment inside conditional expression',
        severity: 'medium',
        cwe: 'CWE-481',
        hint: 'Use === for comparison, or wrap intentional assignments in parentheses.',
      }, node.test, 'high', 'Condition uses "=" assignment instead of "==" or "===".');
    }

    // Self-comparison, NaN comparison, invalid typeof, and hardcoded credential comparison.
    if (node.type === 'BinaryExpression' && ['==', '===', '!=', '!=='].includes(node.operator)) {
      const leftSrc = raw.slice(node.left.start, node.left.end);
      const rightSrc = raw.slice(node.right.start, node.right.end);
      if (leftSrc && leftSrc === rightSrc && (node.left.type === 'Identifier' || node.left.type === 'MemberExpression')) {
        emit({
          id: 'js-self-compare',
          title: 'Value compared to itself',
          severity: 'medium',
          cwe: 'CWE-480',
          hint: 'Comparing an expression to itself is always true/false (except NaN); use Number.isNaN.',
        }, node, 'high', `"${leftSrc}" is compared with itself.`);
      }
      if ((node.left.type === 'Identifier' && node.left.name === 'NaN') || (node.right.type === 'Identifier' && node.right.name === 'NaN')) {
        emit({
          id: 'js-nan-compare',
          title: 'Direct comparison with NaN',
          severity: 'high',
          cwe: 'CWE-480',
          hint: 'Use Number.isNaN(value); NaN === NaN is always false.',
        }, node, 'high', 'Comparing against NaN with == or === always evaluates to false (or true for !==).');
      }
      const typeofSide = node.left.type === 'UnaryExpression' && node.left.operator === 'typeof'
        ? node.right
        : node.right.type === 'UnaryExpression' && node.right.operator === 'typeof' ? node.left : null;
      if (typeofSide?.type === 'StringLiteral' && !VALID_TYPEOF.has(typeofSide.value)) {
        emit({
          id: 'js-invalid-typeof',
          title: `Invalid typeof comparison "${typeofSide.value}"`,
          severity: 'high',
          cwe: 'CWE-480',
          hint: 'typeof only returns undefined, object, boolean, number, bigint, string, symbol, or function.',
        }, node, 'high', `typeof can never equal "${typeofSide.value}".`);
      }
      const leftName = identifierName(node.left);
      const rightName = identifierName(node.right);
      if ((SENSITIVE_NAME.test(leftName) && node.right.type === 'StringLiteral' && node.right.value.length > 0)
        || (SENSITIVE_NAME.test(rightName) && node.left.type === 'StringLiteral' && node.left.value.length > 0)) {
        emit({
          id: 'js-hardcoded-auth',
          title: 'Hardcoded credential comparison',
          severity: 'high',
          cwe: 'CWE-798',
          hint: 'Do not compare passwords or secrets against hardcoded literals; verify against hashed/configured credentials.',
        }, node, 'high', 'Credential variable is compared directly to a hardcoded string literal.');
      }
    }

    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      const name = node.callee?.type === 'Identifier' ? node.callee.name : memberName(node.callee);
      if (name === 'eval') emit('js-eval', node);
      if (node.type === 'NewExpression' && name === 'Function') emit('js-new-function', node);
      if (node.type === 'NewExpression' && name === 'RegExp' && node.arguments[0] && containsInput(node.arguments[0])) {
        emit('js-regex-injection', node, 'high', 'Tracked untrusted input is compiled into a regular expression.');
      }
      if (name === 'assign' && node.callee?.object?.name === 'Object' && node.arguments.slice(1).some(containsInput)) {
        emit('js-object-assign-proto', node, 'high', 'Tracked untrusted input is merged directly into an object.');
      }
      if (name === 'write' && node.callee?.object?.name === 'document' && (node.arguments.some((arg) => !staticText(arg)) || node.arguments.some((arg) => arg.type === 'StringLiteral' && /<script|on\w+\s*=/i.test(arg.value)))) {
        emit('js-document-write', node, 'high', 'Executable HTML or dynamic content is passed to document.write.');
      }
      if (name === 'insertAdjacentHTML' && node.arguments[1] && !staticText(node.arguments[1])) {
        emit('js-insert-adjacent-html', node, 'medium', 'Dynamic content is passed to insertAdjacentHTML.');
      }
      if (['query', 'execute', 'raw'].includes(name) && node.arguments.some(isDynamicSql)) {
        emit('js-sql-concat', node, 'medium', 'SQL text includes dynamically constructed content; verify parameter binding.');
      }
      if (['exec', 'execSync'].includes(name) && node.arguments.some((arg) => (arg.type === 'TemplateLiteral' && arg.expressions.length) || (arg.type === 'BinaryExpression' && arg.operator === '+'))) {
        emit('js-exec-interpolation', node, 'medium', 'A shell command is constructed dynamically; use an argument-array API.');
      }
      if (FILE_SINKS.has(name) && node.arguments.some(containsInput)) {
        emit('js-path-traversal', node, 'high', 'Request-controlled data reaches a filesystem path.');
      }
      const calleeObjSrc = node.callee?.object ? raw.slice(node.callee.object.start, node.callee.object.end) : '';
      if (['create', 'update', 'insertOne', 'updateOne', 'findByIdAndUpdate', 'findOneAndUpdate'].includes(name)
        && !/(?:crypto|hmac|hash|cipher|createHmac|createHash|createCipher)/i.test(calleeObjSrc)
        && node.arguments.some((arg) => arg?.type === 'MemberExpression' && containsInput(arg))
        && !/\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(file || '')) {
        emit({
          id: 'js-mass-assignment-db',
          title: `Unfiltered request payload passed to .${name}() (Mass Assignment)`,
          severity: 'high',
          cwe: 'CWE-915',
          hint: 'Explicitly pick/validate allowed fields (e.g. via Zod) before passing data to ORM/DB write methods.',
        }, node, 'high', `Raw request body is passed directly to .${name}(), risking privilege-escalation field injection.`);
      }
      const isRelativeRedirectTpl = (arg) => arg?.type === 'TemplateLiteral'
        && typeof arg.quasis?.[0]?.value?.raw === 'string'
        && /^\/(?!\/)/.test(arg.quasis[0].value.raw);
      const isValidatedRedirectTernary = (arg) => arg?.type === 'ConditionalExpression'
        && /\b(?:origin\s*===|startsWith\s*\(\s*['"]\/['"]\))/.test(raw.slice(arg.test.start, arg.test.end));
      if (name === 'redirect' && (node.arguments.some(containsInput) || (node.arguments[0] && !staticText(node.arguments[0]) && !isRelativeRedirectTpl(node.arguments[0]) && !isValidatedRedirectTernary(node.arguments[0])))) {
        const hasInput = containsInput(node.arguments[0]);
        emit({
          id: 'js-redirect-param',
          title: hasInput ? 'Open redirect from query parameter' : 'Unvalidated redirect target',
          severity: 'medium',
          cwe: 'CWE-601',
          hint: 'Allow only same-site relative paths or an explicit origin allow-list.',
        }, node, hasInput ? 'high' : 'medium', hasInput ? 'Request-controlled data reaches a redirect call.' : 'Dynamic destination reaches a redirect call; validate against an allow-list.');
      }
      const networkRequest = name === 'fetch' || (['get', 'post', 'request'].includes(name) && /(?:axios|https?|http)/i.test(raw.slice(node.callee.start, node.callee.end)));
      if (networkRequest && containsInput(node.arguments[0])) {
        emit('js-ssrf', node, 'high', 'Request-controlled data reaches an outbound URL.');
      }
      if (name === 'startsWith' && node.arguments[0]?.type === 'StringLiteral' && /^https?:\/\/[^/]+$/i.test(node.arguments[0].value)) {
        emit({
          id: 'js-bypassable-url-check',
          title: 'Bypassable URL prefix validation',
          severity: 'medium',
          cwe: 'CWE-601',
          hint: 'Parse with new URL() and compare exact hostname instead of using startsWith.',
        }, node, 'high', `startsWith("${node.arguments[0].value}") can be bypassed by "${node.arguments[0].value}.evil.com".`);
      }
      if (name === 'random' && node.callee?.object?.name === 'Math') {
        const activeFn = fnStack[fnStack.length - 1];
        if (activeFn && SECRET_FN_NAME.test(activeFn.name)) {
          emit('js-math-random-secret', node, 'high', `Math.random() is used inside security-sensitive function "${activeFn.name}".`);
        }
      }
      if (['log', 'debug', 'info', 'warn', 'error'].includes(name) && node.callee?.object?.name === 'console') {
        const leaked = node.arguments.find((arg) => SENSITIVE_NAME.test(identifierName(arg)));
        if (leaked) {
          emit({
            id: 'js-log-sensitive',
            title: 'Sensitive credential logged to console',
            severity: 'medium',
            cwe: 'CWE-532',
            hint: 'Never log passwords, tokens, or secrets to console output.',
          }, node, 'high', `Sensitive identifier "${identifierName(leaked)}" is passed to console.${name}().`);
        }
      }
      const isNonProdPath = /(?:^|[\\/])(?:test|tests|__tests__|spec|specs|benchmark|benchmarks|fixtures?|examples?)(?:[\\/]|$)/i.test(file || '');
      if (node.type === 'CallExpression' && parent?.type === 'ExpressionStatement' && node.callee?.property?.name === 'then' && (node.callee?.type === 'MemberExpression' || node.callee?.type === 'OptionalMemberExpression') && node.arguments.length < 2 && !/\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(file || '') && !isNonProdPath) {
        const after = raw.slice(node.end || 0, (node.end || 0) + 120);
        if (!/^\s*\.\s*(?:catch|finally)\b/.test(after)) {
          emit('js-promise-no-catch', node, 'low', 'Promise chain has no rejection handler; attach .catch or provide an onRejected callback.');
        }
      }
      if (['map', 'filter', 'find', 'some', 'every', 'reduce'].includes(name) && node.arguments[0]
        && (node.arguments[0].type === 'ArrowFunctionExpression' || node.arguments[0].type === 'FunctionExpression')
        && node.arguments[0].body?.type === 'BlockStatement' && node.arguments[0].body.body.length > 0) {
        let hasReturn = false;
        walkSubtree(node.arguments[0].body, (sub) => {
          if (sub !== node.arguments[0] && (sub.type === 'FunctionDeclaration' || sub.type === 'FunctionExpression' || sub.type === 'ArrowFunctionExpression')) return false;
          if (sub.type === 'ReturnStatement' || sub.type === 'ThrowStatement') hasReturn = true;
        });
        if (!hasReturn) {
          emit({
            id: 'js-missing-array-return',
            title: `Missing return in Array.${name}() callback`,
            severity: 'high',
            cwe: 'CWE-670',
            hint: `Return a value from the .${name}() callback (or use concise arrow syntax without {}).`,
          }, node.arguments[0], 'high', `.${name}() callback uses a block body {} with no return statement, returning undefined.`);
        }
      }
      if (name === 'catch' && !(parent?.type === 'MemberExpression' && parentKey === 'object')
        && node.arguments[0] && (node.arguments[0].type === 'ArrowFunctionExpression' || node.arguments[0].type === 'FunctionExpression')) {
        const cb = node.arguments[0];
        const recvSrc = node.callee?.object ? raw.slice(node.callee.object.start, node.callee.object.end) : '';
        const isBestEffortCleanup = /\.(?:unlink|rm|rmdir|close|cancel|stop|pause|play|resume|remove|revokeObjectURL|scrollTo)\s*\(/i.test(recvSrc);
        if (cb.body?.type === 'BlockStatement' && cb.body.body.length === 0 && !isBestEffortCleanup) {
          emit({
            id: 'js-empty-promise-catch',
            title: 'Empty Promise .catch() handler',
            severity: 'medium',
            cwe: 'CWE-390',
            hint: 'Log or handle the rejection instead of swallowing it silently.',
          }, node, 'medium', 'Promise .catch() handler has an empty block and silently discards errors.');
        }
      }
      if (name === 'useEffect' && node.arguments[0] && (node.arguments[0].type === 'ArrowFunctionExpression' || node.arguments[0].type === 'FunctionExpression')) {
        const effBody = node.arguments[0].body;
        if (effBody?.type === 'BlockStatement') {
          const effSrc = raw.slice(effBody.start, effBody.end);
          const registersListener = /\b(?:addEventListener|setInterval|\.subscribe)\s*\(/.test(effSrc);
          const hasReturnCleanup = /\breturn\s+(?:\(\s*\)\s*=>|function\b|[a-zA-Z_$][\w$]*)/.test(effSrc);
          if (registersListener && !hasReturnCleanup) {
            emit({
              id: 'js-react-effect-leak',
              title: 'useEffect registers listener/interval without cleanup',
              severity: 'medium',
              cwe: 'CWE-401',
              hint: 'Return a cleanup function from useEffect (e.g. return () => clearInterval(id) / removeEventListener(...)) to prevent memory leaks.',
            }, node, 'medium', 'useEffect sets up an event listener, interval, or subscription without returning a cleanup teardown.');
          }
        }
      }
    }

    // Control-flow guard check: `if (!x) { log(); }` (no return/throw/else) followed immediately by `x.prop`.
    if (node.type === 'BlockStatement' || node.type === 'Program') {
      const stmts = node.body || [];
      for (let idx = 0; idx < stmts.length - 1; idx++) {
        const cur = stmts[idx];
        const nxt = stmts[idx + 1];
        if (cur?.type !== 'IfStatement' || cur.alternate) continue;
        let guardedVar = '';
        if (cur.test?.type === 'UnaryExpression' && cur.test.operator === '!' && cur.test.argument?.type === 'Identifier') {
          guardedVar = cur.test.argument.name;
        } else if (cur.test?.type === 'BinaryExpression' && ['==', '==='].includes(cur.test.operator)) {
          if (cur.test.left?.type === 'Identifier' && (cur.test.right?.type === 'NullLiteral' || (cur.test.right?.type === 'Identifier' && cur.test.right.name === 'undefined'))) {
            guardedVar = cur.test.left.name;
          }
        }
        if (!guardedVar) continue;
        const conseqSrc = raw.slice(cur.consequent.start, cur.consequent.end);
        if (/\b(?:return|throw|continue|break|process\.exit)\b/.test(conseqSrc)) continue;
        if (new RegExp(`\\b${guardedVar}\\s*=`).test(conseqSrc)) continue;
        if (nxt.type === 'IfStatement' && /\|\||&&/.test(raw.slice(nxt.test.start, nxt.test.end))) continue;
        let derefFound = false;
        walkSubtree(nxt, (inner) => {
          if (derefFound) return;
          if (inner.type === 'MemberExpression' && !inner.optional && inner.object?.type === 'Identifier' && inner.object.name === guardedVar) {
            derefFound = true;
          }
        });
        if (derefFound) {
          emit({
            id: 'js-unguarded-null-deref',
            title: `Missing return/throw after null check on "${guardedVar}"`,
            severity: 'high',
            cwe: 'CWE-476',
            hint: `Add a return or throw inside the if-guard for "${guardedVar}", or guard the next statement so "${guardedVar}" is not dereferenced when null/undefined.`,
          }, nxt, 'high', `Previous null/falsy guard for "${guardedVar}" does not exit, and the next statement accesses "${guardedVar}" unconditionally.`);
        }
      }
    }

    // File-handle leak check: `const fh = await fs.open(...)` without enclosing try/finally.
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init?.type === 'AwaitExpression') {
      const call = node.init.argument;
      const calleeStr = call?.type === 'CallExpression' ? memberName(call.callee) : '';
      const objStr = call?.type === 'CallExpression' ? (call.callee?.object?.name || memberName(call.callee?.object)) : '';
      if (calleeStr === 'open' && ['fs', 'fsPromises', 'fsp', 'promises'].includes(objStr)) {
        const handleName = node.id.name;
        const fnBody = fnStack[fnStack.length - 1]?.body;
        if (fnBody) {
          const bodySrc = raw.slice(fnBody.start, fnBody.end);
          const hasFinallyClose = new RegExp(`finally\\s*\\{[\\s\\S]*\\b${handleName}\\.close\\s*\\(`).test(bodySrc);
          if (!hasFinallyClose) {
            emit({
              id: 'js-resource-leak',
              title: `File handle "${handleName}" opened without try/finally close`,
              severity: 'medium',
              cwe: 'CWE-775',
              hint: `Close "${handleName}" inside a finally { await ${handleName}.close(); } block so errors do not leak file descriptors.`,
            }, node, 'medium', `File handle "${handleName}" is opened with fs.open() without a finally block ensuring ${handleName}.close().`);
          }
        }
      }
    }

    if (node.type === 'AssignmentExpression') {
      const sink = memberName(node.left);
      if (['innerHTML', 'outerHTML'].includes(sink)) {
        if (isSafeHtmlValue(node.right, numericVars, safeHtmlVars)) {
          if (options.safeHtmlLines && line) options.safeHtmlLines.add(line + lineOffset);
        } else {
          const taintedNames = line ? taint.byLine[line - 1] || new Set() : new Set();
        const rightSrc = raw.slice(node.right.start, node.right.end);
        const sourceVisible = USER_INPUT.test(rightSrc) || [...taintedNames].some((name) => {
          const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          return new RegExp(`(^|[^\\w$])${escaped}(?=$|[^\\w$])`).test(rightSrc);
        });
          emit(sink === 'innerHTML' ? 'js-innerhtml' : 'js-outerhtml', node, sourceVisible ? 'high' : 'medium', sourceVisible ? 'Tracked untrusted input reaches an HTML sink.' : 'Dynamic content reaches an HTML sink; inspect its source.');
        }
      }
      const locationTarget = (memberName(node.left) === 'href' && memberName(node.left.object) === 'location')
        || memberName(node.left) === 'location';
      if (locationTarget && containsInput(node.right)) {
        emit('js-unsafe-redirect', node, 'medium', 'Request-controlled data reaches a browser redirect destination.');
      }
      if (node.left?.type === 'MemberExpression' && memberName(node.left.object) === 'prototype' && ['Object', 'Array', 'String', 'Function'].includes(node.left.object?.object?.name)) {
        emit('js-prototype-pollution', node, 'high', `Direct mutation of ${node.left.object.object.name}.prototype affects all objects globally.`);
      }
      if (node.left?.type === 'MemberExpression') {
        const propName = memberName(node.left);
        const objPropName = memberName(node.left.object);
        const isProtoWrite = propName === `__proto${'__'}` || objPropName === `__proto${'__'}`
          || (objPropName === 'prototype' && memberName(node.left.object?.object) === 'constructor');
        if (isProtoWrite) {
          emit('js-prototype-pollution', node, 'high', 'Direct assignment to __proto__ or constructor.prototype can pollute object prototypes.');
        }
        if (node.left.object?.type === 'Identifier' && ['window', 'globalThis'].includes(node.left.object.name) && propName) {
          const STANDARD_DOM_PROPS = new Set([
            'location', 'title', 'name', 'status', 'defaultStatus',
            'onload', 'onerror', 'onresize', 'onscroll', 'onbeforeunload',
            'onhashchange', 'onpopstate', 'onstorage', 'onmessage',
            'onfocus', 'onblur', 'onkeydown', 'onkeyup',
          ]);
          const isCleanup = (node.right?.type === 'Identifier' && node.right.name === 'undefined')
            || node.right?.type === 'NullLiteral'
            || (node.right?.type === 'UnaryExpression' && node.right.operator === 'void');
          if (STANDARD_DOM_PROPS.has(propName) || isCleanup) {
            markSafeRuleLine('lib-global-window-mutation', node);
          } else if (rules.has('lib-global-window-mutation')) {
            emit('lib-global-window-mutation', node, 'medium', `Assignment to ${node.left.object.name}.${propName} mutates the global namespace.`);
          }
        }
      }
      if (sink === 'src' && !staticText(node.right) && /\bscript\b/i.test(raw)) {
        const objName = node.left.object?.name || '';
        if (objName && new RegExp(`createElement\\s*\\(\\s*["']script["']\\s*\\)`).test(raw)) {
          emit({
            id: 'js-dynamic-script-src',
            title: 'Dynamic script src assignment',
            severity: 'medium',
            cwe: 'CWE-829',
            hint: 'Allow-list script URLs or load static bundled modules with Subresource Integrity.',
          }, node, 'medium', 'A dynamically created <script> element receives a non-literal src.');
        }
      }
    }

    // Suppress regex false positives for defensive __proto__ guards & window/globalThis comparisons.
    if (
      ((node.type === 'StringLiteral' && node.value === `__proto${'__'}`)
        || (node.type === 'Identifier' && node.name === `__proto${'__'}`))
      && parent
      && (
        (parent.type === 'BinaryExpression' && ['===', '!==', '==', '!=', 'in'].includes(parent.operator))
        || (parent.type === 'SwitchCase' && parentKey === 'test')
        || parent.type === 'ArrayExpression'
        || (parent.type === 'CallExpression' && parentKey === 'arguments')
        || (parent.type === 'UnaryExpression' && ['delete', 'typeof'].includes(parent.operator))
      )
    ) {
      markSafeRuleLine('js-prototype-pollution', node);
    }

    if (
      node.type === 'BinaryExpression'
      && ['===', '!==', '==', '!=', '<', '>', '<=', '>='].includes(node.operator)
      && (
        (node.left?.type === 'MemberExpression' && node.left.object?.type === 'Identifier' && ['window', 'globalThis'].includes(node.left.object.name))
        || (node.right?.type === 'MemberExpression' && node.right.object?.type === 'Identifier' && ['window', 'globalThis'].includes(node.right.object.name))
      )
    ) {
      markSafeRuleLine('lib-global-window-mutation', node);
    }

    // Undeclared identifier check (skip .d.ts, re-exports, type nodes, property keys, declarations, and typeof).
    const isDtsFile = /\.d\.[cm]?ts$/i.test(file || '');
    if (
      !isDtsFile
      && !inReexport
      && node.type === 'Identifier'
      && topScope.size > 0
      && parent
      && !(parent.type === 'MemberExpression' && parentKey === 'property' && !parent.computed)
      && !(parent.type === 'OptionalMemberExpression' && parentKey === 'property' && !parent.computed)
      && !(parent.type === 'ObjectProperty' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'ObjectMethod' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'ClassMethod' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'ClassProperty' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'PropertyDefinition' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'MethodDefinition' && parentKey === 'key' && !parent.computed)
      && !(parent.type === 'ExportSpecifier' && (parentKey === 'exported' || parent.exportKind === 'type'))
      && !(parent.type === 'LabeledStatement' && parentKey === 'label')
      && !(parent.type === 'BreakStatement' && parentKey === 'label')
      && !(parent.type === 'ContinueStatement' && parentKey === 'label')
      && !(parent.type === 'VariableDeclarator' && parentKey === 'id')
      && !(parent.type === 'FunctionDeclaration' && parentKey === 'id')
      && !(parent.type === 'FunctionExpression' && parentKey === 'id')
      && !(parent.type === 'ClassDeclaration' && parentKey === 'id')
      && !(parent.type === 'UnaryExpression' && parent.operator === 'typeof')
      && !parent.type.startsWith('TS')
      && !parent.type.startsWith('Import')
      && parent.type !== 'MetaProperty'
      && !isDeclared(node.name)
    ) {
      emit({
        id: 'js-undeclared-var',
        title: 'Potentially undeclared variable',
        severity: 'medium',
        cwe: 'CWE-457',
        hint: `Declare "${node.name}" or import it before use to avoid a ReferenceError.`,
      }, node, 'low', `Identifier "${node.name}" is not declared in this file or standard globals.`);
    }

    const nextInReexport = inReexport || (node.type === 'ExportNamedDeclaration' && (Boolean(node.source) || node.exportKind === 'type')) || node.type === 'ExportAllDeclaration';
    for (const [key, value] of Object.entries(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra' || key === 'errors' || key === 'comments' || key === 'tokens') continue;
      if (Array.isArray(value)) value.forEach((item) => visit(item, node, key, nextInReexport));
      else if (value && typeof value === 'object' && typeof value.type === 'string') visit(value, node, key, nextInReexport);
    }

    if (isFn) { fnStack.pop(); scopeStack.pop(); }
    if (pushedBlockScope) scopeStack.pop();
  };

  visit(ast, null, '');

  // Next.js App Router mutating API handler without server-side auth check
  if (/(?:^|[\\/])app[\\/]api[\\/].*route\.[jt]sx?$/i.test(file || '')
    && !/[\\/](?:auth|login|register|signup|logout|webhook|leads|contact|enquiry|health)[\\/]/i.test(file || '')) {
    const hasMutatingHandler = /\bexport\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b/.test(raw);
    const hasDbOrFsWrite = /\.(?:create|update|delete|insert|save|findByIdAnd|writeFile|unlink|upload)\b/.test(raw);
    const hasAuthCheck = /\b(?:getSession|getServerSession|verifyAuth|requireAuth|isAuthenticated|currentUser|cookies\s*\(|jwt\.verify|checkAuth|authenticate|authorization)\b/i.test(raw);
    if (hasMutatingHandler && hasDbOrFsWrite && !hasAuthCheck) {
      const m = raw.match(/\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b/);
      const line = m ? raw.slice(0, m.index).split(/\r?\n/).length : 1;
      findings.push(makeFinding({
        id: 'js-nextjs-api-no-auth',
        title: `Next.js ${m ? m[1] : 'mutating'} API route performs writes without server-side auth check`,
        severity: 'high',
        cwe: 'CWE-306',
        hint: 'Verify the caller session/token on the server before mutating database or filesystem state.',
      }, file, line, raw.split(/\r?\n/)[line - 1] || '', { confidence: 'high', reason: 'Mutating Next.js App Router handler has DB/file write calls and no recognized auth guard.' }));
    }
  }

  return findings;
}

module.exports = { analyzeJavaScriptAst };
