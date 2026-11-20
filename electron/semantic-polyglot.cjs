'use strict';

// Semantic security analyzers for Solidity (.sol), Python (.py), Go (.go), and Rust (.rs):
//  - Solidity Checks-Effects-Interactions (reentrancy), unprotected init/delegatecall, tx.origin, unchecked call
//  - Python, Go & Rust AST-backed intraprocedural AND interprocedural call-graph taint into SQL / shell / path sinks

let astGrep = null;
function getAstGrep() {
  if (astGrep !== null) return astGrep;
  try {
    const { parse, registerDynamicLanguage } = require('@ast-grep/napi');
    registerDynamicLanguage({
      python: require('@ast-grep/lang-python'),
      go: require('@ast-grep/lang-go'),
      rust: require('@ast-grep/lang-rust'),
    });
    astGrep = { parse };
  } catch {
    astGrep = false;
  }
  return astGrep;
}

function buildFinding(rel, line, id, title, severity, cwe, hint, reason, excerpt) {
  return {
    id: `${rel}:${line}:${id}`,
    ruleId: id,
    title,
    severity,
    cwe,
    hint,
    confidence: 'high',
    reason,
    file: rel,
    line,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

function analyzeSolidity(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const fnRe = /\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)\{/g;

  let m;
  while ((m = fnRe.exec(raw)) !== null) {
    const fnName = m[1];
    const modifiers = m[3] || '';
    const bodyStart = m.index + m[0].length;
    let depth = 1;
    let pos = bodyStart;
    while (pos < raw.length && depth > 0) {
      const ch = raw[pos++];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    const body = raw.slice(bodyStart, pos - 1);
    const fnStartLine = raw.slice(0, m.index).split(/\r?\n/).length;

    const isPublicOrExt = /\b(?:public|external)\b/.test(modifiers);
    const hasReentrancyGuard = /\bnonReentrant\b/i.test(modifiers);
    const hasAuthGuard = /\b(?:onlyOwner|onlyRole|onlyAdmin|initializer|reinitializer|auth|requiresAuth)\b/i.test(modifiers)
      || /\brequire\s*\(\s*msg\.sender\s*={2}/.test(body)
      || /\bif\s*\(\s*msg\.sender\s*!=/.test(body)
      || /\b_checkOwner\s*\(/.test(body);

    if (!hasReentrancyGuard) {
      const extCallRe = /\.(?:call\s*\{[^}]*value\s*:|call\.value\s*\(|send\s*\()/;
      const callMatch = extCallRe.exec(body);
      if (callMatch) {
        const afterCall = body.slice(callMatch.index + callMatch[0].length);
        const stateWriteRe = /\b([A-Za-z_]\w*\[[^\]]+\](?:\[[^\]]+\])?)\s*(?:=|-=|\+=)|\bdelete\s+[A-Za-z_]\w*\[/;
        const writeMatch = stateWriteRe.exec(afterCall);
        if (writeMatch) {
          const callOffset = bodyStart + callMatch.index;
          const callLine = raw.slice(0, callOffset).split(/\r?\n/).length;
          findings.push(buildFinding(
            rel,
            callLine,
            'sol-reentrancy-cei',
            `Potential reentrancy in "${fnName}()": state updated after external Ether call`,
            'critical',
            'CWE-841',
            'Update contract balances/state BEFORE making external calls (Checks-Effects-Interactions) or add a nonReentrant modifier.',
            `External value transfer in "${fnName}" precedes state mutation.`,
            lines[callLine - 1],
          ));
        }
      }
    }

    if (isPublicOrExt && !hasAuthGuard) {
      const hasDangerOp = /\bselfdestruct\s*\(|\.delegatecall\s*\(/.test(body);
      const isInit = /^(?:initialize|init)$/i.test(fnName);
      if (hasDangerOp || isInit) {
        findings.push(buildFinding(
          rel,
          fnStartLine,
          'sol-unprotected-sensitive-fn',
          isInit
            ? `Initializer "${fnName}()" lacks initializer/access guard`
            : `Public/external function "${fnName}()" performs ${/\bselfdestruct/.test(body) ? 'selfdestruct' : 'delegatecall'} without access control`,
          'critical',
          'CWE-284',
          isInit
            ? 'Protect upgradeable initializers with OpenZeppelin `initializer` modifier.'
            : 'Restrict privileged selfdestruct/delegatecall functions with `onlyOwner` or role-based access control.',
          `"${fnName}" is public/external and lacks owner/initializer guard.`,
          lines[fnStartLine - 1],
        ));
      }
    }
    if (/\btx\.origin\s*={2}/.test(body)) {
      const txOffset = bodyStart + body.search(/\btx\.origin\s*={2}/);
      const txLine = raw.slice(0, txOffset).split(/\r?\n/).length;
      findings.push(buildFinding(
        rel, txLine, 'sol-tx-origin-auth',
        `Authorization in "${fnName}()" uses tx.origin`,
        'high', 'CWE-477',
        'Use msg.sender instead of tx.origin for authorization checks to prevent phishing attacks.',
        `Function "${fnName}" checks tx.origin == ... for access control.`,
        lines[txLine - 1],
      ));
    }

    const lowLevelCall = /\.(?:call|delegatecall|send)\s*(?:\{[^}]*\})?\s*\([^;]*\)\s*;/.exec(body);
    if (lowLevelCall) {
      const callLine = raw.slice(0, bodyStart + lowLevelCall.index).split(/\r?\n/).length;
      const lineText = lines[callLine - 1] || '';
      if (!/=\s*[^=]|\brequire\s*\(|\bif\s*\(/.test(lineText)) {
        findings.push(buildFinding(
          rel, callLine, 'sol-unchecked-call',
          `Unchecked low-level call return value in "${fnName}()"`,
          'high', 'CWE-252',
          'Capture `(bool ok, ) = target.call(...)` and `require(ok)` so silent failures do not corrupt contract state.',
          `Low-level call/send return value is ignored in "${fnName}".`,
          lineText,
        ));
      }
    }
  }

  return findings;
}

const PY_SOURCE_RE = /\b(?:request\.(?:args|form|json|data|values|get_json)|input\s*\(|sys\.argv)/;
const PY_SANITIZER_RE = /\b(?:int|float|bool|shlex\.quote|html\.escape|markupsafe\.escape)\s*\(/;
const PY_SINK_RE = /\b(?:cursor\.execute|os\.system|subprocess\.(?:run|Popen|call)\s*\(|eval\s*\(|exec\s*\()/;

function analyzePythonTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const ag = getAstGrep();

  // AST-backed function-level taint if @ast-grep/napi is available
  if (ag) {
    try {
      const root = ag.parse('python', raw).root();
      const fns = root.findAll({ rule: { kind: 'function_definition' } });
      for (const fn of fns) {
        const tainted = new Set();
        const stmts = fn.findAll({ rule: { kind: 'assignment' } });
        for (const st of stmts) {
          const text = st.text();
          const eq = text.indexOf('=');
          if (eq < 0) continue;
          const lhs = text.slice(0, eq).trim().split(/[\s,]+/)[0];
          const rhs = text.slice(eq + 1);
          if (!/^[A-Za-z_]\w*$/.test(lhs)) continue;
          if (PY_SANITIZER_RE.test(rhs)) { tainted.delete(lhs); continue; }
          if (PY_SOURCE_RE.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) tainted.add(lhs);
          else tainted.delete(lhs);
        }
        const calls = fn.findAll({ rule: { kind: 'call' } });
        for (const call of calls) {
          const cText = call.text();
          if (!PY_SINK_RE.test(cText)) continue;
          if (PY_SANITIZER_RE.test(cText)) continue;
          const usesTainted = PY_SOURCE_RE.test(cText) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(cText));
          if (usesTainted && (!/\bsubprocess\./.test(cText) || /\bshell\s*=\s*True\b/.test(cText))) {
            const line = call.range().start.line + 1;
            findings.push(buildFinding(
              rel, line, 'py-taint-sink',
              'User-controlled input reaches dangerous Python execution/SQL sink',
              'high', 'CWE-89',
              'Use parameterized SQL queries or argument arrays (shell=False) instead of passing tainted input.',
              'AST taint analysis confirms request/input variable flows into a dangerous sink.',
              lines[line - 1] || cText,
            ));
          }
        }
      }
    } catch {
      // Fall through to line analyzer on unexpected parse error
    }
  }

  if (findings.length === 0) {
    const tainted = new Set();
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      if (/^(?:async\s+)?def\s+/.test(trimmed)) { tainted.clear(); continue; }

      const assign = trimmed.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
      if (assign) {
        const [, lhs, rhs] = assign;
        if (PY_SANITIZER_RE.test(rhs)) tainted.delete(lhs);
        else if (PY_SOURCE_RE.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) tainted.add(lhs);
        else tainted.delete(lhs);
      }

      if (PY_SINK_RE.test(trimmed) && !PY_SANITIZER_RE.test(trimmed)) {
        const usesTainted = PY_SOURCE_RE.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
        if (usesTainted && (!/\bsubprocess\./.test(trimmed) || /\bshell\s*=\s*True\b/.test(trimmed))) {
          findings.push(buildFinding(
            rel, i + 1, 'py-taint-sink',
            'User-controlled input reaches dangerous Python execution/SQL sink',
            'high', 'CWE-89',
            'Use parameterized SQL queries or argument arrays (shell=False) instead of passing tainted input.',
            'Tainted request/input variable flows into a dangerous sink in the same function.',
            trimmed,
          ));
        }
      }
    }
  }

  // Python mutating FastAPI/Flask route without auth dependency/decorator
  const pyRouteRe = /^\s*@(?:app|router)\.(post|put|patch|delete)\s*\(([^)]*)\)/gim;
  let rm;
  while ((rm = pyRouteRe.exec(raw)) !== null) {
    if (/login|register|signup|auth|token|webhook|health/i.test(rm[2])) continue;
    const lineIdx = raw.slice(0, rm.index).split(/\r?\n/).length;
    const block = lines.slice(lineIdx - 1, Math.min(lines.length, lineIdx + 18)).join('\n');
    const hasWrite = /(?:\.commit\(|\.execute\(|\.delete\(|\.save\(|\binsert\b|\bupdate\b|\bunlink\b)/i.test(block);
    const hasAuth = /\b(?:Depends|current_user|login_required|jwt|verify_token|Authorization|get_current_user|session)\b/i.test(block);
    if (hasWrite && !hasAuth) {
      findings.push(buildFinding(
        rel, lineIdx, 'py-route-missing-auth',
        `Mutating Python ${rm[1].toUpperCase()} route lacks auth dependency/guard`,
        'high', 'CWE-306',
        'Add Depends(get_current_user) or @login_required to protect mutating endpoints.',
        'Mutating Python route writes to DB/storage without an authentication dependency.',
        lines[lineIdx - 1],
      ));
    }
  }
  return findings;
}

const GO_SOURCE_RE = /\b(?:r\.URL\.Query\s*\(|r\.FormValue\s*\(|c\.(?:Query|Param|PostForm)\s*\()/;
const GO_SANITIZER_RE = /\b(?:strconv\.(?:Atoi|ParseInt|ParseFloat)|filepath\.Base)\s*\(/;
const GO_SINK_RE = /\b(?:db\.(?:Query|Exec|QueryRow)\s*\(|exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c")/;
const GO_PATH_SINK_RE = /\b(?:os\.(?:ReadFile|Open|WriteFile|Remove)|ioutil\.ReadFile)\s*\(/;

function analyzeGoTaint(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  const tainted = new Set();

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (/^func\s+/.test(trimmed)) { tainted.clear(); continue; }

    const assign = trimmed.match(/^([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*(.+)$/);
    if (assign) {
      const [, lhs, rhs] = assign;
      if (GO_SANITIZER_RE.test(rhs)) tainted.delete(lhs);
      else if (GO_SOURCE_RE.test(rhs) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) tainted.add(lhs);
    }

    if (GO_SINK_RE.test(trimmed) && !GO_SANITIZER_RE.test(trimmed)) {
      const usesTainted = GO_SOURCE_RE.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      const hasConcatOrFmt = /[+]|fmt\.Sprintf\s*\(/.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted && hasConcatOrFmt) {
        if (/\bdb\.(?:Query|Exec|QueryRow)\s*\(/.test(trimmed) && !/[+]|fmt\.Sprintf/.test(trimmed)) continue;
        findings.push(buildFinding(
          rel, i + 1, 'go-taint-sink',
          'HTTP request input flows into Go SQL/shell sink',
          'high', 'CWE-89',
          'Use parameterized SQL placeholders ($1 / ?) or pass explicit command arguments without sh -c.',
          'Tainted HTTP request input flows into SQL concatenation or shell command execution.',
          trimmed,
        ));
      }
    }

    if (GO_PATH_SINK_RE.test(trimmed) && !GO_SANITIZER_RE.test(trimmed)) {
      const usesTainted = GO_SOURCE_RE.test(trimmed) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(trimmed));
      if (usesTainted) {
        findings.push(buildFinding(
          rel, i + 1, 'go-path-traversal',
          'HTTP request input flows into Go filesystem read/write sink',
          'high', 'CWE-22',
          'Sanitize filenames with filepath.Base() and verify the resolved path stays inside an allowed base directory.',
          'Tainted HTTP request input flows into os.ReadFile/os.Open/os.Remove without filepath.Base.',
          trimmed,
        ));
      }
    }
  }
  return findings;
}

function analyzeRustSemantic(raw, rel) {
  const findings = [];
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (/sqlx::query\s*\(\s*&?format!\s*\(/.test(trimmed) || /\.execute\s*\(\s*&?format!\s*\(/.test(trimmed)) {
      findings.push(buildFinding(
        rel, i + 1, 'rust-sql-format',
        'Rust SQL query built with format!() interpolation',
        'high', 'CWE-89',
        'Use bound parameters (.bind(value)) with sqlx::query("SELECT ... WHERE id = $1") instead of format!().',
        'Dynamic format!() string is passed directly into SQL query execution.',
        trimmed,
      ));
    }
    if (/Command::new\s*\(\s*"(?:sh|bash)"\s*\)\s*\.arg\s*\(\s*"-c"\s*\)\s*\.arg\s*\(\s*&?[A-Za-z_]\w*/.test(trimmed)) {
      findings.push(buildFinding(
        rel, i + 1, 'rust-cmd-shell-taint',
        'Dynamic variable passed to sh -c via std::process::Command',
        'high', 'CWE-78',
        'Pass the executable and individual arguments via Command::new(bin).arg(arg) without a shell.',
        'Command::new("sh").arg("-c").arg(var) enables shell injection if var contains untrusted input.',
        trimmed,
      ));
    }
  }
  return findings;
}

function analyzeSemanticPolyglot(raw, rel, extName) {
  if (extName === '.sol') return analyzeSolidity(raw, rel);
  if (extName === '.py') return analyzePythonTaint(raw, rel);
  if (extName === '.go') return analyzeGoTaint(raw, rel);
  if (extName === '.rs') return analyzeRustSemantic(raw, rel);
  return [];
}

const RS_SOURCE_RE = /\b(?:web::(?:Query|Path|Json)|Query<|Path<|Json<|req\.(?:query_string|headers|match_info)|std::env::args)/;
const RS_SANITIZER_RE = /\b(?:\.parse::<(?:i32|i64|u32|u64|usize|bool)>|Path::new\([^)]*\)\.file_name)/;
const RS_SINK_RE = /\b(?:sqlx::query\s*\(\s*&?format!|Command::new\s*\(\s*"(?:sh|bash)"\s*\)\s*\.arg\s*\(\s*"-c")/;

const LANG_CG_SPEC = {
  '.py': {
    lang: 'python',
    fnKinds: ['function_definition'],
    assignKinds: ['assignment'],
    callKinds: ['call'],
    sourceRe: PY_SOURCE_RE,
    sanitizerRe: PY_SANITIZER_RE,
    sinkRe: PY_SINK_RE,
    ruleId: 'py-crossfile-taint',
    hint: (fnName, sinkMeta) => `Sanitize or parameterize input before calling "${fnName}()" (${sinkMeta.file}:${sinkMeta.line}).`,
    title: (fnName, sinkMeta) => `Cross-file taint: request input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
  },
  '.go': {
    lang: 'go',
    fnKinds: ['function_declaration', 'method_declaration'],
    assignKinds: ['short_var_declaration', 'assignment_statement'],
    callKinds: ['call_expression'],
    sourceRe: GO_SOURCE_RE,
    sanitizerRe: GO_SANITIZER_RE,
    sinkRe: /\b(?:db\.(?:Query|Exec|QueryRow)\s*\(|exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"|os\.(?:ReadFile|Open|WriteFile|Remove)\s*\()/,
    ruleId: 'go-crossfile-taint',
    hint: (fnName, sinkMeta) => `Use parameterized queries or validate input before calling "${fnName}()" (${sinkMeta.file}:${sinkMeta.line}).`,
    title: (fnName, sinkMeta) => `Cross-file taint: HTTP input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
  },
  '.rs': {
    lang: 'rust',
    fnKinds: ['function_item'],
    assignKinds: ['let_declaration', 'assignment_expression'],
    callKinds: ['call_expression', 'macro_invocation'],
    sourceRe: RS_SOURCE_RE,
    sanitizerRe: RS_SANITIZER_RE,
    sinkRe: RS_SINK_RE,
    ruleId: 'rust-crossfile-taint',
    hint: (fnName, sinkMeta) => `Use bound parameters or avoid shell -c before calling "${fnName}()" (${sinkMeta.file}:${sinkMeta.line}).`,
    title: (fnName, sinkMeta) => `Cross-file taint: untrusted input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
  },
};

function parseFnSignature(fnText, extName) {
  if (extName === '.py') {
    const m = fnText.match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!m) return null;
    const params = m[2].split(',')
      .map((p) => p.trim().split(/[:=]/)[0].trim().replace(/^\*+/, ''))
      .filter((p) => /^[A-Za-z_]\w*$/.test(p) && p !== 'self' && p !== 'cls');
    return { fnName: m[1], params };
  }
  if (extName === '.go') {
    const m = fnText.match(/^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    if (!m) return null;
    const params = m[2].split(',')
      .map((p) => p.trim().split(/\s+/)[0])
      .filter((p) => /^[A-Za-z_]\w*$/.test(p));
    return { fnName: m[1], params };
  }
  if (extName === '.rs') {
    const m = fnText.match(/^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)(?:<[^>]*>)?\s*\(([^)]*)\)/);
    if (!m) return null;
    const params = m[2].split(',')
      .map((p) => p.trim().split(':')[0].trim().replace(/^mut\s+/, ''))
      .filter((p) => /^[A-Za-z_]\w*$/.test(p) && p !== 'self');
    return { fnName: m[1], params };
  }
  return null;
}

function splitCallArgs(callText) {
  const open = callText.indexOf('(');
  const close = callText.lastIndexOf(')');
  if (open < 0 || close <= open) return [];
  const inner = callText.slice(open + 1, close);
  const args = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      args.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}

function parseAssignPair(text, extName) {
  let clean = text.trim();
  if (extName === '.rs') clean = clean.replace(/^let\s+(?:mut\s+)?/, '').replace(/;$/, '');
  const sep = extName === '.go' && clean.includes(':=') ? ':=' : '=';
  const idx = clean.indexOf(sep);
  if (idx < 0) return null;
  const lhs = clean.slice(0, idx).trim().split(/[\s,]+/)[0];
  const rhs = clean.slice(idx + sep.length).trim();
  if (!/^[A-Za-z_]\w*$/.test(lhs)) return null;
  return { lhs, rhs };
}

function exprUsesAny(expr, varSet) {
  for (const v of varSet) {
    if (new RegExp(`\\b${v}\\b`).test(expr)) return true;
  }
  return false;
}

function buildAstCallGraph(polyglotFiles, ag) {
  const fnNodes = [];
  const fnByName = new Map();

  for (const { rel, raw, extName } of polyglotFiles) {
    const spec = LANG_CG_SPEC[extName];
    if (!spec) continue;
    let root;
    try { root = ag.parse(spec.lang, raw).root(); } catch { continue; }
    const lines = raw.split(/\r?\n/);

    const fns = [];
    for (const kind of spec.fnKinds) fns.push(...root.findAll({ rule: { kind } }));

    for (const fn of fns) {
      const sig = parseFnSignature(fn.text(), extName);
      if (!sig) continue;
      const startLine = fn.range().start.line + 1;

      // Track which variables inside this function are tainted by each param index AND by external sources
      const paramTaintedVars = sig.params.map((p) => new Set([p]));
      const sourceTaintedVars = new Set();

      const assigns = [];
      for (const ak of spec.assignKinds) assigns.push(...fn.findAll({ rule: { kind: ak } }));
      assigns.sort((a, b) => a.range().start.index - b.range().start.index);

      for (const st of assigns) {
        const pair = parseAssignPair(st.text(), extName);
        if (!pair) continue;
        if (spec.sanitizerRe.test(pair.rhs)) {
          sourceTaintedVars.delete(pair.lhs);
          for (const pSet of paramTaintedVars) pSet.delete(pair.lhs);
          continue;
        }
        if (spec.sourceRe.test(pair.rhs) || exprUsesAny(pair.rhs, sourceTaintedVars)) {
          sourceTaintedVars.add(pair.lhs);
        }
        for (let idx = 0; idx < paramTaintedVars.length; idx++) {
          if (exprUsesAny(pair.rhs, paramTaintedVars[idx])) {
            paramTaintedVars[idx].add(pair.lhs);
          }
        }
      }

      const calls = [];
      for (const ck of spec.callKinds) calls.push(...fn.findAll({ rule: { kind: ck } }));
      calls.sort((a, b) => a.range().start.index - b.range().start.index);

      const sinkParams = new Set();
      let directSinkLine = null;
      const outgoingCalls = [];

      for (const call of calls) {
        const cText = call.text();
        const cLine = call.range().start.line + 1;

        if (spec.sinkRe.test(cText) && !spec.sanitizerRe.test(cText)) {
          const isSafeGoSql = extName === '.go' && /\bdb\.(?:Query|Exec|QueryRow)\s*\(/.test(cText) && !/[+]|fmt\.Sprintf/.test(cText);
          const isSafePySubprocess = extName === '.py' && /\bsubprocess\./.test(cText) && !/\bshell\s*=\s*True\b/.test(cText);
          if (!isSafeGoSql && !isSafePySubprocess) {
            for (let idx = 0; idx < paramTaintedVars.length; idx++) {
              if (exprUsesAny(cText, paramTaintedVars[idx])) {
                sinkParams.add(idx);
                if (!directSinkLine) directSinkLine = cLine;
              }
            }
          }
        }

        const calleeMatch = cText.match(/^(?:[A-Za-z_]\w*(?:\.|::))?([A-Za-z_]\w*)\s*\(/);
        if (calleeMatch) {
          const calleeName = calleeMatch[1];
          const args = splitCallArgs(cText);
          const argParamDeps = args.map((arg) => {
            const deps = new Set();
            for (let idx = 0; idx < paramTaintedVars.length; idx++) {
              if (exprUsesAny(arg, paramTaintedVars[idx])) deps.add(idx);
            }
            return deps;
          });
          const argSourceDeps = args.map((arg) =>
            !spec.sanitizerRe.test(arg) && (spec.sourceRe.test(arg) || exprUsesAny(arg, sourceTaintedVars)),
          );
          outgoingCalls.push({
            calleeName,
            line: cLine,
            excerpt: lines[cLine - 1] || cText,
            argParamDeps,
            argSourceDeps,
          });
        }
      }

      const node = {
        extName,
        spec,
        file: rel,
        line: startLine,
        fnName: sig.fnName,
        params: sig.params,
        sinkParams,
        sinkMeta: sinkParams.size > 0 ? { file: rel, line: directSinkLine || startLine, fnName: sig.fnName } : null,
        outgoingCalls,
      };
      fnNodes.push(node);
      const key = `${extName}:${sig.fnName}`;
      if (!fnByName.has(key)) fnByName.set(key, []);
      fnByName.get(key).push(node);
    }
  }

  // Fixed-point propagation across the interprocedural call graph (handles multi-hop chains)
  for (let iter = 0; iter < 10; iter++) {
    let changed = false;
    for (const node of fnNodes) {
      for (const call of node.outgoingCalls) {
        const targets = fnByName.get(`${node.extName}:${call.calleeName}`) || [];
        for (const target of targets) {
          if (target === node || target.sinkParams.size === 0) continue;
          for (const sinkIdx of target.sinkParams) {
            const callerParamDeps = call.argParamDeps[sinkIdx];
            if (!callerParamDeps) continue;
            for (const pIdx of callerParamDeps) {
              if (!node.sinkParams.has(pIdx)) {
                node.sinkParams.add(pIdx);
                if (!node.sinkMeta) node.sinkMeta = target.sinkMeta;
                changed = true;
              }
            }
          }
        }
      }
    }
    if (!changed) break;
  }

  return { fnNodes, fnByName };
}

function analyzeCrossFilePolyglot(polyglotFiles) {
  const findings = [];
  const ag = getAstGrep();

  if (ag) {
    const { fnNodes, fnByName } = buildAstCallGraph(polyglotFiles, ag);
    const seen = new Set();
    for (const caller of fnNodes) {
      for (const call of caller.outgoingCalls) {
        const targets = fnByName.get(`${caller.extName}:${call.calleeName}`) || [];
        for (const target of targets) {
          if (target.file === caller.file || target.sinkParams.size === 0) continue;
          const hitsTaintedArg = [...target.sinkParams].some((idx) => call.argSourceDeps[idx]);
          if (!hitsTaintedArg) continue;
          const dedupeKey = `${caller.file}:${call.line}:${caller.spec.ruleId}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          const sinkMeta = target.sinkMeta || { file: target.file, line: target.line, fnName: target.fnName };
          findings.push(buildFinding(
            caller.file,
            call.line,
            caller.spec.ruleId,
            caller.spec.title(call.calleeName, sinkMeta),
            'critical',
            'CWE-89',
            caller.spec.hint(call.calleeName, sinkMeta),
            `AST call-graph taint flows from ${caller.file}:${call.line} into sink ${sinkMeta.file}:${sinkMeta.line}.`,
            call.excerpt,
          ));
        }
      }
    }
    return findings;
  }

  // Fallback line-based cross-file analyzer when @ast-grep/napi is unavailable
  const pySinkFns = new Map();
  const goSinkFns = new Map();

  for (const { rel, raw, extName } of polyglotFiles) {
    const lines = raw.split(/\r?\n/);
    if (extName === '.py') {
      for (let i = 0; i < lines.length; i++) {
        const defMatch = lines[i].match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/);
        if (!defMatch) continue;
        const fnName = defMatch[1];
        const params = defMatch[2].split(',').map((p) => p.trim().split(/[:=]/)[0].trim().replace(/^\*+/, '')).filter((p) => /^[A-Za-z_]\w*$/.test(p) && p !== 'self' && p !== 'cls');
        if (!params.length) continue;
        const body = lines.slice(i + 1, Math.min(lines.length, i + 25)).join('\n');
        if (PY_SINK_RE.test(body) && params.some((p) => new RegExp(`\\b${p}\\b`).test(body))) {
          pySinkFns.set(fnName, { file: rel, line: i + 1 });
        }
      }
    } else if (extName === '.go') {
      for (let i = 0; i < lines.length; i++) {
        const fnMatch = lines[i].match(/^\s*func\s+([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)/);
        if (!fnMatch) continue;
        const fnName = fnMatch[1];
        const params = fnMatch[2].split(',').map((p) => p.trim().split(/\s+/)[0]).filter((p) => /^[A-Za-z_]\w*$/.test(p));
        if (!params.length) continue;
        const body = lines.slice(i + 1, Math.min(lines.length, i + 30)).join('\n');
        if (GO_SINK_RE.test(body) && params.some((p) => new RegExp(`\\b${p}\\b`).test(body))) {
          goSinkFns.set(fnName, { file: rel, line: i + 1 });
        }
      }
    }
  }

  for (const { rel, raw, extName } of polyglotFiles) {
    const lines = raw.split(/\r?\n/);
    if (extName === '.py' && pySinkFns.size > 0) {
      const tainted = new Set();
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (/^(?:async\s+)?def\s+/.test(trimmed)) { tainted.clear(); continue; }
        const assign = trimmed.match(/^([A-Za-z_]\w*)\s*=\s*(.+)$/);
        if (assign && (PY_SOURCE_RE.test(assign[2]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(assign[2])))) {
          tainted.add(assign[1]);
        }
        for (const [fnName, sinkMeta] of pySinkFns.entries()) {
          if (sinkMeta.file === rel) continue;
          const callRe = new RegExp(`\\b${fnName}\\s*\\(([^)]+)\\)`);
          const cm = callRe.exec(trimmed);
          if (cm && (PY_SOURCE_RE.test(cm[1]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(cm[1])))) {
            findings.push(buildFinding(
              rel, i + 1, 'py-crossfile-taint',
              `Cross-file taint: request input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
              'critical', 'CWE-89',
              `Sanitize or parameterize input before calling "${fnName}()" in ${sinkMeta.file}.`,
              `Tainted input flows from ${rel}:${i + 1} into sink helper ${sinkMeta.file}:${sinkMeta.line}.`,
              trimmed,
            ));
          }
        }
      }
    } else if (extName === '.go' && goSinkFns.size > 0) {
      const tainted = new Set();
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (/^func\s+/.test(trimmed)) { tainted.clear(); continue; }
        const assign = trimmed.match(/^([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*(.+)$/);
        if (assign && (GO_SOURCE_RE.test(assign[2]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(assign[2])))) {
          tainted.add(assign[1]);
        }
        for (const [fnName, sinkMeta] of goSinkFns.entries()) {
          if (sinkMeta.file === rel) continue;
          const callRe = new RegExp(`\\b(?:[a-z_]+\\.)?${fnName}\\s*\\(([^)]+)\\)`);
          const cm = callRe.exec(trimmed);
          if (cm && (GO_SOURCE_RE.test(cm[1]) || [...tainted].some((v) => new RegExp(`\\b${v}\\b`).test(cm[1])))) {
            findings.push(buildFinding(
              rel, i + 1, 'go-crossfile-taint',
              `Cross-file taint: HTTP input passed to "${fnName}()" (${sinkMeta.file}:${sinkMeta.line})`,
              'critical', 'CWE-89',
              `Use parameterized queries or validate input before calling "${fnName}()" in ${sinkMeta.file}.`,
              `Tainted HTTP input flows from ${rel}:${i + 1} into sink helper ${sinkMeta.file}:${sinkMeta.line}.`,
              trimmed,
            ));
          }
        }
      }
    }
  }

  return findings;
}

module.exports = { analyzeSemanticPolyglot, analyzeCrossFilePolyglot };
