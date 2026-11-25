#!/usr/bin/env node
'use strict';
// deepcheck-disable-file js-console-log js-process-exit

const fs = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline/promises');
const { spawn } = require('node:child_process');
const pkg = require('../package.json');
const {
  scanProjectRoot,
  discoverTestPlan,
  rulesForKind,
  toSarifReport,
  toMarkdownReport,
  kinds,
  SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'],
} = require('../electron/scanner.cjs');
const { checkAiHealth } = require('../electron/ai-review.cjs');
const { scanLiveUrl, generateWebRemediation } = require('../electron/web-auditor.cjs');
const { runNpcSwarmTest } = require('../electron/npc-swarm-tester.cjs');
const { scanGitHistorySecrets } = require('../electron/git-history-scanner.cjs');
const { auditSupplyChain } = require('../electron/supply-chain-auditor.cjs');
const { getPreCommitHookStatus, installPreCommitHook, removePreCommitHook } = require('../electron/git-hooks.cjs');

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
};

function sevColor(sev) {
  if (sev === 'critical') return `${C.bold}${C.red}`;
  if (sev === 'high') return C.red;
  if (sev === 'medium') return C.yellow;
  if (sev === 'low') return C.cyan;
  return C.gray;
}

function printHelp() {
  console.log(`OSIEN Probe v${pkg.version} — Offline static analysis, cross-file taint, CVE auditor & AI verifier

Usage:
  probe                               Launch interactive Terminal UI (all app options)
  probe scan [path] [options]         Scan a project directory
  probe npc [url-or-path] [options]   Simulate 100+ NPC users to stress-test & find bugs
  probe secrets-history [path]        Scan Git commit history for leaked secrets
  probe sbom [path] [--out file.json] Audit supply chain (typosquats/licenses/scripts) & export CycloneDX SBOM
  probe hook <install|remove|status>  Manage fast 1-click Git pre-commit guard
  probe rules [options]               List available rules and CWE mappings
  probe ai-status                     Check local Ollama AI review availability
  probe mcp                           Start the stdio MCP server (osien-probe-mcp)

Options:
  --kind, -k <category>   Project category (${kinds.join(' | ')}) [default: Software]
  --changed, --git-diff   Scan only Git-modified / untracked files (ultra-fast diff scan)
  --bugs-only             Filter out low-signal lint/style hints
  --json                  Output raw JSON scan report
  --sarif                 Output SARIF 2.1.0 report
  --markdown, --md        Output Markdown report
  --out, -o <file>        Write output report to a file
  --fail-on <severity>    Exit 1 if any finding is at or above (critical|high|medium|low|info)
  --fix [platform]        Generate live website fix config (nginx|apache|express|nextjs|vercel|cloudflare|all)
  --probe-exposed         Check for exposed /.git/HEAD and /.env on live URLs
  --probe-cors            Check if live URL reflects arbitrary Origin headers
  --crawl <n>             Crawl up to N same-origin linked HTML pages on live URLs
  --quiet, -q             Only print summary counts (no per-finding lines)
  --help, -h              Show this help
  --version, -v           Print version`);
}

function parseArgs(argv) {
  const opts = {
    command: argv.length === 0 ? 'menu' : 'scan',
    target: '.',
    kind: 'Software',
    changedOnly: false,
    bugsOnly: false,
    format: 'text',
    out: null,
    failOn: null,
    fix: null,
    probeExposed: false,
    probeCors: false,
    crawlPages: 0,
    npcs: 120,
    quiet: false,
    help: false,
    version: false,
  };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--version' || arg === '-v') opts.version = true;
    else if (arg === '--bugs-only') opts.bugsOnly = true;
    else if (arg === '--changed' || arg === '--git-diff') opts.changedOnly = true;
    else if (arg === '--probe-exposed') opts.probeExposed = true;
    else if (arg === '--probe-cors') opts.probeCors = true;
    else if (arg === '--crawl' && argv[i + 1]) opts.crawlPages = Math.max(0, Number(argv[++i]) || 0);
    else if (arg === '--npcs' && argv[i + 1]) opts.npcs = Math.max(10, Math.min(1000, Number(argv[++i]) || 120));
    else if (arg === '--fix' || arg === '--remediate') {
      const next = argv[i + 1];
      if (next && !next.startsWith('-') && ['nginx', 'apache', 'express', 'nextjs', 'vercel', 'cloudflare', 'all'].includes(next)) {
        opts.fix = next;
        i++;
      } else {
        opts.fix = 'all';
      }
    }
    else if (arg === '--json') opts.format = 'json';
    else if (arg === '--sarif') opts.format = 'sarif';
    else if (arg === '--markdown' || arg === '--md') opts.format = 'markdown';
    else if (arg === '--quiet' || arg === '-q') opts.quiet = true;
    else if ((arg === '--kind' || arg === '-k') && argv[i + 1]) opts.kind = argv[++i];
    else if ((arg === '--out' || arg === '-o') && argv[i + 1]) opts.out = argv[++i];
    else if (arg === '--fail-on' && argv[i + 1]) opts.failOn = argv[++i];
    else if (!arg.startsWith('-')) positional.push(arg);
  }
  if (['scan', 'npc', 'secrets-history', 'sbom', 'hook', 'rules', 'ai-status', 'menu', 'tui', 'ui', 'mcp'].includes(positional[0])) {
    const cmd = positional.shift();
    opts.command = cmd === 'tui' || cmd === 'ui' ? 'menu' : cmd;
  }
  if (opts.command === 'hook') {
    opts.hookAction = positional.shift() || 'status';
  }
  if (positional[0]) opts.target = positional[0];
  if (positional[1] && kinds.includes(positional[1])) opts.kind = positional[1];
  return opts;
}

function printBanner(lastRun) {
  console.log(`\n${C.bold}${C.green}┌────────────────────────────────────────────────────────────────────┐${C.reset}`);
  console.log(`${C.bold}${C.green}│${C.reset}  ${C.bold}OSIEN PROBE v${pkg.version}${C.reset}  ${C.dim}· 10 Categories · AST + Taint + CVE Engine${C.reset}     ${C.bold}${C.green}│${C.reset}`);
  console.log(`${C.bold}${C.green}└────────────────────────────────────────────────────────────────────┘${C.reset}`);
  if (lastRun) {
    const c = lastRun.result.severityCounts || {};
    console.log(`${C.dim}Active scan:${C.reset} ${C.bold}${lastRun.root}${C.reset} [${lastRun.kind}] · Score ${C.bold}${lastRun.result.score}/100${C.reset} · Findings: ${C.bold}${lastRun.result.findings.length}${C.reset} (C:${c.critical || 0} H:${c.high || 0} M:${c.medium || 0} L:${c.low || 0} I:${c.info || 0})`);
  } else {
    console.log(`${C.dim}No scan run yet in this session. Select [1] to scan a project.${C.reset}`);
  }
}

function printFindingList(list, limit = 30) {
  if (!list.length) {
    console.log(`${C.green}✔ No matching findings.${C.reset}`);
    return;
  }
  const shown = list.slice(0, limit);
  for (const f of shown) {
    console.log(`${sevColor(f.severity)}[${f.severity.toUpperCase()}]${C.reset} ${C.bold}${f.title}${C.reset} ${C.dim}(${f.ruleId})${C.reset} — ${C.cyan}${f.file}:${f.line}${C.reset}`);
    if (f.cwe || f.hint) console.log(`  ${C.dim}${f.cwe ? `${f.cwe}: ` : ''}${f.hint || ''}${C.reset}`);
    if (f.excerpt) console.log(`  ${C.gray}${f.excerpt.slice(0, 120)}${C.reset}`);
  }
  if (list.length > limit) {
    console.log(`${C.dim}... showing ${limit} of ${list.length} findings. Use Export [5] or severity filter [2] to view more.${C.reset}`);
  }
}

async function launchInteractiveCli() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let lastRun = null;

  try {
    while (true) {
      printBanner(lastRun);
      console.log(`
  ${C.bold}[1]${C.reset} Scan Project (Folder + Category + Bugs-Only / Full)
  ${C.bold}[2]${C.reset} Inspect Findings by Severity (critical / high / medium / low / info)
  ${C.bold}[3]${C.reset} Dependency CVE & Supply-Chain Audit
  ${C.bold}[4]${C.reset} Cross-File Taint & Deep Semantic Findings
  ${C.bold}[5]${C.reset} Export Report (JSON / SARIF 2.1.0 / Markdown)
  ${C.bold}[6]${C.reset} Browse Rule Catalog & CWE Search (${kinds.length} categories)
  ${C.bold}[7]${C.reset} Discover & Run Project Tests
  ${C.bold}[8]${C.reset} Check Local AI (Ollama) Status
  ${C.bold}[9]${C.reset} Launch OSIEN Probe Desktop App
  ${C.bold}[0]${C.reset} Exit
`);
      const choice = (await rl.question(`${C.green}probe>${C.reset} `)).trim();
      if (choice === '0' || choice.toLowerCase() === 'exit' || choice.toLowerCase() === 'q') break;

      if (choice === '1') {
        const targetRaw = (await rl.question(`Folder path [${C.dim}.${C.reset}]: `)).trim() || '.';
        console.log(`\nCategories:`);
        kinds.forEach((k, idx) => console.log(`  ${C.bold}[${idx + 1}]${C.reset} ${k} (${rulesForKind(k).length} rules)`));
        const kindIdxRaw = (await rl.question(`Category number [${C.dim}2 = Software${C.reset}]: `)).trim();
        const kindIdx = kindIdxRaw ? Number(kindIdxRaw) - 1 : 1;
        const selectedKind = kinds[kindIdx] || 'Software';
        const bugsAns = (await rl.question(`Filter noise with --bugs-only? [Y/n]: `)).trim().toLowerCase();
        const bugsOnly = bugsAns !== 'n' && bugsAns !== 'no';
        const root = path.resolve(targetRaw);
        console.log(`${C.dim}Scanning ${root} as ${selectedKind} (${bugsOnly ? 'bugs-only' : 'full'})...${C.reset}`);
        const result = await scanProjectRoot(root, selectedKind, { bugsOnly });
        lastRun = { root, kind: selectedKind, result };
        console.log(`${C.green}Done in ${result.durationMs}ms:${C.reset} ${result.filesScanned} files, ${result.rulesEvaluated.toLocaleString()} rule checks, Score ${C.bold}${result.score}/100${C.reset}, Findings ${C.bold}${result.findings.length}${C.reset}`);
        printFindingList(result.findings, 15);
      } else if (choice === '2') {
        if (!lastRun) {
          console.log(`${C.yellow}Run a scan first [1].${C.reset}`);
          continue;
        }
        const sev = (await rl.question(`Severity filter (all | critical | high | medium | low | info) [all]: `)).trim().toLowerCase() || 'all';
        const list = sev === 'all' ? lastRun.result.findings : lastRun.result.findings.filter((f) => f.severity === sev);
        printFindingList(list, 40);
      } else if (choice === '3') {
        if (!lastRun) {
          console.log(`${C.yellow}Run a scan first [1].${C.reset}`);
          continue;
        }
        const deps = lastRun.result.findings.filter((f) => String(f.ruleId).startsWith('dep-'));
        printFindingList(deps, 40);
      } else if (choice === '4') {
        if (!lastRun) {
          console.log(`${C.yellow}Run a scan first [1].${C.reset}`);
          continue;
        }
        const deep = lastRun.result.findings.filter((f) => /(?:crossfile|sol-|taint|idor|timing|mass-assignment|nextjs-api-no-auth|route-missing-auth|unguarded-null)/.test(f.ruleId));
        printFindingList(deep, 40);
      } else if (choice === '5') {
        if (!lastRun) {
          console.log(`${C.yellow}Run a scan first [1].${C.reset}`);
          continue;
        }
        const fmt = (await rl.question(`Format (json | sarif | markdown) [sarif]: `)).trim().toLowerCase() || 'sarif';
        const defaultName = fmt === 'json' ? 'osien-report.json' : fmt === 'markdown' ? 'osien-report.md' : 'osien-report.sarif.json';
        const outFile = (await rl.question(`Output file [${defaultName}]: `)).trim() || defaultName;
        const meta = { name: path.basename(lastRun.root), root: lastRun.root, kind: lastRun.kind };
        const content = fmt === 'json'
          ? JSON.stringify(lastRun.result, null, 2)
          : fmt === 'markdown'
            ? toMarkdownReport(lastRun.result, meta)
            : JSON.stringify(toSarifReport(lastRun.result, meta), null, 2);
        const dest = path.resolve(outFile);
        await fs.writeFile(dest, content, 'utf8');
        console.log(`${C.green}Saved ${fmt.toUpperCase()} report -> ${dest}${C.reset}`);
      } else if (choice === '6') {
        kinds.forEach((k, idx) => console.log(`  [${idx + 1}] ${k} (${rulesForKind(k).length} rules)`));
        const kRaw = (await rl.question(`Category number [1]: `)).trim();
        const k = kinds[(Number(kRaw || '1') - 1)] || kinds[0];
        const q = (await rl.question(`Filter keyword or CWE (optional): `)).trim().toLowerCase();
        const matched = rulesForKind(k).filter((r) => !q || `${r.id} ${r.title} ${r.cwe}`.toLowerCase().includes(q));
        console.log(`${C.bold}${matched.length} rules matched in "${k}":${C.reset}`);
        for (const r of matched.slice(0, 25)) {
          console.log(`  ${sevColor(r.severity)}[${r.severity.toUpperCase()}]${C.reset} ${r.id} (${r.cwe}, ${r.lang}) — ${r.title}`);
        }
      } else if (choice === '7') {
        const targetRaw = (await rl.question(`Project path [${lastRun ? lastRun.root : '.'}]: `)).trim() || (lastRun ? lastRun.root : '.');
        const plan = await discoverTestPlan(path.resolve(targetRaw));
        if (!plan.testCommand) {
          console.log(`${C.yellow}No test command detected in ${targetRaw}.${C.reset}`);
        } else {
          console.log(`Detected test command: ${C.bold}${plan.testCommand}${C.reset} (${plan.targets.length} test files)`);
          const go = (await rl.question(`Execute now? [y/N]: `)).trim().toLowerCase();
          if (go === 'y' || go === 'yes') {
            await new Promise((resolve) => {
              const child = spawn(plan.testCommand, { cwd: path.resolve(targetRaw), shell: true, stdio: 'inherit' });
              child.on('close', () => resolve());
            });
          }
        }
      } else if (choice === '8') {
        const health = await checkAiHealth();
        console.log(JSON.stringify(health, null, 2));
      } else if (choice === '9') {
        const unpackedExe = path.resolve(__dirname, '../release/win-unpacked/OSIEN Probe.exe');
        const hasExe = await fs.stat(unpackedExe).then(() => true).catch(() => false);
        if (hasExe) {
          spawn(unpackedExe, [], { detached: true, stdio: 'ignore' }).unref();
          console.log(`${C.green}Launched OSIEN Probe desktop app.${C.reset}`);
        } else {
          const electronBin = path.resolve(__dirname, '../node_modules/.bin/electron.cmd');
          spawn(electronBin, [path.resolve(__dirname, '..')], { detached: true, stdio: 'ignore', shell: true }).unref();
          console.log(`${C.green}Launched OSIEN Probe Electron app.${C.reset}`);
        }
      } else {
        console.log(`${C.yellow}Unknown option "${choice}". Choose 0–9.${C.reset}`);
      }
    }
  } finally {
    rl.close();
  }
}

async function run() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) {
    console.log(pkg.version);
    return;
  }
  if (opts.help) {
    printHelp();
    return;
  }
  if (opts.command === 'menu') {
    await launchInteractiveCli();
    return;
  }
  if (opts.command === 'npc') {
    const isUrl = /^https?:\/\//i.test(opts.target);
    const root = isUrl ? opts.target : path.resolve(opts.target);
    const res = await runNpcSwarmTest({ id: root, name: path.basename(root) || root, root }, { npcCount: opts.npcs });
    if (opts.format === 'json') {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`OSIEN Probe v${pkg.version} — NPC Swarm Test (${res.npcCount} NPCs)`);
      console.log(`Target:   ${res.targetUrl}`);
      console.log(`Requests: ${res.stats.totalRequests} (${res.stats.rps} req/s) · Duration: ${res.durationMs}ms`);
      console.log(`Status:   2xx/3xx=${res.stats.ok2xx3xx} 4xx=${res.stats.status4xx} 429=${res.stats.status429} 5xx=${res.stats.status5xx} timeouts=${res.stats.timeouts}`);
      console.log(`Latency:  p50=${res.stats.p50Ms}ms p95=${res.stats.p95Ms}ms p99=${res.stats.p99Ms}ms`);
      console.log(`Findings: ${res.findings.length}`);
      for (const f of res.findings) {
        console.log(`  [${f.severity.toUpperCase()}] ${f.title} (${f.ruleId}) — ${f.file}`);
        if (f.hint) console.log(`      ${f.hint}`);
      }
    }
    return;
  }
  if (opts.command === 'mcp') {
    const mcpEntry = path.resolve(__dirname, 'osien-probe-mcp.cjs');
    const child = spawn(process.execPath, [mcpEntry], { stdio: 'inherit' });
    await new Promise((resolve) => child.on('close', (code) => {
      process.exit(code || 0);
      resolve();
    }));
    return;
  }

  if (opts.command === 'ai-status') {
    const status = await checkAiHealth();
    console.log(JSON.stringify(status, null, 2));
    process.exit(status.available && status.modelInstalled ? 0 : 1);
  }

  if (!kinds.includes(opts.kind)) {
    console.error(`Unknown category "${opts.kind}". Use one of: ${kinds.join(', ')}`);
    process.exit(2);
  }

  if (opts.command === 'rules') {
    const rules = rulesForKind(opts.kind);
    if (opts.format === 'json') {
      console.log(JSON.stringify(rules.map(({ id, title, severity, cwe, lang, hint }) => ({ id, title, severity, cwe, lang, hint })), null, 2));
    } else {
      console.log(`OSIEN Probe rules for "${opts.kind}" (${rules.length} rules):`);
      for (const r of rules) console.log(`- [${r.severity.toUpperCase()}] ${r.id} (${r.cwe}, ${r.lang}): ${r.title}`);
    }
    return;
  }

  if (opts.command === 'secrets-history') {
    const root = path.resolve(opts.target);
    const res = await scanGitHistorySecrets(root, { maxCommits: 50 });
    if (opts.format === 'json') {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`OSIEN Probe Git History Secret Scan · ${root}`);
      console.log(`Commits scanned: ${res.commitsScanned} · Leaks found: ${res.findings.length}`);
      for (const f of res.findings) {
        console.log(`[${f.severity.toUpperCase()}] ${f.title} (${f.status}) — ${f.file} @ ${f.commitHash} (${f.commitDate}) ${f.redactedPreview}`);
      }
    }
    if (res.findings.length > 0 && opts.failOn) process.exit(1);
    return;
  }

  if (opts.command === 'sbom') {
    const root = path.resolve(opts.target);
    const res = await auditSupplyChain(root);
    if (opts.out) {
      await fs.mkdir(path.dirname(path.resolve(opts.out)), { recursive: true });
      await fs.writeFile(path.resolve(opts.out), JSON.stringify(res.sbom, null, 2), 'utf8');
      console.log(`CycloneDX 1.5 SBOM saved to ${path.resolve(opts.out)} (${res.totalDependencies} components)`);
    } else if (opts.format === 'json') {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`OSIEN Probe Supply-Chain & SBOM Audit · ${res.projectName}`);
      console.log(`Dependencies: ${res.totalDependencies} · Installed inspected: ${res.inspectedInstalled} · Findings: ${res.findings.length}`);
      for (const f of res.findings) {
        console.log(`[${f.severity.toUpperCase()}] ${f.title} (${f.file})`);
        if (f.detail) console.log(`    ${f.detail}`);
      }
    }
    if (res.findings.length > 0 && opts.failOn) process.exit(1);
    return;
  }

  if (opts.command === 'hook') {
    const root = path.resolve(opts.target);
    if (opts.hookAction === 'install') {
      const r = await installPreCommitHook(root, { failOn: opts.failOn || 'critical' });
      console.log(`Installed OSIEN Probe pre-commit hook at ${r.hookPath} (blocks on ${r.failOn}+ findings).`);
    } else if (opts.hookAction === 'remove') {
      const r = await removePreCommitHook(root);
      console.log(r.removed ? `Removed OSIEN Probe pre-commit hook from ${r.hookPath}.` : 'No OSIEN Probe pre-commit hook was installed.');
    } else {
      const s = await getPreCommitHookStatus(root);
      console.log(s.isGitRepo ? `Pre-commit guard: ${s.installed ? 'INSTALLED' : 'NOT INSTALLED'} (${s.hookPath})` : 'Not a Git repository.');
    }
    return;
  }

  const isLiveUrl = /^https?:\/\//i.test(opts.target);
  const root = isLiveUrl ? opts.target : path.resolve(opts.target);
  const result = isLiveUrl
    ? await scanLiveUrl(root, {
      bugsOnly: opts.bugsOnly,
      probeExposedFiles: opts.probeExposed,
      probeCorsReflection: opts.probeCors,
      crawlPages: opts.crawlPages,
    })
    : await scanProjectRoot(root, opts.kind, { bugsOnly: opts.bugsOnly, changedOnly: opts.changedOnly });
  if (isLiveUrl && opts.fix) {
    result.remediation = generateWebRemediation(result, root);
  }
  const filesScanned = result.filesScanned ?? result.scannedFiles ?? 0;
  const rulesEvaluated = result.rulesEvaluated ?? result.totalChecks ?? 0;
  const projectMeta = { name: isLiveUrl ? new URL(root).hostname : path.basename(root), root, kind: result.kind || opts.kind };

  let output = '';
  if (opts.format === 'sarif') {
    output = JSON.stringify(toSarifReport(result, projectMeta), null, 2);
  } else if (opts.format === 'json') {
    output = JSON.stringify(result, null, 2);
  } else if (opts.format === 'markdown') {
    output = toMarkdownReport(result, projectMeta);
  } else {
    const lines = [
      `OSIEN Probe v${pkg.version}`,
      `Path:        ${result.root || root}`,
      `Category:    ${result.kind || opts.kind}`,
      `Files:       ${filesScanned}`,
      `Rule checks: ${rulesEvaluated.toLocaleString()}`,
      `Findings:    ${result.findings.length}${result.truncated ? ' (truncated at limit)' : ''}`,
      `Score:       ${result.score}/100`,
      `Duration:    ${result.durationMs}ms`,
      `Severity:    ${Object.entries(result.severityCounts).map(([k, v]) => `${k}=${v}`).join(' ')}`,
    ];
    if (result.testCommand) lines.push(`Test cmd:    ${result.testCommand}`);
    if (!opts.quiet && result.findings.length) {
      lines.push('');
      for (const f of result.findings) {
        lines.push(`[${f.severity.toUpperCase()} · ${f.confidence || 'medium'}] ${f.title} (${f.ruleId}) — ${f.file}:${f.line}`);
        if (f.cwe || f.hint) lines.push(`    ${f.cwe ? `${f.cwe}: ` : ''}${f.hint || ''}`);
        if (f.reason) lines.push(`    Why: ${f.reason}`);
        if (f.excerpt) lines.push(`    ${f.excerpt}`);
      }
    }
    if (isLiveUrl && opts.fix && result.remediation) {
      const platforms = opts.fix === 'all' ? Object.keys(result.remediation.configs) : [opts.fix];
      for (const p of platforms) {
        if (result.remediation.configs[p]) {
          lines.push('', `--- Fix Config (${p}) ---`, result.remediation.configs[p]);
        }
      }
    }
    output = lines.join('\n');
  }

  if (opts.out) {
    await fs.mkdir(path.dirname(path.resolve(opts.out)), { recursive: true });
    await fs.writeFile(path.resolve(opts.out), output, 'utf8');
    console.error(`Report saved to ${path.resolve(opts.out)}`);
  } else {
    console.log(output);
  }

  if (opts.failOn) {
    const threshold = SEVERITIES.indexOf(opts.failOn.toLowerCase());
    if (threshold >= 0 && result.findings.some((f) => SEVERITIES.indexOf(f.severity) <= threshold)) {
      process.exit(1);
    }
  }
}

run().catch((error) => {
  console.error(error?.message || String(error));
  process.exit(2);
});
