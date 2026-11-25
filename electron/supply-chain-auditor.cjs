'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const POPULAR_PACKAGES = [
  'react', 'react-dom', 'next', 'vue', 'angular', 'svelte', 'express', 'fastify', 'koa',
  'lodash', 'axios', 'chalk', 'commander', 'yargs', 'inquirer', 'dotenv', 'zod', 'joi',
  'typescript', 'vite', 'webpack', 'esbuild', 'rollup', 'eslint', 'prettier', 'jest', 'vitest',
  'mocha', 'playwright', 'puppeteer', 'electron', 'tailwindcss', 'postcss', 'autoprefixer',
  'mongoose', 'prisma', 'drizzle-orm', 'sequelize', 'pg', 'mysql2', 'redis', 'ioredis',
  'jsonwebtoken', 'bcrypt', 'bcryptjs', 'cors', 'helmet', 'multer', 'socket.io', 'ws',
  'cross-env', 'rimraf', 'glob', 'minimist', 'uuid', 'nanoid', 'dayjs', 'moment', 'date-fns',
  'stripe', 'openai', 'firebase', 'supabase', 'graphql', 'apollo-server',
  // Popular Python packages
  'requests', 'numpy', 'pandas', 'flask', 'django', 'fastapi', 'uvicorn', 'pydantic',
  'sqlalchemy', 'pytest', 'pillow', 'scipy', 'boto3', 'urllib3', 'cryptography',
];

const POPULAR_SET = new Set(POPULAR_PACKAGES);

const RISKY_SCRIPT_PATTERNS = [
  { re: /\b(?:curl|wget)\s+https?:\/\//i, reason: 'Downloads remote payload during install' },
  { re: new RegExp(`\\bpowershell(?:\\.exe)?\\b.*(?:-${'enc'}|-${'encodedcommand'}|iex|downloadstring)`, 'i'), reason: 'Executes obfuscated PowerShell during install' },
  { re: /\beval\s*\(|new\s+Function\s*\(/i, reason: 'Dynamically evaluates code in lifecycle hook' },
  { re: /base64\s+(?:-d|--decode)|Buffer\.from\([^)]*['"]base64['"]\)/i, reason: 'Decodes obfuscated base64 payload during install' },
  { re: /\/dev\/tcp\/|nc\s+-e|bash\s+-i/i, reason: 'Reverse-shell style command in lifecycle hook' },
];

const COPYLEFT_RE = /\b(AGPL|GPL-?[23]|SSPL|BUSL|BSL-1\.1|EUPL|UNLICENSED)\b/i;
const PERMISSIVE_RE = /\b(MIT|ISC|BSD|Apache-2\.0|0BSD|Unlicense)\b/i;

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[a.length][b.length];
}

function detectTyposquat(pkgName) {
  const clean = String(pkgName || '').trim().toLowerCase();
  if (!clean || clean.startsWith('@') || clean.length < 4 || POPULAR_SET.has(clean)) return null;
  for (const popular of POPULAR_PACKAGES) {
    if (Math.abs(clean.length - popular.length) > 2) continue;
    const dist = levenshtein(clean, popular);
    if (dist === 1 || (dist === 2 && popular.length >= 7)) {
      return { suspect: clean, target: popular, distance: dist };
    }
  }
  return null;
}

async function readJsonSafe(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function auditSupplyChain(projectRoot) {
  const findings = [];
  const components = [];
  const rootPkg = await readJsonSafe(path.join(projectRoot, 'package.json'));
  const rootLicense = typeof rootPkg?.license === 'string' ? rootPkg.license : '';
  const projectIsPermissive = PERMISSIVE_RE.test(rootLicense);

  const allDeps = {
    ...(rootPkg?.dependencies || {}),
    ...(rootPkg?.devDependencies || {}),
  };

  // 1. Check npm dependencies for typosquatting & collect SBOM components
  for (const [name, ver] of Object.entries(allDeps)) {
    const cleanVer = String(ver || '').replace(/^[\^~>=<]+/, '') || '0.0.0';
    components.push({
      type: 'library',
      name,
      version: cleanVer,
      purl: `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(cleanVer)}`,
      ecosystem: 'npm',
    });

    const typo = detectTyposquat(name);
    if (typo) {
      findings.push({
        ruleId: 'supply-chain-typosquat',
        title: `Possible typosquatted package "${typo.suspect}" (similar to "${typo.target}")`,
        severity: 'high',
        cwe: 'CWE-829',
        file: 'package.json',
        detail: `Edit distance ${typo.distance} from popular package "${typo.target}". Verify publisher & downloads before trusting.`,
      });
    }
  }

  // 2. Check Python requirements.txt if present
  try {
    const reqText = await fs.readFile(path.join(projectRoot, 'requirements.txt'), 'utf8');
    for (const line of reqText.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const m = trimmed.match(/^([A-Za-z0-9_.-]+)(?:[=<>!~]+([^\s;#]+))?/);
      if (!m) continue;
      const pkgName = m[1];
      const pkgVer = m[2] || 'latest';
      components.push({
        type: 'library',
        name: pkgName,
        version: pkgVer,
        purl: `pkg:pypi/${encodeURIComponent(pkgName.toLowerCase())}@${encodeURIComponent(pkgVer)}`,
        ecosystem: 'pypi',
      });
      const typo = detectTyposquat(pkgName);
      if (typo) {
        findings.push({
          ruleId: 'supply-chain-typosquat-pypi',
          title: `Possible typosquatted Python package "${typo.suspect}" (similar to "${typo.target}")`,
          severity: 'high',
          cwe: 'CWE-829',
          file: 'requirements.txt',
          detail: `Edit distance ${typo.distance} from popular PyPI package "${typo.target}".`,
        });
      }
    }
  } catch {
    // No requirements.txt
  }

  // 3. Inspect installed node_modules/*/package.json for risky install scripts & copyleft license conflicts
  const nmDir = path.join(projectRoot, 'node_modules');
  const licenseSummary = {};
  let inspectedPackages = 0;

  async function inspectPackageDir(pkgDir, relName) {
    const pkg = await readJsonSafe(path.join(pkgDir, 'package.json'));
    if (!pkg) return;
    inspectedPackages += 1;

    const lic = typeof pkg.license === 'string'
      ? pkg.license
      : (typeof pkg.license?.type === 'string' ? pkg.license.type : 'UNKNOWN');
    licenseSummary[lic] = (licenseSummary[lic] || 0) + 1;

    // Enrich SBOM component license if present
    const comp = components.find((c) => c.name === relName);
    if (comp && lic !== 'UNKNOWN') {
      comp.licenses = [{ license: { id: lic } }];
      if (pkg.version) comp.version = pkg.version;
    }

    if (projectIsPermissive && COPYLEFT_RE.test(lic)) {
      findings.push({
        ruleId: 'supply-chain-license-conflict',
        title: `Restrictive/copyleft license (${lic}) in dependency "${relName}"`,
        severity: 'medium',
        cwe: 'CWE-1104',
        file: `node_modules/${relName}/package.json`,
        detail: `Project license is "${rootLicense}", which may conflict with "${lic}" in "${relName}".`,
      });
    }

    const scripts = pkg.scripts || {};
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      const cmd = scripts[hook];
      if (!cmd || typeof cmd !== 'string') continue;
      for (const pat of RISKY_SCRIPT_PATTERNS) {
        if (pat.re.test(cmd)) {
          findings.push({
            ruleId: 'supply-chain-risky-install-script',
            title: `Suspicious "${hook}" script in "${relName}"`,
            severity: 'high',
            cwe: 'CWE-506',
            file: `node_modules/${relName}/package.json`,
            detail: `${pat.reason}: ${cmd.slice(0, 140)}`,
          });
          break;
        }
      }
    }
  }

  try {
    const entries = await fs.readdir(nmDir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.name.startsWith('.')) continue;
      if (ent.name.startsWith('@')) {
        const scopedDir = path.join(nmDir, ent.name);
        try {
          const scopedEntries = await fs.readdir(scopedDir, { withFileTypes: true });
          for (const sub of scopedEntries) {
            if (sub.isDirectory()) {
              await inspectPackageDir(path.join(scopedDir, sub.name), `${ent.name}/${sub.name}`);
            }
          }
        } catch { /* ignore */ }
      } else {
        await inspectPackageDir(path.join(nmDir, ent.name), ent.name);
      }
    }
  } catch {
    // node_modules not installed
  }

  const sbom = generateCycloneDxSbom({
    projectName: rootPkg?.name || path.basename(projectRoot),
    projectVersion: rootPkg?.version || '0.0.0',
    components,
  });

  return {
    ok: true,
    projectName: rootPkg?.name || path.basename(projectRoot),
    rootLicense: rootLicense || 'UNSPECIFIED',
    totalDependencies: components.length,
    inspectedInstalled: inspectedPackages,
    licenseSummary,
    findings,
    sbom,
    auditedAt: new Date().toISOString(),
  };
}

function generateCycloneDxSbom({ projectName, projectVersion, components }) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'OSIEN',
          name: 'OSIEN Probe',
          version: '1.0.6',
        },
      ],
      component: {
        type: 'application',
        name: String(projectName || 'project'),
        version: String(projectVersion || '0.0.0'),
      },
    },
    components: (components || []).map((c) => ({
      type: c.type || 'library',
      name: c.name,
      version: c.version,
      purl: c.purl,
      ...(c.licenses ? { licenses: c.licenses } : {}),
    })),
  };
}

module.exports = {
  levenshtein,
  detectTyposquat,
  auditSupplyChain,
  generateCycloneDxSbom,
};
