import { useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { AnimatePresence, motion } from 'motion/react';
import { ShieldAlert, FileCode2, Cpu, CheckCircle2 } from 'lucide-react';
import DecryptedText from './DecryptedText';

type CategoryKey = 'website' | 'api' | 'software';

interface Finding {
  id: string;
  ruleId: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  file: string;
  line: number;
  excerpt: string;
  trace: string;
  fix: string;
  aiVerdict: 'likely_real' | 'uncertain';
}

interface ScanProfile {
  label: string;
  command: string;
  files: number;
  ms: number;
  findings: Finding[];
}

const WEIGHTS: Record<Finding['severity'], number> = {
  critical: 18,
  high: 10,
  medium: 4,
  low: 1,
};

const PROFILES: Record<CategoryKey, ScanProfile> = {
  website: {
    label: 'Website',
    command: 'probe scan ./storefront -k Website --sarif',
    files: 142,
    ms: 318,
    findings: [
      {
        id: 'w1',
        ruleId: 'js-dom-innerhtml-tainted',
        cwe: 'CWE-79',
        severity: 'high',
        title: 'Tainted query string in innerHTML',
        file: 'src/SearchBanner.tsx',
        line: 47,
        excerpt: 'el.innerHTML = `Results for ${params.get("q")}`;',
        trace: 'URLSearchParams.get("q") → innerHTML',
        fix: 'Use textContent or DOMPurify.sanitize().',
        aiVerdict: 'likely_real',
      },
      {
        id: 'w2',
        ruleId: 'secret-stripe-live-key',
        cwe: 'CWE-798',
        severity: 'critical',
        title: 'Hardcoded Stripe live key',
        file: 'src/lib/checkout.ts',
        line: 9,
        excerpt: 'export const STRIPE_KEY = "sk_live_51N9x...REDACTED";',
        trace: 'Provider signature + entropy > 4.2',
        fix: 'Revoke key and load from server env.',
        aiVerdict: 'likely_real',
      },
      {
        id: 'w3',
        ruleId: 'js-open-redirect-location',
        cwe: 'CWE-601',
        severity: 'medium',
        title: 'Unvalidated redirect target',
        file: 'src/routes/callback.ts',
        line: 22,
        excerpt: 'window.location.assign(nextUrl || "/");',
        trace: 'req.query.next → location.assign',
        fix: 'Allow only single-slash relative paths.',
        aiVerdict: 'likely_real',
      },
    ],
  },
  api: {
    label: 'API',
    command: 'probe scan ./billing-api -k "API / backend" --fail-on high',
    files: 218,
    ms: 492,
    findings: [
      {
        id: 'a1',
        ruleId: 'sql-template-injection',
        cwe: 'CWE-89',
        severity: 'critical',
        title: 'Interpolated SQL template literal',
        file: 'server/invoices.js',
        line: 84,
        excerpt: 'await db.query(`SELECT * FROM invoices WHERE org = \'${req.query.org}\'`);',
        trace: 'req.query.org → raw SQL sink',
        fix: 'Use parameterized bindings ($1).',
        aiVerdict: 'likely_real',
      },
      {
        id: 'a2',
        ruleId: 'py-ast-pickle-loads',
        cwe: 'CWE-502',
        severity: 'high',
        title: 'Unsafe pickle.loads deserialization',
        file: 'workers/cache.py',
        line: 31,
        excerpt: 'payload = pickle.loads(raw_bytes)',
        trace: 'tree-sitter-python → pickle.loads',
        fix: 'Deserialize with json.loads().',
        aiVerdict: 'likely_real',
      },
      {
        id: 'a3',
        ruleId: 'fs-path-traversal-join',
        cwe: 'CWE-22',
        severity: 'medium',
        title: 'Unnormalized path.join on param',
        file: 'server/exports.js',
        line: 53,
        excerpt: 'const target = path.join(EXPORT_DIR, req.params.file);',
        trace: 'req.params.file → path.join',
        fix: 'Wrap with path.basename() + root check.',
        aiVerdict: 'uncertain',
      },
    ],
  },
  software: {
    label: 'Software',
    command: 'probe scan ./cli-engine -k Software --bugs-only',
    files: 94,
    ms: 241,
    findings: [
      {
        id: 's1',
        ruleId: 'go-ast-exec-command-shell',
        cwe: 'CWE-78',
        severity: 'high',
        title: 'Formatted shell string in exec.Command',
        file: 'internal/exec.go',
        line: 64,
        excerpt: 'exec.Command("sh", "-c", fmt.Sprintf("git log %s", ref))',
        trace: 'tree-sitter-go → exec.Command("sh", "-c")',
        fix: 'Pass args directly without sh -c.',
        aiVerdict: 'likely_real',
      },
      {
        id: 's2',
        ruleId: 'rs-ast-unsafe-transmute',
        cwe: 'CWE-704',
        severity: 'medium',
        title: 'Unchecked std::mem::transmute',
        file: 'crates/parser/ffi.rs',
        line: 118,
        excerpt: 'let slice: &[u8] = unsafe { std::mem::transmute(raw_buf) };',
        trace: 'tree-sitter-rust → mem::transmute',
        fix: 'Use slice::from_raw_parts with bounds.',
        aiVerdict: 'uncertain',
      },
      {
        id: 's3',
        ruleId: 'js-redos-nested-quantifier',
        cwe: 'CWE-1333',
        severity: 'low',
        title: 'Nested quantifier regex (ReDoS)',
        file: 'src/glob.js',
        line: 19,
        excerpt: 'const re = /^([a-zA-Z0-9_-]+)+\\.json$/;',
        trace: 'Regex AST → (+)+ backtracking',
        fix: 'Flatten to /^[a-zA-Z0-9_-]+\\.json$/.',
        aiVerdict: 'likely_real',
      },
    ],
  },
};

function computeScore(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  return Math.round((100 * 100) / (100 + penalty));
}

export function AuditPreview() {
  const [category, setCategory] = useState<CategoryKey>('website');
  const profile = PROFILES[category];
  const [selectedId, setSelectedId] = useState<string>(profile.findings[0].id);

  const selectedFinding =
    profile.findings.find((f) => f.id === selectedId) ?? profile.findings[0];
  const score = computeScore(profile.findings);

  const handleCategoryChange = (value: string) => {
    const next = value as CategoryKey;
    setCategory(next);
    setSelectedId(PROFILES[next].findings[0].id);
  };

  return (
    <Tabs.Root value={category} onValueChange={handleCategoryChange} className="audit-shell">
      <div className="audit-bar">
        <div className="audit-bar-left">
          <div className="window-dots" aria-hidden="true">
            <i />
            <i />
            <i />
          </div>
          <span className="audit-cmd">{profile.command}</span>
        </div>

        <Tabs.List className="audit-tabs" aria-label="Project category">
          {(Object.keys(PROFILES) as CategoryKey[]).map((key) => {
            const active = category === key;
            return (
              <Tabs.Trigger
                key={key}
                value={key}
                className={`audit-tab ${active ? 'is-active' : ''}`}
              >
                {active && (
                  <motion.span
                    layoutId="audit-tab-pill"
                    className="tab-pill-bg"
                    transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                  />
                )}
                <span className="tab-label">{PROFILES[key].label}</span>
              </Tabs.Trigger>
            );
          })}
        </Tabs.List>
      </div>

      <div className="audit-metrics audit-metrics-3">
        <div className="audit-metric">
          <span>SCORE</span>
          <strong className="metric-score">
            {score}
            <small>/100</small>
          </strong>
        </div>
        <div className="audit-metric">
          <span>FILES</span>
          <strong>{profile.files}</strong>
        </div>
        <div className="audit-metric">
          <span>TIME</span>
          <strong>{profile.ms}ms</strong>
        </div>
      </div>

      <div className="audit-body">
        <div className="audit-list" role="listbox" aria-label="Findings">
          {profile.findings.map((finding) => {
            const isSelected = finding.id === selectedFinding.id;
            return (
              <button
                key={finding.id}
                type="button"
                role="option"
                aria-selected={isSelected}
                className={`finding-row ${isSelected ? 'is-selected' : ''}`}
                onClick={() => setSelectedId(finding.id)}
              >
                <div className="finding-row-top">
                  <span className={`sev-pill sev-${finding.severity}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <span className="finding-cwe">{finding.cwe}</span>
                  <span className="finding-loc">
                    {finding.file}:{finding.line}
                  </span>
                </div>
                <p className="finding-title">
                  <DecryptedText text={finding.title} animateOn="hover" speed={30} />
                </p>
              </button>
            );
          })}
        </div>

        <div className="audit-inspector">
          <AnimatePresence mode="wait">
            <motion.div
              key={selectedFinding.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="inspector-inner"
            >
              <div className="inspector-head">
                <div className="inspector-title">
                  <ShieldAlert size={14} aria-hidden="true" />
                  <span>{selectedFinding.ruleId}</span>
                </div>
                <span className={`ai-verdict verdict-${selectedFinding.aiVerdict}`}>
                  <Cpu size={11} aria-hidden="true" />
                  <CheckCircle2 size={11} aria-hidden="true" />
                  {selectedFinding.aiVerdict}
                </span>
              </div>

              <div className="inspector-code">
                <div className="inspector-code-meta">
                  <FileCode2 size={12} aria-hidden="true" />
                  <span>
                    {selectedFinding.file}:{selectedFinding.line}
                  </span>
                </div>
                <pre>
                  <code>
                    <span className="line-num">{selectedFinding.line}</span>
                    {selectedFinding.excerpt}
                  </code>
                </pre>
              </div>

              <div className="inspector-meta-grid">
                <div className="inspector-block">
                  <span className="inspector-label">TRACE</span>
                  <p className="inspector-mono">
                    <DecryptedText text={selectedFinding.trace} speed={30} />
                  </p>
                </div>
                <div className="inspector-block">
                  <span className="inspector-label">FIX</span>
                  <p>
                    <DecryptedText text={selectedFinding.fix} speed={30} />
                  </p>
                </div>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </Tabs.Root>
  );
}
