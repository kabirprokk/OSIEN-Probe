import { useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { motion } from 'motion/react';
import { ArrowLeft, Bot, Check, Copy, User } from 'lucide-react';
import DecryptedText from './DecryptedText';

interface DocsPageProps {
  onBack: () => void;
}

const AI_LLMS_TXT = `# OSIEN Probe (v1.0.5) — AI Agent Reference

## What it is
Offline static source code scanner (1,142+ ultra rules), 11-language tree-sitter AST call graphs & CFG compound guard analyzer, deep Live Website URL auditor with auto-fix config generator, secret detector, and zero-dependency stdio MCP server. Executes ZERO project code during scans.

## Install
git clone https://github.com/kabirprokk/OSIEN-Probe.git
cd OSIEN-Probe && npm install

## CLI Commands
probe                                               # Interactive TUI
probe scan <path|https://url> [options]             # Static project or Live URL scan
probe rules [--kind <category>]                     # List 1,142+ rules & CWEs
probe ai-status                                     # Check AI providers (Ollama, Claude, OpenCode, Pi)
probe mcp                                           # Start stdio MCP server
npm run audit -- <path> "<category>" --sarif        # Export SARIF 2.1.0

## CLI Flags
--kind, -k <Website | Software | API / backend | Mobile app | Library | Data / ML>
--bugs-only | --json | --sarif | --markdown | --out <file> | --fail-on <critical|high|medium|low|info>
--fix [nginx|apache|express|nextjs|vercel|cloudflare|all]  # Generate live web security fix config
--probe-exposed                                     # Check /.git/HEAD and /.env on live URLs
--probe-cors                                        # Check arbitrary Origin CORS reflection
--crawl <n>                                         # Crawl up to N same-origin linked HTML pages

## AST Call Graphs & Languages
JS/TS (Babel) + 11 tree-sitter grammars: Python, Go, Rust, Java, PHP, Ruby, Kotlin, C/C++, Swift, C#, Bash.

## MCP Server (stdio)
Command: node bin/osien-probe-mcp.cjs
Tools:
1. scan_project({ path, category?, format?: "json"|"sarif", maxFindings?: 1..1000 })
2. inspect_finding_context({ root, file, line, radius?: 1..30 })
3. verify_finding_with_ai({ root, file, line, title, severity?, ruleId?, excerpt? })
4. list_rules({ category? })

## Score Formula & Limits
Score = 100 * 100 / (100 + penalty); weights: critical=18, high=10, medium=4, low=1, info=0.
Limits: Static heuristics (not proof). Skips node_modules, dist, build, .git, minified JS/CSS, lockfiles, files > 1MB. Caps at 6,000 files or 1,000 findings.
Suppressions: .deepcheckignore globs or inline deepcheck-disable-file / deepcheck-disable-line / deepcheck-disable-next-line.`;

const MCP_JSON = `{
  "mcpServers": {
    "osien-probe": {
      "command": "node",
      "args": ["bin/osien-probe-mcp.cjs"]
    }
  }
}`;

export function DocsPage({ onBack }: DocsPageProps) {
  const [audience, setAudience] = useState<'human' | 'ai'>('human');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 1800);
    } catch {
      setCopiedId(null);
    }
  };

  return (
    <motion.div
      className="docs-page section-wrap"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
    >
      {/* Top Bar */}
      <div className="docs-header">
        <button type="button" className="docs-back-btn" onClick={onBack}>
          <ArrowLeft size={14} aria-hidden="true" />
          BACK TO HOME
        </button>

        <div className="docs-header-actions">
          <Tabs.Root
            value={audience}
            onValueChange={(v) => setAudience(v as 'human' | 'ai')}
            className="docs-mode-tabs"
          >
            <Tabs.List className="audit-tabs" aria-label="Documentation reader mode">
              <Tabs.Trigger
                value="human"
                className={`audit-tab ${audience === 'human' ? 'is-active' : ''}`}
              >
                {audience === 'human' && (
                  <motion.span layoutId="docs-mode-pill" className="tab-pill-bg" />
                )}
                <span className="tab-label">
                  <User size={11} aria-hidden="true" /> HUMAN
                </span>
              </Tabs.Trigger>
              <Tabs.Trigger
                value="ai"
                className={`audit-tab ${audience === 'ai' ? 'is-active' : ''}`}
              >
                {audience === 'ai' && (
                  <motion.span layoutId="docs-mode-pill" className="tab-pill-bg" />
                )}
                <span className="tab-label">
                  <Bot size={11} aria-hidden="true" /> AI / AGENT
                </span>
              </Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content value="human" />
            <Tabs.Content value="ai" />
          </Tabs.Root>

          <button
            type="button"
            className="copy-command docs-llms-btn"
            data-copied={copiedId === 'llms'}
            onClick={() => copyText('llms', AI_LLMS_TXT)}
          >
            {copiedId === 'llms' ? (
              <>
                <Check size={12} aria-hidden="true" /> COPIED LLMS.TXT
              </>
            ) : (
              <>
                <Copy size={12} aria-hidden="true" /> COPY FOR AI
              </>
            )}
          </button>
        </div>
      </div>

      {/* Title */}
      <div className="docs-hero">
        <p className="eyebrow">
          <span className="status-dot" aria-hidden="true" />
          <DecryptedText text="OSIEN PROBE · DOCUMENTATION" speed={40} />
        </p>
        <h1>
          {audience === 'human' ? (
            <>
              <DecryptedText text="How Probe works." speed={42} />
              <br />
              <span>
                <DecryptedText text="Simply explained." speed={42} />
              </span>
            </>
          ) : (
            <>
              <DecryptedText text="Machine-readable spec." speed={42} />
              <br />
              <span>
                <DecryptedText text="Ready for agents." speed={42} />
              </span>
            </>
          )}
        </h1>
      </div>

      {audience === 'human' ? (
        <div className="docs-stack">
          {/* 01 / WHAT IS IT (Visual SVG) */}
          <section className="docs-section">
            <div className="section-kicker">
              <span>01 / WHAT IS IT</span>
              <span className="kicker-line" />
              <span>Zero cloud · Zero execution</span>
            </div>
            <p className="docs-lead">
              OSIEN Probe reads your source files on your own machine and flags bugs, unsafe code
              paths, and leaked secrets — without ever running your project.
            </p>

            <div className="docs-svg-card">
              <svg viewBox="0 0 920 210" role="img" aria-label="OSIEN Probe local architecture">
                {/* Node 1: Local Code */}
                <rect x="24" y="42" width="220" height="126" rx="8" fill="#0b0b0b" stroke="rgba(255,255,255,0.22)" />
                <text x="48" y="76" fill="#9a9a9a" fontFamily="JetBrains Mono, monospace" fontSize="10" letterSpacing="1.5">01 INPUT</text>
                <text x="48" y="106" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="20" fontWeight="500">Your Code</text>
                <text x="48" y="132" fill="#9a9a9a" fontFamily="Inter, sans-serif" fontSize="12">Local folder or Git URL</text>
                <text x="48" y="150" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">0 lines executed</text>

                {/* Arrow 1 */}
                <line x1="244" y1="105" x2="328" y2="105" stroke="#a3ff12" strokeWidth="1.5" strokeDasharray="5 5" />
                <polygon points="328,100 338,105 328,110" fill="#a3ff12" />

                {/* Node 2: Probe Core */}
                <rect x="342" y="28" width="236" height="154" rx="8" fill="#0f0f0f" stroke="#a3ff12" strokeWidth="1.5" />
                <circle cx="366" cy="56" r="4" fill="#a3ff12" />
                <text x="380" y="60" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10" letterSpacing="1.5">OSIEN PROBE CORE</text>
                <text x="366" y="92" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="20" fontWeight="500">Static Engine</text>
                <text x="366" y="118" fill="#d8d8d8" fontFamily="JetBrains Mono, monospace" fontSize="11">• 11-Language AST</text>
                <text x="366" y="138" fill="#d8d8d8" fontFamily="JetBrains Mono, monospace" fontSize="11">• Same-File Taint</text>
                <text x="366" y="158" fill="#d8d8d8" fontFamily="JetBrains Mono, monospace" fontSize="11">• Entropy Secret Check</text>

                {/* Arrow 2 */}
                <line x1="578" y1="105" x2="662" y2="105" stroke="#ffffff" strokeWidth="1.5" strokeDasharray="5 5" />
                <polygon points="662,100 672,105 662,110" fill="#ffffff" />

                {/* Node 3: Outputs */}
                <rect x="676" y="42" width="220" height="126" rx="8" fill="#0b0b0b" stroke="rgba(255,255,255,0.22)" />
                <text x="700" y="76" fill="#9a9a9a" fontFamily="JetBrains Mono, monospace" fontSize="10" letterSpacing="1.5">03 OUTPUT</text>
                <text x="700" y="106" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="20" fontWeight="500">Clear Triage</text>
                <text x="700" y="132" fill="#9a9a9a" fontFamily="Inter, sans-serif" fontSize="12">Exact file, line &amp; fix hint</text>
                <text x="700" y="150" fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="10">SARIF · JSON · Markdown</text>
              </svg>
            </div>
          </section>

          {/* 02 / HOW A SCAN WORKS (4-Step Visual Pipeline SVG) */}
          <section className="docs-section">
            <div className="section-kicker">
              <span>02 / PIPELINE</span>
              <span className="kicker-line" />
              <span>4 steps per scan</span>
            </div>

            <div className="docs-svg-card">
              <svg viewBox="0 0 920 175" role="img" aria-label="4 step scan pipeline">
                {[
                  { x: 18, n: '01', title: 'Walk Files', sub: 'Skips deps, locks & >1MB', accent: false },
                  { x: 244, n: '02', title: 'Parse AST', sub: 'Babel + 11 tree-sitter', accent: false },
                  { x: 470, n: '03', title: 'Track Taint', sub: 'Input → Sanitizer → Sink', accent: true },
                  { x: 696, n: '04', title: 'AI Triage', sub: 'Optional local Ollama', accent: false },
                ].map((step, idx) => (
                  <g key={step.n}>
                    <rect
                      x={step.x}
                      y="24"
                      width="206"
                      height="126"
                      rx="6"
                      fill="#0b0b0b"
                      stroke={step.accent ? '#a3ff12' : 'rgba(255,255,255,0.2)'}
                    />
                    <text
                      x={step.x + 20}
                      y="54"
                      fill={step.accent ? '#a3ff12' : '#9a9a9a'}
                      fontFamily="JetBrains Mono, monospace"
                      fontSize="11"
                    >
                      {step.n}
                    </text>
                    <text
                      x={step.x + 20}
                      y="90"
                      fill="#ffffff"
                      fontFamily="Space Grotesk, sans-serif"
                      fontSize="19"
                      fontWeight="500"
                    >
                      {step.title}
                    </text>
                    <text
                      x={step.x + 20}
                      y="118"
                      fill="#9a9a9a"
                      fontFamily="Inter, sans-serif"
                      fontSize="12"
                    >
                      {step.sub}
                    </text>
                    {idx < 3 && (
                      <line
                        x1={step.x + 206}
                        y1="87"
                        x2={step.x + 226}
                        y2="87"
                        stroke="#a3ff12"
                        strokeWidth="1.5"
                      />
                    )}
                  </g>
                ))}
              </svg>
            </div>
          </section>

          {/* 03 / SCORE FORMULA (Visual SVG) */}
          <section className="docs-section">
            <div className="section-kicker">
              <span>03 / SCORING</span>
              <span className="kicker-line" />
              <span>100 × 100 / (100 + penalty)</span>
            </div>

            <div className="docs-svg-card">
              <svg viewBox="0 0 920 150" role="img" aria-label="Severity weight scale">
                {[
                  { label: 'CRITICAL', w: 18, bar: 420, y: 24, fill: '#ffffff' },
                  { label: 'HIGH', w: 10, bar: 240, y: 56, fill: 'rgba(255,255,255,0.68)' },
                  { label: 'MEDIUM', w: 4, bar: 110, y: 88, fill: 'rgba(255,255,255,0.42)' },
                  { label: 'LOW', w: 1, bar: 36, y: 120, fill: '#a3ff12' },
                ].map((row) => (
                  <g key={row.label}>
                    <text x="24" y={row.y + 12} fill="#d8d8d8" fontFamily="JetBrains Mono, monospace" fontSize="11">
                      {row.label}
                    </text>
                    <rect x="130" y={row.y} width="540" height="16" rx="3" fill="rgba(255,255,255,0.06)" />
                    <rect x="130" y={row.y} width={row.bar} height="16" rx="3" fill={row.fill} />
                    <text x="695" y={row.y + 12} fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="11">
                      +{row.w} penalty
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </section>

          {/* 04 / INSTALL & USE */}
          <section className="docs-section">
            <div className="section-kicker">
              <span>04 / INSTALL &amp; USE</span>
              <span className="kicker-line" />
              <span>3 ways to run</span>
            </div>

            <div className="docs-grid-3">
              <div className="docs-card">
                <span className="feature-index">DESKTOP</span>
                <h3>Visual App &amp; Save Config</h3>
                <p>Drag-drop folders, Git URLs, or deep Live URL audits. Export fix configs &amp; install via native NSIS.</p>
                <code>npm install &amp;&amp; npm run dev</code>
              </div>
              <div className="docs-card">
                <span className="feature-index">LIVE URL &amp; CLI</span>
                <h3>Crawl, Probe &amp; Auto-Fix</h3>
                <p>Audit live HTTPS sites for TLS, CORS reflection, and exposed dotfiles, then generate server fix configs.</p>
                <code>probe scan https://site.com --crawl 5 --fix vercel</code>
              </div>
              <div className="docs-card">
                <span className="feature-index">SUPPRESSIONS</span>
                <h3>Ignore Noise</h3>
                <p>Skips minified JS/CSS automatically. Use <code>.deepcheckignore</code> globs or inline comments.</p>
                <code>// deepcheck-disable-next-line</code>
              </div>
            </div>
          </section>
        </div>
      ) : (
        <div className="docs-stack">
          {/* AI / AGENT MODE */}
          <section className="docs-section">
            <div className="section-kicker">
              <span>01 / MCP ARCHITECTURE</span>
              <span className="kicker-line" />
              <span>Zero-dependency stdio server</span>
            </div>

            <div className="docs-svg-card">
              <svg viewBox="0 0 920 185" role="img" aria-label="AI Agent to OSIEN Probe MCP flow">
                <rect x="24" y="34" width="220" height="116" rx="8" fill="#0b0b0b" stroke="rgba(255,255,255,0.24)" />
                <text x="46" y="66" fill="#9a9a9a" fontFamily="JetBrains Mono, monospace" fontSize="10">AI CLIENT</text>
                <text x="46" y="98" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="20" fontWeight="500">Coding Agent</text>
                <text x="46" y="124" fill="#9a9a9a" fontFamily="JetBrains Mono, monospace" fontSize="10">JSON-RPC over stdio</text>

                <line x1="244" y1="92" x2="336" y2="92" stroke="#a3ff12" strokeWidth="1.5" />
                <polygon points="336,87 346,92 336,97" fill="#a3ff12" />

                <rect x="350" y="24" width="240" height="136" rx="8" fill="#0f0f0f" stroke="#a3ff12" strokeWidth="1.5" />
                <text x="372" y="54" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">osien-probe-mcp.cjs</text>
                <text x="372" y="84" fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="11">1. scan_project</text>
                <text x="372" y="104" fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="11">2. inspect_finding_context</text>
                <text x="372" y="124" fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="11">3. verify_finding_with_ai</text>
                <text x="372" y="144" fill="#ffffff" fontFamily="JetBrains Mono, monospace" fontSize="11">4. list_rules</text>

                <line x1="590" y1="92" x2="674" y2="92" stroke="#ffffff" strokeWidth="1.5" />
                <polygon points="674,87 684,92 674,97" fill="#ffffff" />

                <rect x="688" y="34" width="208" height="116" rx="8" fill="#0b0b0b" stroke="rgba(255,255,255,0.24)" />
                <text x="710" y="66" fill="#9a9a9a" fontFamily="JetBrains Mono, monospace" fontSize="10">SANDBOXED</text>
                <text x="710" y="98" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="20" fontWeight="500">Local Repo</text>
                <text x="710" y="124" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">Path-traversal guarded</text>
              </svg>
            </div>
          </section>

          <section className="docs-section">
            <div className="section-kicker">
              <span>02 / MCP CONFIG &amp; TOOLS</span>
              <span className="kicker-line" />
              <span>Copy &amp; wire directly</span>
            </div>

            <div className="docs-ai-grid">
              <div className="docs-code-panel">
                <div className="docs-code-head">
                  <span>MCP CLIENT CONFIG</span>
                  <button
                    type="button"
                    className="copy-command"
                    data-copied={copiedId === 'mcp-json'}
                    onClick={() => copyText('mcp-json', MCP_JSON)}
                  >
                    {copiedId === 'mcp-json' ? <Check size={11} /> : <Copy size={11} />}
                    {copiedId === 'mcp-json' ? 'COPIED' : 'COPY'}
                  </button>
                </div>
                <pre>
                  <code>{MCP_JSON}</code>
                </pre>
              </div>

              <div className="docs-tools-list">
                <div className="docs-tool-row">
                  <code>scan_project</code>
                  <span>path, category?, format? (&quot;json&quot;|&quot;sarif&quot;), maxFindings?</span>
                </div>
                <div className="docs-tool-row">
                  <code>inspect_finding_context</code>
                  <span>root, file, line, radius? (1–30, path-traversal safe)</span>
                </div>
                <div className="docs-tool-row">
                  <code>verify_finding_with_ai</code>
                  <span>root, file, line, title → likely_real | likely_false_positive | uncertain</span>
                </div>
                <div className="docs-tool-row">
                  <code>list_rules</code>
                  <span>category? → rule IDs, severities, CWEs, hints + Ollama health</span>
                </div>
              </div>
            </div>
          </section>

          <section className="docs-section">
            <div className="section-kicker">
              <span>03 / RAW LLMS.TXT</span>
              <span className="kicker-line" />
              <span>Paste directly into any LLM prompt</span>
            </div>
            <div className="docs-code-panel">
              <div className="docs-code-head">
                <span>LLMS.TXT CONTEXT</span>
                <button
                  type="button"
                  className="copy-command"
                  data-copied={copiedId === 'llms-raw'}
                  onClick={() => copyText('llms-raw', AI_LLMS_TXT)}
                >
                  {copiedId === 'llms-raw' ? <Check size={11} /> : <Copy size={11} />}
                  {copiedId === 'llms-raw' ? 'COPIED' : 'COPY ALL'}
                </button>
              </div>
              <pre>
                <code>{AI_LLMS_TXT}</code>
              </pre>
            </div>
          </section>
        </div>
      )}
    </motion.div>
  );
}
