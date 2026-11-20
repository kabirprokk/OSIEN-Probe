import { motion } from 'motion/react';
import { ArrowLeft, ArrowUpRight, Compass, Cpu, Globe, Rocket, ShieldCheck } from 'lucide-react';
import DecryptedText from './DecryptedText';

interface HistoryPageProps {
  onBack: () => void;
  onOpenDocs: () => void;
}

const TIMELINE = [
  {
    era: 'ORIGIN',
    version: 'v0.x → v1.0.0',
    title: 'Started as DeepCheck',
    summary:
      'Born as a local offline desktop bug finder with single-pass pattern checks and automatic local Ollama AI reviews.',
    tags: ['Offline Desktop', 'Pattern Engine', 'Local Ollama'],
    status: 'past' as const,
  },
  {
    era: 'IDENTITY',
    version: 'v1.0.1',
    title: 'Reborn as OSIEN Probe',
    summary:
      'Renamed to OSIEN Probe with its orbital emblem, scriptable CLI, zero-dependency stdio MCP server, and SARIF 2.1.0 exports.',
    tags: ['probe CLI', 'osien-probe-mcp', 'SARIF 2.1.0'],
    status: 'past' as const,
  },
  {
    era: 'SCALE',
    version: 'v1.0.2 → v1.0.4',
    title: '1,142+ Ultra Rules & Polyglot AST',
    summary:
      'Expanded to 11 tree-sitter grammars, CFG compound guard narrowing, 1,160+ regression tests, and Claude / OpenCode / Pi AI providers.',
    tags: ['1,142+ Rules', '11 AST Grammars', 'Multi-AI Triage'],
    status: 'past' as const,
  },
  {
    era: 'NOW',
    version: 'v1.0.5',
    title: 'Call Graphs, Live URL Auditor & Native NSIS',
    summary:
      'Full AST call graphs (JS/TS, Python, Go, Rust, Java, PHP, Ruby, Kotlin, C/C++, Swift), multi-page live URL crawl with --fix configs, and drag-drop Desktop polish.',
    tags: ['AST Call Graphs', 'Live URL + --fix', 'Save Config', 'NSIS'],
    status: 'now' as const,
  },
];

const NEXT_ITEMS = [
  {
    index: '01',
    icon: Cpu,
    title: 'Whole-Program Cross-Module Taint',
    desc: 'Inter-procedural call-graph tracing across monorepo boundaries — still 100% offline with zero code execution.',
  },
  {
    index: '02',
    icon: ShieldCheck,
    title: 'Safe Diff Auto-Patching',
    desc: 'Previewable, deterministic one-click remediation patches across Desktop, CLI, and MCP agent workflows.',
  },
  {
    index: '03',
    icon: Globe,
    title: 'Native IDE & CI Extensions',
    desc: 'Real-time inline diagnostics for VS Code and zero-config GitHub Actions powered by the exact same local core.',
  },
];

export function HistoryPage({ onBack, onOpenDocs }: HistoryPageProps) {
  return (
    <motion.div
      className="docs-page history-page section-wrap"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.42, ease: [0.22, 1, 0.36, 1] }}
    >
      {/* Top Bar */}
      <div className="docs-header">
        <button type="button" className="docs-back-btn" onClick={onBack}>
          <ArrowLeft size={14} aria-hidden="true" />
          BACK TO HOME
        </button>

        <div className="docs-header-actions">
          <button type="button" className="docs-back-btn" onClick={onOpenDocs}>
            DOCS
          </button>
          <a
            className="docs-back-btn"
            href="https://github.com/kabirprokk/OSIEN-Probe/commits/main"
            target="_blank"
            rel="noreferrer"
          >
            GIT LOG <ArrowUpRight size={13} aria-hidden="true" />
          </a>
        </div>
      </div>

      {/* Hero */}
      <div className="docs-hero">
        <p className="eyebrow">
          <span className="status-dot" aria-hidden="true" />
          OSIEN PROBE · EVOLUTION &amp; ROADMAP
        </p>
        <h1>
          <DecryptedText text="Where Probe started." animateOn="hover" speed={42} />
          <br />
          <span>
            <DecryptedText text="Where it is going." animateOn="hover" speed={42} />
          </span>
        </h1>
      </div>

      <div className="docs-stack">
        {/* 01 / VISUAL ORBITAL TIMELINE SVG */}
        <section className="docs-section">
          <div className="section-kicker">
            <span>01 / FLIGHT PATH</span>
            <span className="kicker-line" />
            <span>DeepCheck → v1.0.5 → Horizon</span>
          </div>

          <div className="docs-svg-card">
            <svg viewBox="0 0 920 220" role="img" aria-label="OSIEN Probe evolution flight path from origin to future">
              <defs>
                <linearGradient id="hist-path" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="rgba(255,255,255,0.3)" />
                  <stop offset="72%" stopColor="#a3ff12" />
                  <stop offset="100%" stopColor="rgba(163,255,18,0.2)" />
                </linearGradient>
              </defs>

              {/* Past -> Now solid orbital arc */}
              <path
                d="M 70 150 Q 260 65 460 110 T 700 84"
                fill="none"
                stroke="url(#hist-path)"
                strokeWidth="2.5"
                strokeLinecap="round"
              />

              {/* Now -> Future dashed trajectory */}
              <path
                d="M 700 84 Q 785 62 854 48"
                fill="none"
                stroke="#a3ff12"
                strokeWidth="1.8"
                strokeDasharray="6 6"
              />
              <polygon points="852,43 864,46 854,53" fill="#a3ff12" />

              {/* Node 1: Origin */}
              <g transform="translate(70, 150)">
                <circle r="7" fill="#050505" stroke="#ffffff" strokeWidth="2" />
                <text x="0" y="28" textAnchor="middle" fill="#b3b3b3" fontFamily="JetBrains Mono, monospace" fontSize="10">v0.x</text>
                <text x="0" y="45" textAnchor="middle" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="13" fontWeight="500">DeepCheck</text>
              </g>

              {/* Node 2: v1.0.1 */}
              <g transform="translate(275, 92)">
                <circle r="7" fill="#050505" stroke="#ffffff" strokeWidth="2" />
                <text x="0" y="-22" textAnchor="middle" fill="#b3b3b3" fontFamily="JetBrains Mono, monospace" fontSize="10">v1.0.1</text>
                <text x="0" y="-38" textAnchor="middle" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="13" fontWeight="500">Probe + MCP</text>
              </g>

              {/* Node 3: v1.0.4 */}
              <g transform="translate(495, 114)">
                <circle r="8" fill="#050505" stroke="#a3ff12" strokeWidth="2" />
                <text x="0" y="28" textAnchor="middle" fill="#b3b3b3" fontFamily="JetBrains Mono, monospace" fontSize="10">v1.0.4</text>
                <text x="0" y="45" textAnchor="middle" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="13" fontWeight="500">1,142+ Rules</text>
              </g>

              {/* Node 4: NOW v1.0.5 */}
              <g transform="translate(700, 84)">
                <circle r="18" fill="rgba(163,255,18,0.14)" stroke="rgba(163,255,18,0.45)" strokeWidth="1" />
                <circle r="9" fill="#a3ff12" />
                <circle r="3.5" fill="#050505" />
                <text x="0" y="-28" textAnchor="middle" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10" letterSpacing="1.2">NOW · v1.0.5</text>
                <text x="0" y="34" textAnchor="middle" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="14" fontWeight="600">Call Graphs + Live URL</text>
              </g>

              {/* Node 5: Future */}
              <g transform="translate(864, 46)">
                <text x="-10" y="32" textAnchor="middle" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">v1.1+</text>
                <text x="-10" y="48" textAnchor="middle" fill="#e0e0e0" fontFamily="Space Grotesk, sans-serif" fontSize="12">Next Horizon</text>
              </g>
            </svg>
          </div>
        </section>

        {/* 02 / MILESTONES */}
        <section className="docs-section">
          <div className="section-kicker">
            <span>02 / MILESTONES</span>
            <span className="kicker-line" />
            <span>Every leap shipped in the open</span>
          </div>

          <div className="history-grid">
            {TIMELINE.map((item) => (
              <article
                key={item.version}
                className={`history-card ${item.status === 'now' ? 'is-now' : ''}`}
              >
                <div className="history-card-top">
                  <span className="history-era">{item.era}</span>
                  <span className="history-ver">{item.version}</span>
                </div>
                <h3>{item.title}</h3>
                <p>{item.summary}</p>
                <div className="feature-tags">
                  {item.tags.map((tag) => (
                    <span key={tag}>{tag}</span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </section>

        {/* 03 / GROWTH SNAPSHOT SVG */}
        <section className="docs-section">
          <div className="section-kicker">
            <span>03 / GROWTH</span>
            <span className="kicker-line" />
            <span>Rule &amp; engine expansion</span>
          </div>

          <div className="docs-svg-card">
            <svg viewBox="0 0 920 170" role="img" aria-label="OSIEN Probe rule catalog growth from v1.0.0 to v1.0.5">
              {[
                { label: 'v1.0.0  DeepCheck', count: '120+ rules', width: 98, y: 24, fill: 'rgba(255,255,255,0.28)' },
                { label: 'v1.0.1  Probe + MCP', count: '482 rules', width: 222, y: 60, fill: 'rgba(255,255,255,0.52)' },
                { label: 'v1.0.3  Polyglot AST', count: '551 rules', width: 268, y: 96, fill: 'rgba(255,255,255,0.78)' },
                { label: 'v1.0.5  NOW (Ultra)', count: '1,142+ rules · 11 AST Call Graphs', width: 430, y: 132, fill: '#a3ff12' },
              ].map((bar) => (
                <g key={bar.label}>
                  <text x="16" y={bar.y + 13} fill="#e0e0e0" fontFamily="JetBrains Mono, monospace" fontSize="11">
                    {bar.label}
                  </text>
                  <rect x="200" y={bar.y} width="430" height="18" rx="3" fill="rgba(255,255,255,0.06)" />
                  <rect x="200" y={bar.y} width={bar.width} height="18" rx="3" fill={bar.fill} />
                  <text
                    x="648"
                    y={bar.y + 13}
                    fill={bar.fill === '#a3ff12' ? '#a3ff12' : '#b3b3b3'}
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="10.5"
                  >
                    {bar.count}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </section>

        {/* 04 / WHAT'S COMING NEXT */}
        <section className="docs-section">
          <div className="section-kicker">
            <span>04 / WHAT&apos;S NEXT</span>
            <span className="kicker-line" />
            <span>The v1.1+ horizon</span>
          </div>

          <div className="docs-svg-card">
            <svg viewBox="0 0 920 155" role="img" aria-label="Upcoming OSIEN Probe roadmap blueprint">
              <rect x="24" y="24" width="268" height="106" rx="6" fill="#0b0b0b" stroke="rgba(255,255,255,0.22)" />
              <text x="44" y="52" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">NEXT 01</text>
              <text x="44" y="82" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="18" fontWeight="500">Cross-Module Taint</text>
              <text x="44" y="106" fill="#b3b3b3" fontFamily="Inter, sans-serif" fontSize="12">Whole-repo call graphs offline</text>

              <line x1="292" y1="77" x2="324" y2="77" stroke="#a3ff12" strokeWidth="1.5" strokeDasharray="4 4" />

              <rect x="326" y="24" width="268" height="106" rx="6" fill="#0b0b0b" stroke="#a3ff12" strokeWidth="1.4" />
              <text x="346" y="52" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">NEXT 02</text>
              <text x="346" y="82" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="18" fontWeight="500">Safe Diff Auto-Patch</text>
              <text x="346" y="106" fill="#b3b3b3" fontFamily="Inter, sans-serif" fontSize="12">1-click verified local fixes</text>

              <line x1="594" y1="77" x2="626" y2="77" stroke="#ffffff" strokeWidth="1.5" strokeDasharray="4 4" />

              <rect x="628" y="24" width="268" height="106" rx="6" fill="#0b0b0b" stroke="rgba(255,255,255,0.22)" />
              <text x="648" y="52" fill="#a3ff12" fontFamily="JetBrains Mono, monospace" fontSize="10">NEXT 03</text>
              <text x="648" y="82" fill="#ffffff" fontFamily="Space Grotesk, sans-serif" fontSize="18" fontWeight="500">IDE &amp; CI Plugins</text>
              <text x="648" y="106" fill="#b3b3b3" fontFamily="Inter, sans-serif" fontSize="12">VS Code + GitHub Action</text>
            </svg>
          </div>

          <div className="docs-grid-3">
            {NEXT_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.index} className="docs-card">
                  <div className="feature-top">
                    <span className="feature-index">{item.index}</span>
                    <span className="feature-symbol">
                      <Icon size={17} aria-hidden="true" />
                    </span>
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.desc}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Bottom CTA */}
        <div className="history-footer-cta">
          <div className="history-footer-note">
            <Compass size={16} aria-hidden="true" />
            <span>Follow every release and commit openly on GitHub.</span>
          </div>
          <a
            className="button button-primary"
            href="https://github.com/kabirprokk/OSIEN-Probe"
            target="_blank"
            rel="noreferrer"
          >
            <Rocket size={15} aria-hidden="true" /> Follow on GitHub
          </a>
        </div>
      </div>
    </motion.div>
  );
}
