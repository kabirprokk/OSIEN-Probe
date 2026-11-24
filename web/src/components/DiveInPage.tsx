import { useState } from 'react';
import { motion } from 'motion/react';
import { ArrowLeft, ArrowUpRight, Compass, ExternalLink, Github } from 'lucide-react';
import DecryptedText from './DecryptedText';

interface DiveInPageProps {
  onBack: () => void;
  onOpenDocs: () => void;
}

interface OceanProject {
  id: string;
  name: string;
  zone: 'SUNLIGHT' | 'TWILIGHT' | 'MIDNIGHT' | 'ABYSSAL';
  depthM: number;
  tag: string;
  summary: string;
  liveUrl?: string;
  repoUrl: string;
  cx: number;
  cy: number;
  align: 'left' | 'right';
  current?: boolean;
}

const OCEAN_PROJECTS: OceanProject[] = [
  {
    id: 'osien',
    name: 'OSIEN',
    zone: 'SUNLIGHT',
    depthM: 40,
    tag: 'Parent Ecosystem',
    summary: 'The parent company & open-source monorepo housing every OSIEN tool, app, and experiment.',
    liveUrl: 'https://osien.is-a.dev/',
    repoUrl: 'https://github.com/kabirprokk/OSIEN',
    cx: 480,
    cy: 135,
    align: 'right',
  },
  {
    id: 'osien-probe',
    name: 'OSIEN Probe',
    zone: 'SUNLIGHT',
    depthM: 180,
    tag: 'Static Analysis · v1.0.5',
    summary: 'Offline 11-language AST bug finder (1,142+ rules), live URL auditor with auto-fix configs, and MCP server.',
    liveUrl: 'https://osienprobe.vercel.app/',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Probe',
    cx: 340,
    cy: 295,
    align: 'right',
    current: true,
  },
  {
    id: 'osien-stack',
    name: 'OSIEN Stack',
    zone: 'TWILIGHT',
    depthM: 480,
    tag: '45 MCP Tools',
    summary: 'Portable AI tooling stack with 45 MCP tools, reusable skills, commands, agents, and task runners.',
    liveUrl: 'https://osienstack.vercel.app/',
    repoUrl: 'https://github.com/kabirprokk/Osien-Stack',
    cx: 650,
    cy: 470,
    align: 'left',
  },
  {
    id: 'ocms',
    name: 'OCMS Marketplace',
    zone: 'TWILIGHT',
    depthM: 720,
    tag: 'OpenCode Registry',
    summary: 'OpenCode Marketplace web portal, CLI, and registry for discovering and installing AI coding tools.',
    liveUrl: 'https://ocms.pages.dev/',
    repoUrl: 'https://github.com/kabirprokk/opencode-marketplace-web',
    cx: 320,
    cy: 645,
    align: 'right',
  },
  {
    id: 'osin',
    name: 'OSIN',
    zone: 'TWILIGHT',
    depthM: 960,
    tag: 'Terminal AI',
    summary: 'Focused terminal-native AI coding assistant with configurable OpenAI-compatible endpoints.',
    liveUrl: 'https://osin.pages.dev/',
    repoUrl: 'https://github.com/kabirprokk/OSIN',
    cx: 660,
    cy: 815,
    align: 'left',
  },
  {
    id: 'osien-forge',
    name: 'OSIEN Forge',
    zone: 'MIDNIGHT',
    depthM: 1420,
    tag: 'AI Studio Toolkit',
    summary: 'Free AI workflows for generating games, websites, brand kits, invoices, and self-healing tools.',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Forge',
    cx: 350,
    cy: 1005,
    align: 'right',
  },
  {
    id: 'keepthestyle',
    name: 'KeepTheStyle v1',
    zone: 'MIDNIGHT',
    depthM: 1850,
    tag: 'Visual Builder',
    summary: 'No-code visual website builder designed for rapid layout composition and clean exports.',
    liveUrl: 'https://keepthestyle-v1.vercel.app/',
    repoUrl: 'https://github.com/kabirprokk/keepthestyle_v1',
    cx: 645,
    cy: 1185,
    align: 'left',
  },
  {
    id: 'gramiqo',
    name: 'Gramiqo',
    zone: 'MIDNIGHT',
    depthM: 2280,
    tag: 'Browser Extension',
    summary: 'Lightweight browser extension crafted in the OSIEN ecosystem for everyday web productivity.',
    liveUrl: 'https://gramiqo.vercel.app/',
    repoUrl: 'https://github.com/kabirprokk/Gramiqo',
    cx: 340,
    cy: 1365,
    align: 'right',
  },
  {
    id: 'record-common',
    name: 'Record Common',
    zone: 'ABYSSAL',
    depthM: 3100,
    tag: 'Data Utility',
    summary: 'Structured TypeScript web utility for organizing and sharing common records cleanly.',
    liveUrl: 'https://reccommons.vercel.app/',
    repoUrl: 'https://github.com/kabirprokk/Record-Common',
    cx: 630,
    cy: 1550,
    align: 'left',
  },
  {
    id: 'osien-memories',
    name: 'OSIEN Memories',
    zone: 'ABYSSAL',
    depthM: 3850,
    tag: 'Desktop Importer',
    summary: 'Clean-room Windows iPhone media importer and deterministic date/type file organizer.',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Memories',
    cx: 485,
    cy: 1720,
    align: 'right',
  },
];

const DEPTH_MARKERS = [
  { y: 120, label: '0m · SUNLIGHT ZONE' },
  { y: 420, label: '400m · TWILIGHT ZONE' },
  { y: 950, label: '1,200m · MIDNIGHT ZONE' },
  { y: 1490, label: '2,800m · ABYSSAL TRENCH' },
];

export function DiveInPage({ onBack, onOpenDocs }: DiveInPageProps) {
  const [selectedId, setSelectedId] = useState<string>('osien-probe');

  const selected =
    OCEAN_PROJECTS.find((p) => p.id === selectedId) ?? OCEAN_PROJECTS[0];

  // Smooth sinuous dive cable connecting all 10 projects from surface to abyss
  const cablePath = OCEAN_PROJECTS.map((p, idx) => {
    if (idx === 0) return `M ${p.cx} ${p.cy}`;
    const prev = OCEAN_PROJECTS[idx - 1];
    const midY = (prev.cy + p.cy) / 2;
    return `C ${prev.cx} ${midY}, ${p.cx} ${midY}, ${p.cx} ${p.cy}`;
  }).join(' ');

  return (
    <motion.div
      className="docs-page dive-page section-wrap"
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
            href="https://github.com/kabirprokk"
            target="_blank"
            rel="noreferrer"
          >
            GITHUB <ArrowUpRight size={13} aria-hidden="true" />
          </a>
        </div>
      </div>

      {/* Hero */}
      <div className="docs-hero">
        <p className="eyebrow">
          <span className="status-dot" aria-hidden="true" />
          OSIEN ECOSYSTEM · 10 VERIFIED WORKING PROJECTS
        </p>
        <h1>
          <DecryptedText text="Dive into OSIEN." animateOn="hover" speed={42} />
          <br />
          <span>
            <DecryptedText text="Explore the deep." animateOn="hover" speed={42} />
          </span>
        </h1>
        <p className="docs-lead">
          Scroll down the sonar cable and click any project node in the ocean to inspect it or
          launch it live.
        </p>
      </div>

      {/* Interactive Inspector Dock (sticky on desktop so clicking any SVG node updates immediately) */}
      <div className="dive-layout">
        <div className="dive-ocean-wrap">
          <svg
            viewBox="0 0 960 1850"
            className="dive-ocean-svg"
            role="img"
            aria-label="Interactive OSIEN deep-ocean map with 10 clickable working projects"
          >
            <defs>
              <linearGradient id="ocean-depth" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#0e120e" />
                <stop offset="22%" stopColor="#090b09" />
                <stop offset="55%" stopColor="#050605" />
                <stop offset="100%" stopColor="#020202" />
              </linearGradient>
              <linearGradient id="cable-glow" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#ffffff" stopOpacity="0.85" />
                <stop offset="45%" stopColor="#a3ff12" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#a3ff12" stopOpacity="0.35" />
              </linearGradient>
            </defs>

            {/* Deepening ocean backdrop */}
            <rect x="0" y="0" width="960" height="1850" rx="10" fill="url(#ocean-depth)" />

            {/* Surface ocean waves */}
            <path
              d="M 0 58 Q 120 34 240 58 T 480 58 T 720 58 T 960 58"
              fill="none"
              stroke="#a3ff12"
              strokeWidth="1.8"
              strokeOpacity="0.7"
            />
            <path
              d="M 0 74 Q 140 52 280 74 T 560 74 T 840 74 T 960 74"
              fill="none"
              stroke="rgba(255,255,255,0.22)"
              strokeWidth="1.1"
            />

            {/* Depth zone horizontal sonar grid lines */}
            {DEPTH_MARKERS.map((m) => (
              <g key={m.label}>
                <line
                  x1="28"
                  y1={m.y}
                  x2="932"
                  y2={m.y}
                  stroke="rgba(255,255,255,0.08)"
                  strokeDasharray="4 8"
                />
                <text
                  x="32"
                  y={m.y - 10}
                  fill="#949494"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="10"
                  letterSpacing="1.6"
                >
                  {m.label}
                </text>
              </g>
            ))}

            {/* Subtle underwater currents & bioluminescent specks */}
            {[
              [140, 220],
              [810, 310],
              [180, 560],
              [790, 690],
              [120, 880],
              [840, 1080],
              [160, 1260],
              [800, 1430],
              [210, 1640],
              [770, 1760],
            ].map(([bx, by], idx) => (
              <circle
                key={idx}
                cx={bx}
                cy={by}
                r={idx % 2 === 0 ? 2 : 1.3}
                fill={idx % 3 === 0 ? '#a3ff12' : 'rgba(255,255,255,0.35)'}
              />
            ))}

            {/* Continuous glowing sonar dive cable */}
            <path
              d={cablePath}
              fill="none"
              stroke="rgba(163, 255, 18, 0.16)"
              strokeWidth="7"
              strokeLinecap="round"
            />
            <path
              d={cablePath}
              fill="none"
              stroke="url(#cable-glow)"
              strokeWidth="2"
              strokeLinecap="round"
            />

            {/* Clickable Project Beacon Nodes */}
            {OCEAN_PROJECTS.map((project) => {
              const isSelected = project.id === selected.id;
              const cardX = project.align === 'right' ? project.cx + 34 : project.cx - 274;
              const cardY = project.cy - 34;

              return (
                <g
                  key={project.id}
                  className={`ocean-node ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => setSelectedId(project.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSelectedId(project.id);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`${project.name} at ${project.depthM} meters — ${project.tag}`}
                  aria-pressed={isSelected}
                >
                  {/* Sonar pulse ring */}
                  <circle
                    cx={project.cx}
                    cy={project.cy}
                    r={isSelected ? 22 : 14}
                    fill={isSelected ? 'rgba(163,255,18,0.16)' : 'rgba(255,255,255,0.05)'}
                    stroke={isSelected ? '#a3ff12' : 'rgba(255,255,255,0.28)'}
                    strokeWidth={isSelected ? 1.5 : 1}
                  />
                  <circle
                    cx={project.cx}
                    cy={project.cy}
                    r={isSelected ? 7.5 : 5.5}
                    fill={isSelected || project.current ? '#a3ff12' : '#ffffff'}
                  />

                  {/* Horizontal connector line to clickable label card */}
                  <line
                    x1={project.align === 'right' ? project.cx + 14 : project.cx - 14}
                    y1={project.cy}
                    x2={project.align === 'right' ? cardX : cardX + 240}
                    y2={project.cy}
                    stroke={isSelected ? '#a3ff12' : 'rgba(255,255,255,0.25)'}
                    strokeWidth="1"
                  />

                  {/* Clickable SVG Project Capsule */}
                  <rect
                    x={cardX}
                    y={cardY}
                    width="240"
                    height="68"
                    rx="6"
                    fill={isSelected ? '#0f130d' : '#080808'}
                    stroke={isSelected ? '#a3ff12' : 'rgba(255,255,255,0.18)'}
                    strokeWidth={isSelected ? 1.5 : 1}
                  />
                  <text
                    x={cardX + 14}
                    y={cardY + 22}
                    fill={isSelected ? '#a3ff12' : '#949494'}
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="9.5"
                    letterSpacing="1"
                  >
                    {project.depthM}m · {project.tag.toUpperCase()}
                  </text>
                  <text
                    x={cardX + 14}
                    y={cardY + 48}
                    fill="#ffffff"
                    fontFamily="Space Grotesk, sans-serif"
                    fontSize="16"
                    fontWeight="500"
                  >
                    {project.name}
                  </text>
                </g>
              );
            })}

            {/* Ocean floor trench silhouette */}
            <path
              d="M 0 1815 Q 240 1775 480 1808 T 960 1796 L 960 1850 L 0 1850 Z"
              fill="#050505"
              stroke="rgba(163,255,18,0.25)"
              strokeWidth="1"
            />
          </svg>
        </div>

        {/* Sticky Sonar Inspector Card */}
        <aside className="dive-inspector" aria-label="Selected OSIEN project details">
          <div className="dive-inspector-head">
            <span className="dive-zone-badge">
              <i className="status-dot" aria-hidden="true" />
              {selected.depthM}m · {selected.zone}
            </span>
            <span className="dive-online">ONLINE</span>
          </div>

          <h2>{selected.name}</h2>
          <p className="dive-tag">{selected.tag}</p>
          <p className="dive-summary">{selected.summary}</p>

          <div className="dive-actions">
            {selected.liveUrl && (
              <a
                className="button button-primary"
                href={selected.liveUrl}
                target="_blank"
                rel="noreferrer"
              >
                Open Live <ExternalLink size={14} aria-hidden="true" />
              </a>
            )}
            <a
              className="docs-back-btn dive-repo-btn"
              href={selected.repoUrl}
              target="_blank"
              rel="noreferrer"
            >
              <Github size={14} aria-hidden="true" />
              GitHub Repo <ArrowUpRight size={13} aria-hidden="true" />
            </a>
          </div>

          <div className="dive-quick-list" role="group" aria-label="All working OSIEN projects">
            <span className="dive-list-label">
              <Compass size={12} aria-hidden="true" /> JUMP TO DEPTH
            </span>
            {OCEAN_PROJECTS.map((p) => (
              <button
                key={p.id}
                type="button"
                aria-pressed={p.id === selected.id}
                className={`dive-list-item ${p.id === selected.id ? 'is-active' : ''}`}
                onClick={() => setSelectedId(p.id)}
              >
                <span>{p.name}</span>
                <small>{p.depthM}m</small>
              </button>
            ))}
          </div>
        </aside>
      </div>
    </motion.div>
  );
}
