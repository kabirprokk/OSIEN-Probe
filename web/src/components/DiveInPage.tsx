import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  ArrowDown,
  ArrowLeft,
  ArrowUpRight,
  Compass,
  ExternalLink,
  Github,
  Layers,
  Radio,
  Sparkles,
  X,
} from 'lucide-react';
import DecryptedText from './DecryptedText';

interface DiveInPageProps {
  onBack: () => void;
  onOpenDocs: () => void;
}

export interface OceanProject {
  id: string;
  name: string;
  tagline: string;
  description: string;
  depthMeters: number;
  zone: 'SURFACE' | 'SUNLIGHT' | 'TWILIGHT' | 'MIDNIGHT' | 'ABYSSAL' | 'HADAL';
  statusLabel: string;
  language: string;
  release?: string;
  liveUrl?: string;
  githubUrl: string;
  accent: string;
  /** Position inside the 1120x3400 SVG coordinate space */
  cx: number;
  cy: number;
  side: 'left' | 'right';
}

const OCEAN_HEIGHT = 3760;
const OCEAN_WIDTH = 1120;

const WORKING_OSIEN_PROJECTS: OceanProject[] = [
  {
    id: 'osien-hub',
    name: 'OSIEN',
    tagline: 'Parent hub & ecosystem flagship',
    description:
      'The parent organization and central launchpad uniting all OSIEN AI developer tools, desktop apps, web platforms, and browser extensions under one roof.',
    depthMeters: 0,
    zone: 'SURFACE',
    statusLabel: 'LIVE WEB',
    language: 'JavaScript',
    liveUrl: 'https://osien.is-a.dev',
    githubUrl: 'https://github.com/kabirprokk/OSIEN',
    accent: '#38bdf8',
    cx: 560,
    cy: 230,
    side: 'right',
  },
  {
    id: 'osien-probe',
    name: 'OSIEN Probe',
    tagline: 'Offline AST scanner, 100+ NPC swarm & Mirage Vision AI',
    description:
      'Desktop app, CLI, and zero-dependency MCP server for static security analysis, 100+ NPC stress swarms, Cactus Mirage 22MB Vision AI, and live URL auditing.',
    depthMeters: 140,
    zone: 'SUNLIGHT',
    statusLabel: 'LIVE · v1.0.6',
    language: 'JavaScript / Electron',
    release: 'v1.0.6',
    liveUrl: 'https://osienprobe.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/OSIEN-Probe',
    accent: '#22d3ee',
    cx: 340,
    cy: 560,
    side: 'right',
  },
  {
    id: 'osien-stack',
    name: 'Osien-Stack',
    tagline: 'Portable AI toolchain: 45 MCP tools, skills & agents',
    description:
      'The AI tooling that installs itself — 45 MCP tools, skills, commands, agents, and a runner compatible with OpenCode, Claude Code, Cursor, Cline, and Windsurf.',
    depthMeters: 420,
    zone: 'SUNLIGHT',
    statusLabel: 'LIVE WEB',
    language: 'MDX / TypeScript',
    liveUrl: 'https://osienstack.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/Osien-Stack',
    accent: '#2dd4bf',
    cx: 775,
    cy: 900,
    side: 'left',
  },
  {
    id: 'osien-memories',
    name: 'OSIEN Memories',
    tagline: 'Local-first Windows iPhone media importer & organizer',
    description:
      'Clean-room Windows desktop app that scans accessible iPhone photos and videos, reads embedded capture dates, previews media, and organizes files by date and type.',
    depthMeters: 860,
    zone: 'TWILIGHT',
    statusLabel: 'RELEASE · v0.0.3',
    language: 'JavaScript / Electron',
    release: 'v0.0.3',
    githubUrl: 'https://github.com/kabirprokk/OSIEN-Memories',
    accent: '#60a5fa',
    cx: 330,
    cy: 1270,
    side: 'right',
  },
  {
    id: 'osien-forge',
    name: 'OSIEN Forge',
    tagline: 'Open-source AI superpowers for devs & creators',
    description:
      'Build games, websites, brand kits, invoices, sprites, music, and self-healing tools mostly offline using free OpenCode models — ships with Full, Creator & Everyday bundles.',
    depthMeters: 1340,
    zone: 'MIDNIGHT',
    statusLabel: 'RELEASE · full-v1.0',
    language: 'JavaScript / Shell',
    release: 'full-v1.0',
    githubUrl: 'https://github.com/kabirprokk/OSIEN-Forge',
    accent: '#818cf8',
    cx: 785,
    cy: 1660,
    side: 'left',
  },
  {
    id: 'ocm-marketplace',
    name: 'OCM Marketplace',
    tagline: 'Community skills, agents & commands for OpenCode',
    description:
      'Full OpenCode Marketplace ecosystem: live web catalog, community registry schema, and global CLI for browsing and installing free skills, agents, and commands.',
    depthMeters: 1920,
    zone: 'MIDNIGHT',
    statusLabel: 'LIVE WEB',
    language: 'TypeScript / Next.js',
    liveUrl: 'https://ocmskills.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/opencode-marketplace-web',
    accent: '#a78bfa',
    cx: 345,
    cy: 2050,
    side: 'right',
  },
  {
    id: 'osin-cli',
    name: 'OSIN CLI',
    tagline: 'Windows-first keyboard & mouse AI coding CLI',
    description:
      'Opens a project workspace, plans tasks, inspects code, edits files, runs tests or shell commands, and previews clean diffs inside a fast monochrome terminal interface.',
    depthMeters: 2550,
    zone: 'ABYSSAL',
    statusLabel: 'LIVE · CLI',
    language: 'JavaScript / Node.js',
    liveUrl: 'https://osin.pages.dev',
    githubUrl: 'https://github.com/kabirprokk/OSIN',
    accent: '#34d399',
    cx: 770,
    cy: 2440,
    side: 'left',
  },
  {
    id: 'gramiqo',
    name: 'Gramiqo',
    tagline: 'Mobile Instagram features brought to PC web',
    description:
      'Browser extension and web companion that unlocks mobile-grade Instagram controls and workflows directly inside your desktop browser.',
    depthMeters: 3280,
    zone: 'ABYSSAL',
    statusLabel: 'LIVE · OLIN-1-1-a',
    language: 'JavaScript / Extension',
    release: 'OLIN-1-1-a',
    liveUrl: 'https://gramiqo.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/Gramiqo',
    accent: '#f472b6',
    cx: 350,
    cy: 2820,
    side: 'right',
  },
  {
    id: 'keepthestyle-v1',
    name: 'KeepTheStyle v1',
    tagline: 'No-code visual website builder',
    description:
      'Browser-based visual website builder for crafting layouts, styling components, and exporting clean web pages without writing boilerplate by hand.',
    depthMeters: 3980,
    zone: 'HADAL',
    statusLabel: 'LIVE WEB',
    language: 'JavaScript',
    liveUrl: 'https://keepthestyle-v1.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/keepthestyle_v1',
    accent: '#fbbf24',
    cx: 765,
    cy: 3180,
    side: 'left',
  },
  {
    id: 'record-commons',
    name: 'Record Commons',
    tagline: 'Community video archive & review platform',
    description:
      'Open community video archive built for structured video submissions, curation, and collaborative review at the floor of the OSIEN ecosystem.',
    depthMeters: 4720,
    zone: 'HADAL',
    statusLabel: 'LIVE WEB',
    language: 'TypeScript / Next.js',
    liveUrl: 'https://reccommons.vercel.app',
    githubUrl: 'https://github.com/kabirprokk/Record-Common',
    accent: '#22d3ee',
    cx: 560,
    cy: 3545,
    side: 'right',
  },
];

const DEPTH_ZONES = [
  { id: 'surface', label: 'SUNLIGHT', meters: '0m – 400m', y: 120, minDepth: 0 },
  { id: 'twilight', label: 'TWILIGHT', meters: '400m – 1,000m', y: 1080, minDepth: 400 },
  { id: 'midnight', label: 'MIDNIGHT', meters: '1,000m – 2,200m', y: 1520, minDepth: 1000 },
  { id: 'abyssal', label: 'ABYSSAL', meters: '2,200m – 3,500m', y: 2260, minDepth: 2200 },
  { id: 'hadal', label: 'HADAL TRENCH', meters: '3,500m – 4,800m', y: 2740, minDepth: 3500 },
] as const;

const BUBBLES = [
  { cx: 140, cy: 420, r: 4, delay: '0s' },
  { cx: 210, cy: 760, r: 3, delay: '1.2s' },
  { cx: 920, cy: 640, r: 5, delay: '0.6s' },
  { cx: 880, cy: 1120, r: 3.5, delay: '2.1s' },
  { cx: 175, cy: 1480, r: 4.5, delay: '0.9s' },
  { cx: 955, cy: 1840, r: 3, delay: '1.7s' },
  { cx: 220, cy: 2250, r: 4, delay: '0.3s' },
  { cx: 890, cy: 2630, r: 3.5, delay: '2.5s' },
  { cx: 510, cy: 3010, r: 4, delay: '1.1s' },
  { cx: 615, cy: 3100, r: 3, delay: '1.9s' },
];

const BIOLUM_SPORES = [
  { cx: 165, cy: 1710, r: 2.2, color: '#38bdf8' },
  { cx: 945, cy: 1930, r: 2.6, color: '#a78bfa' },
  { cx: 245, cy: 2340, r: 2.0, color: '#34d399' },
  { cx: 865, cy: 2580, r: 2.5, color: '#22d3ee' },
  { cx: 190, cy: 2940, r: 2.8, color: '#f472b6' },
  { cx: 910, cy: 3040, r: 2.3, color: '#38bdf8' },
  { cx: 470, cy: 2680, r: 1.9, color: '#2dd4bf' },
  { cx: 670, cy: 2190, r: 2.1, color: '#818cf8' },
];

function buildTetherPath(projects: OceanProject[]): string {
  if (projects.length === 0) return '';
  let d = `M ${projects[0].cx} ${projects[0].cy}`;
  for (let i = 1; i < projects.length; i++) {
    const prev = projects[i - 1];
    const curr = projects[i];
    const midY = (prev.cy + curr.cy) / 2;
    d += ` C ${prev.cx} ${midY}, ${curr.cx} ${midY}, ${curr.cx} ${curr.cy}`;
  }
  return d;
}

export function DiveInPage({ onBack, onOpenDocs }: DiveInPageProps) {
  const oceanRef = useRef<HTMLDivElement | null>(null);
  const [selected, setSelected] = useState<OceanProject | null>(WORKING_OSIEN_PROJECTS[1]);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [depthRatio, setDepthRatio] = useState(0);

  const tetherPath = useMemo(() => buildTetherPath(WORKING_OSIEN_PROJECTS), []);

  useEffect(() => {
    const updateDepth = () => {
      const el = oceanRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const totalScrollable = Math.max(1, rect.height - window.innerHeight * 0.55);
      const passed = Math.max(0, -rect.top + window.innerHeight * 0.25);
      const ratio = Math.min(1, Math.max(0, passed / totalScrollable));
      setDepthRatio(ratio);
    };
    updateDepth();
    window.addEventListener('scroll', updateDepth, { passive: true });
    window.addEventListener('resize', updateDepth, { passive: true });
    return () => {
      window.removeEventListener('scroll', updateDepth);
      window.removeEventListener('resize', updateDepth);
    };
  }, []);

  const currentMeters = Math.round(depthRatio * 4800);
  const currentAtm = (1 + currentMeters / 10).toFixed(0);
  const currentZone =
    currentMeters >= 3500
      ? 'HADAL TRENCH'
      : currentMeters >= 2200
        ? 'ABYSSAL PLAIN'
        : currentMeters >= 1000
          ? 'MIDNIGHT ZONE'
          : currentMeters >= 400
            ? 'TWILIGHT ZONE'
            : 'SUNLIGHT ZONE';

  const scrollToSvgY = (svgY: number) => {
    const el = oceanRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const docTop = window.scrollY + rect.top;
    const targetY = docTop + (svgY / OCEAN_HEIGHT) * rect.height - window.innerHeight * 0.36;
    window.scrollTo({ top: Math.max(0, targetY), behavior: 'smooth' });
  };

  const handleSelectProject = (project: OceanProject) => {
    setSelected(project);
    scrollToSvgY(project.cy);
  };

  const selectedIndex = selected
    ? WORKING_OSIEN_PROJECTS.findIndex((p) => p.id === selected.id)
    : -1;
  const nextProject =
    selectedIndex >= 0 && selectedIndex < WORKING_OSIEN_PROJECTS.length - 1
      ? WORKING_OSIEN_PROJECTS[selectedIndex + 1]
      : null;

  const probeY = 230 + depthRatio * (3545 - 230);

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
            GITHUB PROFILE
            <ArrowUpRight size={13} aria-hidden="true" />
          </a>
        </div>
      </div>

      {/* Hero Intro */}
      <header className="docs-hero dive-hero">
        <p className="eyebrow">
          <Compass size={13} aria-hidden="true" />
          <DecryptedText
            text="OSIEN ECOSYSTEM · DEEP OCEAN MAP"
            animateOn="view"
            speed={38}
            maxIterations={8}
            sequential
          />
        </p>
        <h1 className="docs-title">
          Dive in<span className="brand-dot">.</span>
        </h1>
        <p className="docs-lead">
          Every working OSIEN project from{' '}
          <a
            href="https://github.com/kabirprokk"
            target="_blank"
            rel="noreferrer"
            className="dive-inline-link"
          >
            @kabirprokk
          </a>{' '}
          mapped across a living, clickable SVG ocean. Scroll deeper into the trench or click any
          sonar beacon to inspect and launch it.
        </p>

        <div className="dive-stats-strip">
          <div className="dive-stat-pill">
            <Radio size={13} aria-hidden="true" />
            <span>{WORKING_OSIEN_PROJECTS.length} VERIFIED WORKING PROJECTS</span>
          </div>
          <div className="dive-stat-pill">
            <Layers size={13} aria-hidden="true" />
            <span>5 OCEAN DEPTH ZONES · 0m → 4,800m</span>
          </div>
          <button
            type="button"
            className="dive-start-btn"
            onClick={() => scrollToSvgY(WORKING_OSIEN_PROJECTS[0].cy)}
          >
            BEGIN DESCENT
            <ArrowDown size={13} aria-hidden="true" />
          </button>
        </div>
      </header>

      {/* Sticky Live Depth HUD */}
      <aside className="dive-depth-hud" aria-label="Ocean depth telemetry">
        <div className="dive-hud-readout">
          <span className="dive-hud-zone">{currentZone}</span>
          <strong className="dive-hud-meters">{currentMeters.toLocaleString()} m</strong>
          <span className="dive-hud-atm">{currentAtm} ATM</span>
        </div>
        <div className="dive-hud-jumps">
          {DEPTH_ZONES.map((z) => (
            <button
              key={z.id}
              type="button"
              className={`dive-zone-chip ${currentZone.startsWith(z.label.split(' ')[0]) ? 'is-active' : ''}`}
              onClick={() => scrollToSvgY(z.y)}
            >
              {z.label}
            </button>
          ))}
        </div>
      </aside>

      {/* Clickable Continuous Deep SVG Ocean */}
      <div className="dive-ocean-frame" ref={oceanRef}>
        <svg
          className="dive-ocean-svg"
          viewBox={`0 0 ${OCEAN_WIDTH} ${OCEAN_HEIGHT}`}
          role="img"
          aria-label="Interactive OSIEN deep ocean map with 10 clickable working projects"
        >
          <defs>
            {/* Continuous deepening ocean gradient */}
            <linearGradient id="oceanDepthGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#0e4f70" />
              <stop offset="14%" stopColor="#093654" />
              <stop offset="32%" stopColor="#05213a" />
              <stop offset="56%" stopColor="#031226" />
              <stop offset="78%" stopColor="#020916" />
              <stop offset="100%" stopColor="#000308" />
            </linearGradient>

            {/* Sunbeam caustic gradient */}
            <linearGradient id="sunBeamGrad" x1="0.5" y1="0" x2="0.5" y2="1">
              <stop offset="0%" stopColor="#7dd3fc" stopOpacity="0.28" />
              <stop offset="55%" stopColor="#38bdf8" stopOpacity="0.08" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
            </linearGradient>

            {/* Glowing submarine cable gradient */}
            <linearGradient id="tetherGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="35%" stopColor="#2dd4bf" />
              <stop offset="68%" stopColor="#818cf8" />
              <stop offset="100%" stopColor="#22d3ee" />
            </linearGradient>

            {/* Trench rock silhouette gradient */}
            <linearGradient id="trenchWallGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#051e33" stopOpacity="0.45" />
              <stop offset="50%" stopColor="#020d1a" stopOpacity="0.82" />
              <stop offset="100%" stopColor="#000206" stopOpacity="0.98" />
            </linearGradient>

            {/* Hydrothermal vent glow */}
            <radialGradient id="ventGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
              <stop offset="55%" stopColor="#818cf8" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#000308" stopOpacity="0" />
            </radialGradient>

            <filter id="nodeGlow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Sky strip above waterline */}
          <rect x="0" y="0" width={OCEAN_WIDTH} height="130" fill="#051320" />

          {/* Main deep ocean water body */}
          <rect x="0" y="115" width={OCEAN_WIDTH} height={OCEAN_HEIGHT - 115} fill="url(#oceanDepthGrad)" />

          {/* Animated surface waves */}
          <path
            className="ocean-wave-back"
            d="M 0 116 Q 140 86 280 116 T 560 116 T 840 116 T 1120 116 L 1120 165 L 0 165 Z"
            fill="#0e4f70"
            opacity="0.65"
          />
          <path
            className="ocean-wave-front"
            d="M 0 124 Q 140 148 280 124 T 560 124 T 840 124 T 1120 124 L 1120 175 L 0 175 Z"
            fill="#126186"
            opacity="0.55"
          />
          <path
            d="M 0 124 Q 140 148 280 124 T 560 124 T 840 124 T 1120 124"
            fill="none"
            stroke="#7dd3fc"
            strokeWidth="1.5"
            opacity="0.65"
          />

          {/* Volumetric sunlight shafts in Epipelagic zone */}
          <polygon points="180,120 340,120 470,760 220,760" fill="url(#sunBeamGrad)" />
          <polygon points="480,120 650,120 790,820 520,820" fill="url(#sunBeamGrad)" />
          <polygon points="790,120 930,120 1030,690 830,690" fill="url(#sunBeamGrad)" />

          {/* Narrowing deep-sea canyon walls */}
          <path
            d="M 0 540 L 62 720 L 38 1040 L 95 1380 L 68 1760 L 135 2140 L 108 2520 L 185 2890 L 220 3320 L 340 3760 L 0 3760 Z"
            fill="url(#trenchWallGrad)"
          />
          <path
            d="M 1120 520 L 1055 740 L 1082 1080 L 1020 1420 L 1052 1790 L 985 2180 L 1012 2560 L 935 2920 L 900 3320 L 780 3760 L 1120 3760 Z"
            fill="url(#trenchWallGrad)"
          />

          {/* Horizontal depth zone sonar strata */}
          {DEPTH_ZONES.map((z) => (
            <g key={z.id} opacity="0.62">
              <line
                x1="44"
                y1={z.y}
                x2={OCEAN_WIDTH - 44}
                y2={z.y}
                stroke="#38bdf8"
                strokeOpacity="0.18"
                strokeDasharray="6 10"
              />
              <text
                x="56"
                y={z.y - 10}
                fill="#7dd3fc"
                fontSize="11"
                fontFamily="monospace"
                letterSpacing="2.4"
                opacity="0.72"
              >
                {z.label} · {z.meters}
              </text>
            </g>
          ))}

          {/* Rising bubbles */}
          {BUBBLES.map((b, i) => (
            <circle
              key={`bubble-${i}`}
              cx={b.cx}
              cy={b.cy}
              r={b.r}
              fill="none"
              stroke="#bae6fd"
              strokeOpacity="0.34"
              strokeWidth="1.2"
              className="ocean-bubble"
              style={{ animationDelay: b.delay }}
            />
          ))}

          {/* Subtle twilight jellyfish silhouettes */}
          <g opacity="0.22" transform="translate(880, 1210)">
            <path d="M 0 0 C 0 -22 36 -22 36 0 Z" fill="#60a5fa" />
            <path d="M 7 2 Q 4 22 10 38 M 18 2 Q 21 24 16 44 M 29 2 Q 33 22 26 38" stroke="#93c5fd" strokeWidth="1.3" fill="none" />
          </g>
          <g opacity="0.18" transform="translate(175, 1740) scale(0.85)">
            <path d="M 0 0 C 0 -22 36 -22 36 0 Z" fill="#a78bfa" />
            <path d="M 7 2 Q 4 22 10 38 M 18 2 Q 21 24 16 44 M 29 2 Q 33 22 26 38" stroke="#c4b5fd" strokeWidth="1.3" fill="none" />
          </g>

          {/* Deep-sea bioluminescent spores */}
          {BIOLUM_SPORES.map((s, i) => (
            <circle
              key={`spore-${i}`}
              cx={s.cx}
              cy={s.cy}
              r={s.r}
              fill={s.color}
              className="ocean-spore"
              style={{ animationDelay: `${(i % 4) * 0.7}s` }}
            />
          ))}

          {/* Ocean floor hydrothermal core glow */}
          <ellipse cx="560" cy="3640" rx="340" ry="120" fill="url(#ventGlow)" />
          <path
            d="M 240 3760 L 380 3675 L 475 3715 L 560 3655 L 650 3715 L 745 3670 L 890 3760 Z"
            fill="#020a15"
            stroke="#22d3ee"
            strokeOpacity="0.22"
          />

          {/* Continuous Submarine Fiber Tether connecting every working OSIEN project */}
          <path
            d={tetherPath}
            fill="none"
            stroke="url(#tetherGrad)"
            strokeWidth="3"
            strokeOpacity="0.25"
          />
          <path
            d={tetherPath}
            fill="none"
            stroke="url(#tetherGrad)"
            strokeWidth="2"
            strokeDasharray="10 12"
            className="ocean-tether-flow"
          />

          {/* Scroll-linked Submersible Probe Depth Indicator on the left guide rail */}
          <g transform={`translate(96, ${probeY})`} opacity="0.85">
            <line x1="-26" y1="0" x2="26" y2="0" stroke="#22d3ee" strokeWidth="1" strokeOpacity="0.45" />
            <circle cx="0" cy="0" r="7" fill="#031226" stroke="#22d3ee" strokeWidth="2" />
            <circle cx="0" cy="0" r="2.5" fill="#22d3ee" />
          </g>

          {/* 9 Clickable SVG OSIEN Project Nodes */}
          {WORKING_OSIEN_PROJECTS.map((project, idx) => {
            const isSelected = selected?.id === project.id;
            const isHovered = hoveredId === project.id;
            const active = isSelected || isHovered;
            const cardW = 330;
            const cardH = 114;
            const cardX =
              project.cx === 560
                ? project.cx - cardW / 2
                : project.side === 'right'
                  ? project.cx + 46
                  : project.cx - cardW - 46;
            const cardY =
              project.cx === 560
                ? project.cy + (idx === 0 ? 44 : -cardH - 44)
                : project.cy - cardH / 2;

            return (
              <g
                key={project.id}
                className={`ocean-project-node ${isSelected ? 'is-selected' : ''}`}
                role="button"
                tabIndex={0}
                aria-label={`${project.name} at ${project.depthMeters} meters depth — ${project.tagline}`}
                onClick={() => handleSelectProject(project)}
                onMouseEnter={() => setHoveredId(project.id)}
                onMouseLeave={() => setHoveredId((curr) => (curr === project.id ? null : curr))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleSelectProject(project);
                  }
                }}
              >
                {/* Connector arm between beacon and info card */}
                <line
                  x1={project.cx}
                  y1={project.cy}
                  x2={
                    project.cx === 560
                      ? project.cx
                      : project.side === 'right'
                        ? cardX
                        : cardX + cardW
                  }
                  y2={
                    project.cx === 560
                      ? idx === 0
                        ? cardY
                        : cardY + cardH
                      : project.cy
                  }
                  stroke={project.accent}
                  strokeWidth={active ? 2 : 1.2}
                  strokeOpacity={active ? 0.9 : 0.45}
                />

                {/* Pulsing sonar ring */}
                <circle
                  cx={project.cx}
                  cy={project.cy}
                  r={active ? 32 : 24}
                  fill="none"
                  stroke={project.accent}
                  strokeWidth="1.5"
                  strokeOpacity={active ? 0.65 : 0.28}
                  className="ocean-sonar-ring"
                />

                {/* Outer beacon housing */}
                <circle
                  cx={project.cx}
                  cy={project.cy}
                  r={active ? 18 : 15}
                  fill="#041528"
                  stroke={project.accent}
                  strokeWidth={active ? 2.8 : 2}
                  filter={active ? 'url(#nodeGlow)' : undefined}
                />

                {/* Inner core dot */}
                <circle
                  cx={project.cx}
                  cy={project.cy}
                  r={active ? 6.5 : 5}
                  fill={project.accent}
                />

                {/* Depth meter tag next to beacon */}
                <text
                  x={project.cx}
                  y={project.cy - 26}
                  textAnchor="middle"
                  fill={project.accent}
                  fontSize="11"
                  fontFamily="monospace"
                  fontWeight="600"
                  letterSpacing="1.2"
                >
                  {project.depthMeters}m
                </text>

                {/* Clickable SVG glass card */}
                <g>
                  <rect
                    x={cardX}
                    y={cardY}
                    width={cardW}
                    height={cardH}
                    rx="10"
                    fill={active ? 'rgba(6, 26, 48, 0.94)' : 'rgba(4, 17, 34, 0.84)'}
                    stroke={project.accent}
                    strokeWidth={active ? 1.8 : 1}
                    strokeOpacity={active ? 0.95 : 0.36}
                  />

                  {/* Status pill inside card */}
                  <rect
                    x={cardX + 16}
                    y={cardY + 14}
                    width="132"
                    height="20"
                    rx="4"
                    fill={project.accent}
                    fillOpacity="0.16"
                  />
                  <text
                    x={cardX + 24}
                    y={cardY + 28}
                    fill={project.accent}
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight="700"
                    letterSpacing="1"
                  >
                    {project.statusLabel}
                  </text>

                  {/* Node index */}
                  <text
                    x={cardX + cardW - 16}
                    y={cardY + 28}
                    textAnchor="end"
                    fill="#94a3b8"
                    fontSize="10"
                    fontFamily="monospace"
                    letterSpacing="1"
                  >
                    {String(idx + 1).padStart(2, '0')} · {project.zone}
                  </text>

                  {/* Project Title */}
                  <text
                    x={cardX + 16}
                    y={cardY + 58}
                    fill="#f8fafc"
                    fontSize="19"
                    fontWeight="600"
                    fontFamily="system-ui, -apple-system, sans-serif"
                  >
                    {project.name}
                  </text>

                  {/* Tagline */}
                  <text
                    x={cardX + 16}
                    y={cardY + 80}
                    fill="#cbd5e1"
                    fontSize="12"
                    fontFamily="system-ui, -apple-system, sans-serif"
                  >
                    {project.tagline.length > 44
                      ? `${project.tagline.slice(0, 44)}…`
                      : project.tagline}
                  </text>

                  {/* Click hint */}
                  <text
                    x={cardX + 16}
                    y={cardY + 100}
                    fill={project.accent}
                    fontSize="10"
                    fontFamily="monospace"
                    letterSpacing="1.2"
                  >
                    CLICK TO INSPECT &amp; LAUNCH ↗
                  </text>
                </g>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Floating Sonar Inspector Drawer when a project node is clicked */}
      <AnimatePresence>
        {selected && (
          <motion.aside
            key={selected.id}
            className="dive-inspector"
            initial={{ opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 24 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            aria-label={`Selected project ${selected.name}`}
            style={{ borderColor: selected.accent }}
          >
            <div className="dive-inspector-top">
              <div className="dive-inspector-meta">
                <span
                  className="dive-inspector-badge"
                  style={{ color: selected.accent, borderColor: selected.accent }}
                >
                  <Sparkles size={11} aria-hidden="true" />
                  {selected.statusLabel}
                </span>
                <span className="dive-inspector-depth">
                  DEPTH {selected.depthMeters.toLocaleString()}m · {selected.zone} ·{' '}
                  {selected.language}
                </span>
              </div>
              <button
                type="button"
                className="dive-inspector-close"
                aria-label="Close project inspector"
                onClick={() => setSelected(null)}
              >
                <X size={15} aria-hidden="true" />
              </button>
            </div>

            <div className="dive-inspector-body">
              <div>
                <h2 className="dive-inspector-title">{selected.name}</h2>
                <p className="dive-inspector-desc">{selected.description}</p>
              </div>

              <div className="dive-inspector-actions">
                {selected.liveUrl && (
                  <a
                    className="btn-primary dive-action-btn"
                    href={selected.liveUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <ExternalLink size={14} aria-hidden="true" />
                    LAUNCH LIVE
                  </a>
                )}
                <a
                  className="btn-secondary dive-action-btn"
                  href={selected.githubUrl}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Github size={14} aria-hidden="true" />
                  GITHUB REPO
                </a>
                {nextProject && (
                  <button
                    type="button"
                    className="docs-back-btn dive-action-btn"
                    onClick={() => handleSelectProject(nextProject)}
                  >
                    DIVE DEEPER: {nextProject.name.toUpperCase()}
                    <ArrowDown size={13} aria-hidden="true" />
                  </button>
                )}
              </div>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
