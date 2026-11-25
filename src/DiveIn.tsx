import { useState } from 'react'
import { ExternalLink, Globe2, Waves } from 'lucide-react'

type OceanProject = {
  id: string
  name: string
  depth: string
  zone: string
  tagline: string
  language: string
  repoUrl: string
  liveUrl: string | null
  x: number
  y: number
  accent: string
}

const OSIEN_PROJECTS: OceanProject[] = [
  {
    id: 'osien',
    name: 'OSIEN',
    depth: '50m',
    zone: 'SUNLIT SURFACE',
    tagline: 'The parent ecosystem & studio behind every OSIEN product.',
    language: 'JavaScript',
    repoUrl: 'https://github.com/kabirprokk/OSIEN',
    liveUrl: 'https://osien.is-a.dev',
    x: 270,
    y: 250,
    accent: '#9bf5ef',
  },
  {
    id: 'osien-memories',
    name: 'OSIEN Memories',
    depth: '180m',
    zone: 'SUNLIT REEF',
    tagline: 'Private, local-first Windows iPhone media importer and organizer.',
    language: 'JavaScript',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Memories',
    liveUrl: null,
    x: 690,
    y: 510,
    accent: '#67e5de',
  },
  {
    id: 'osien-probe',
    name: 'OSIEN Probe',
    depth: '650m',
    zone: 'TWILIGHT ZONE',
    tagline: 'Fast static analysis & security scanner built for testing your projects.',
    language: 'JavaScript',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Probe',
    liveUrl: 'https://osienprobe.vercel.app',
    x: 290,
    y: 820,
    accent: '#56c2ff',
  },
  {
    id: 'osien-stack',
    name: 'Osien Stack',
    depth: '1,800m',
    zone: 'MIDNIGHT ZONE',
    tagline: 'Portable AI tooling stack: 45 MCP tools, skills, commands & agents.',
    language: 'MDX',
    repoUrl: 'https://github.com/kabirprokk/Osien-Stack',
    liveUrl: 'https://osienstack.vercel.app',
    x: 690,
    y: 1140,
    accent: '#8f9bff',
  },
  {
    id: 'osien-forge',
    name: 'OSIEN Forge',
    depth: '4,200m',
    zone: 'ABYSSAL TRENCH',
    tagline: 'Free AI superpowers — games, websites, brand kits & self-healing tools.',
    language: 'JavaScript',
    repoUrl: 'https://github.com/kabirprokk/OSIEN-Forge',
    liveUrl: null,
    x: 490,
    y: 1470,
    accent: '#b48bff',
  },
]

const BUBBLES = [
  { cx: 140, cy: 190, r: 4, o: 0.45 },
  { cx: 830, cy: 230, r: 6, o: 0.35 },
  { cx: 470, cy: 360, r: 3, o: 0.4 },
  { cx: 180, cy: 610, r: 5, o: 0.3 },
  { cx: 860, cy: 700, r: 4, o: 0.3 },
  { cx: 530, cy: 960, r: 3.5, o: 0.35 },
  { cx: 160, cy: 1210, r: 5, o: 0.25 },
  { cx: 820, cy: 1320, r: 4, o: 0.28 },
  { cx: 340, cy: 1560, r: 3, o: 0.3 },
  { cx: 700, cy: 1590, r: 4.5, o: 0.25 },
]

const DEPTH_MARKERS = [
  { y: 150, label: '0m · SURFACE' },
  { y: 420, label: '200m · EPIPELAGIC' },
  { y: 740, label: '650m · TWILIGHT' },
  { y: 1080, label: '1,800m · MIDNIGHT' },
  { y: 1420, label: '4,200m · ABYSSAL' },
]

function openLink(url: string | null) {
  if (!url) return
  window.open(url, '_blank', 'noopener,noreferrer')
}

export function DiveIn() {
  const [active, setActive] = useState<OceanProject>(OSIEN_PROJECTS[0])

  function handleSelect(project: OceanProject) {
    setActive(project)
    openLink(project.liveUrl || project.repoUrl)
  }

  return (
    <section className="dive-shell" aria-label="Dive in to OSIEN Ocean">
      <div className="dive-topbar">
        <div className="dive-badge">
          <Waves size={15} />
          <span>{OSIEN_PROJECTS.length} active OSIEN projects · Scroll to dive deeper</span>
        </div>
      </div>

      <div className="ocean-viewport">
        <svg
          className="ocean-svg"
          viewBox="0 0 1000 1680"
          role="img"
          aria-label="Interactive OSIEN Ocean map of projects"
        >
          <defs>
            <linearGradient id="probeOceanDepth" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#123a52" />
              <stop offset="18%" stopColor="#0e2a40" />
              <stop offset="45%" stopColor="#091c30" />
              <stop offset="75%" stopColor="#061121" />
              <stop offset="100%" stopColor="#030712" />
            </linearGradient>
            <linearGradient id="probeSunRay" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#9bf5ef" stopOpacity="0.22" />
              <stop offset="100%" stopColor="#9bf5ef" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="probeTrenchPath" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#9bf5ef" stopOpacity="0.7" />
              <stop offset="50%" stopColor="#56c2ff" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#b48bff" stopOpacity="0.8" />
            </linearGradient>
            <filter id="probeBeaconGlow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="8" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <rect x="0" y="0" width="1000" height="1680" fill="url(#probeOceanDepth)" rx="18" />

          <polygon points="120,0 260,0 380,460 190,460" fill="url(#probeSunRay)" />
          <polygon points="460,0 640,0 790,520 530,520" fill="url(#probeSunRay)" />
          <polygon points="780,0 910,0 990,420 820,420" fill="url(#probeSunRay)" />

          <path d="M0,78 Q125,42 250,76 T500,76 T750,76 T1000,74 L1000,0 L0,0 Z" fill="#9bf5ef" fillOpacity="0.14" />
          <path d="M0,98 Q140,68 280,96 T560,96 T840,94 T1000,98 L1000,0 L0,0 Z" fill="#67e5de" fillOpacity="0.09" />

          {DEPTH_MARKERS.map((marker) => (
            <g key={marker.label}>
              <line x1="36" y1={marker.y} x2="964" y2={marker.y} stroke="#cdedf8" strokeOpacity="0.08" strokeDasharray="4 8" />
              <text x="44" y={marker.y - 10} fill="#738393" fontSize="11" fontWeight="700" letterSpacing="1.6">
                {marker.label}
              </text>
            </g>
          ))}

          <path
            d="M270,250 C360,360 610,390 690,510 C760,640 360,690 290,820 C220,960 620,1010 690,1140 C750,1270 540,1340 490,1470"
            fill="none"
            stroke="url(#probeTrenchPath)"
            strokeWidth="3"
            strokeDasharray="8 8"
          />

          {BUBBLES.map((b, idx) => (
            <circle key={idx} cx={b.cx} cy={b.cy} r={b.r} fill="#9bf5ef" fillOpacity={b.o} />
          ))}

          <path d="M0,1625 Q180,1575 360,1615 T740,1600 T1000,1620 L1000,1680 L0,1680 Z" fill="#02050d" fillOpacity="0.9" />

          {OSIEN_PROJECTS.map((project) => {
            const isSelected = active.id === project.id
            const cardX = project.x > 520 ? project.x - 350 : project.x + 38
            const cardY = project.y - 54
            return (
              <g
                key={project.id}
                className={`ocean-node ${isSelected ? 'active' : ''}`}
                role="button"
                tabIndex={0}
                aria-label={`Open ${project.name} (${project.depth})`}
                onClick={() => handleSelect(project)}
                onMouseEnter={() => setActive(project)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    handleSelect(project)
                  }
                }}
              >
                <circle cx={project.x} cy={project.y} r={isSelected ? 30 : 22} fill={project.accent} fillOpacity={isSelected ? 0.24 : 0.14} filter="url(#probeBeaconGlow)" />
                <circle cx={project.x} cy={project.y} r="11" fill="#0b1421" stroke={project.accent} strokeWidth="3" />
                <circle cx={project.x} cy={project.y} r="4.5" fill={project.accent} />

                <rect
                  x={cardX}
                  y={cardY}
                  width="312"
                  height="108"
                  rx="16"
                  fill="#0d1b2c"
                  fillOpacity="0.9"
                  stroke={project.accent}
                  strokeOpacity={isSelected ? 0.88 : 0.35}
                  strokeWidth={isSelected ? 2 : 1.2}
                />
                <text x={cardX + 18} y={cardY + 26} fill={project.accent} fontSize="10" fontWeight="700" letterSpacing="1.4">
                  {project.depth} · {project.zone}
                </text>
                <text x={cardX + 18} y={cardY + 51} fill="#f1f6fa" fontSize="17" fontWeight="700">
                  {project.name}
                </text>
                <text x={cardX + 18} y={cardY + 73} fill="#a5b3c0" fontSize="11.5">
                  {project.tagline.length > 46 ? `${project.tagline.slice(0, 46)}…` : project.tagline}
                </text>
                <text x={cardX + 18} y={cardY + 94} fill="#738393" fontSize="10.5" fontWeight="600">
                  {project.language} · Click to open ↗
                </text>
              </g>
            )
          })}
        </svg>
      </div>

      <footer className="dive-hud">
        <div className="dive-hud-copy">
          <span className="dive-kicker">{active.depth} · {active.zone}</span>
          <strong>{active.name}</strong>
          <p>{active.tagline}</p>
        </div>
        <div className="dive-hud-actions">
          {active.liveUrl && (
            <button type="button" className="btn" onClick={() => openLink(active.liveUrl)}>
              <Globe2 size={14} /> Live site
            </button>
          )}
          <button type="button" className="btn primary" onClick={() => openLink(active.repoUrl)}>
            <ExternalLink size={14} /> Open on GitHub
          </button>
        </div>
      </footer>
    </section>
  )
}
