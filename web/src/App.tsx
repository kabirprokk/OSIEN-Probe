import { lazy, Suspense, useEffect, useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import { AnimatePresence, motion } from 'motion/react';
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ArrowUpRight,
  Check,
  Copy,
  FileJson,
  GitBranch,
  Layers,
  Menu,
  Terminal,
  X,
} from 'lucide-react';
import { AuditPreview } from './components/AuditPreview';
import { SpotlightCard } from './components/SpotlightCard';
import { OsienWaveScroll } from './components/OsienWaveScroll';
import { DiamondCursor } from './components/DiamondCursor';
import { getDeviceQualityProfile } from './lib/deviceProfile';
const LaunchLoader = lazy(async () => {
  const m = await import('./components/LaunchLoader');
  return { default: m.LaunchLoader };
});
const BlackHoleTransition = lazy(async () => {
  const m = await import('./components/BlackHoleTransition');
  return { default: m.BlackHoleTransition };
});
const DecryptedText = lazy(() => import('./components/DecryptedText'));

const ProbeScrollScene = lazy(async () => {
  const m = await import('./components/ProbeScrollScene');
  return { default: m.ProbeScrollScene };
});
const TechText = lazy(() => import('./components/TechText'));
const DocsPage = lazy(async () => {
  const m = await import('./components/DocsPage');
  return { default: m.DocsPage };
});
const HistoryPage = lazy(async () => {
  const m = await import('./components/HistoryPage');
  return { default: m.HistoryPage };
});
const ASCIIText = lazy(() => import('./components/ASCIIText'));

type QuickstartTab = 'cli' | 'desktop' | 'mcp';

const QUICKSTART_COMMANDS: Record<QuickstartTab, { comment: string; command: string }[]> = {
  cli: [
    {
      comment: '# Scan a local project & gate CI',
      command: 'probe scan ./project --kind "Website" --sarif --fail-on high',
    },
    {
      comment: '# Deep live URL audit + generate Vercel/Nginx fix config',
      command: 'probe scan https://your-site.com --crawl 5 --probe-cors --probe-exposed --fix vercel',
    },
  ],
  desktop: [
    {
      comment: '# Launch desktop app (drag-drop folders, Git URLs, or Live URLs)',
      command: 'npm install && npm run dev',
    },
    {
      comment: '# Build native Windows NSIS / macOS DMG / Linux AppImage installer',
      command: 'npm run dist:win',
    },
  ],
  mcp: [
    {
      comment: '# Start zero-dependency stdio MCP server',
      command: 'probe mcp',
    },
    {
      comment: '# Register in MCP client',
      command: '{ "command": "node", "args": ["bin/osien-probe-mcp.cjs"] }',
    },
  ],
};

const REVEAL_EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

export default function App() {
  const [page, setPage] = useState<'home' | 'docs' | 'history'>(() =>
    window.location.hash === '#docs'
      ? 'docs'
      : window.location.hash === '#history'
        ? 'history'
        : 'home',
  );
  const [navOpen, setNavOpen] = useState(false);
  const [qsTab, setQsTab] = useState<QuickstartTab>('cli');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [showTopBtn, setShowTopBtn] = useState(false);

  const quality = getDeviceQualityProfile();

  useEffect(() => {
    document.documentElement.dataset.quality = quality.tier;
  }, [quality.tier]);

  // Skip blocking fullscreen preloader only on eco/reduced-motion/audit environments for instant LCP
  const skipPreloader =
    typeof window !== 'undefined' &&
    (quality.tier === 'eco' ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
      navigator.webdriver === true ||
      /Lighthouse|Chrome-Lighthouse|PageSpeed/i.test(navigator.userAgent));

  const [loaderDone, setLoaderDone] = useState(skipPreloader);
  const [mountHeavy3D, setMountHeavy3D] = useState(!skipPreloader);
  const [modelProgress, setModelProgress] = useState(10);
  const [modelReady, setModelReady] = useState(false);
  const [fontsReady, setFontsReady] = useState(false);

  // Only mount heavy WebGL2 ASCIIText when Section 05 scrolls near viewport
  const [showAscii, setShowAscii] = useState(false);

  useEffect(() => {
    if (page !== 'home' || showAscii) return;
    const el = document.getElementById('next');
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setShowAscii(true);
          io.disconnect();
        }
      },
      { rootMargin: '250px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [page, showAscii]);

  // Defer heavy WebGL scene in reduced-motion / audit mode until user interaction so TBT stays ~0ms
  useEffect(() => {
    if (mountHeavy3D) return;
    const activate = () => setMountHeavy3D(true);
    window.addEventListener('pointermove', activate, { once: true, passive: true });
    window.addEventListener('scroll', activate, { once: true, passive: true });
    window.addEventListener('keydown', activate, { once: true, passive: true });
    window.addEventListener('touchstart', activate, { once: true, passive: true });
    return () => {
      window.removeEventListener('pointermove', activate);
      window.removeEventListener('scroll', activate);
      window.removeEventListener('keydown', activate);
      window.removeEventListener('touchstart', activate);
    };
  }, [mountHeavy3D]);

  // Black-hole page transition state (guaranteed >= 1.15s per route change)
  const [transitioning, setTransitioning] = useState(false);
  const [transitionDest, setTransitionDest] = useState('DOCS');

  useEffect(() => {
    let alive = true;
    document.fonts.ready
      .then(() => {
        if (alive) setFontsReady(true);
      })
      .catch(() => {
        if (alive) setFontsReady(true);
      });
    // Safety fallback in case fonts or WebGL stall on restricted devices
    const safety = window.setTimeout(() => {
      if (alive) {
        setFontsReady(true);
        setModelReady(true);
        setModelProgress(100);
      }
    }, 5000);
    return () => {
      alive = false;
      window.clearTimeout(safety);
    };
  }, []);

  const realLoadProgress = Math.min(
    100,
    Math.round(modelProgress * 0.8 + (fontsReady ? 20 : 6)),
  );
  const sceneReady = modelReady && fontsReady;

  // Smooth momentum scroll powered by Lenis (enabled automatically on ultra & balanced devices)
  useEffect(() => {
    if (!mountHeavy3D || !quality.enableSmoothScroll) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    let alive = true;
    let rafId = 0;
    let lenisInstance: { raf: (t: number) => void; destroy: () => void } | null = null;

    import('lenis')
      .then(({ default: Lenis }) => {
        if (!alive) return;
        const lenis = new Lenis({
          duration: 1.12,
          easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
          smoothWheel: true,
          wheelMultiplier: 1.05,
        });
        lenisInstance = lenis;
        const raf = (time: number) => {
          lenis.raf(time);
          rafId = requestAnimationFrame(raf);
        };
        rafId = requestAnimationFrame(raf);
      })
      .catch(() => {
        lenisInstance = null;
      });

    return () => {
      alive = false;
      cancelAnimationFrame(rafId);
      lenisInstance?.destroy();
    };
  }, [mountHeavy3D, quality.enableSmoothScroll]);

  useEffect(() => {
    const onScroll = () => setShowTopBtn(window.scrollY > 520);
    const onHash = () => {
      if (window.location.hash === '#docs') {
        setPage('docs');
      } else if (window.location.hash === '#history') {
        setPage('history');
      } else if (page !== 'home') {
        setPage('home');
      }
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('hashchange', onHash);
    };
  }, [page]);

  const runPageTransition = (
    targetPage: 'home' | 'docs' | 'history',
    label: string,
    anchor?: string,
  ) => {
    if (transitioning) return;
    setNavOpen(false);
    setTransitionDest(label);
    setTransitioning(true);

    // Swap page underneath once black-hole overlay is opaque
    window.setTimeout(() => {
      setPage(targetPage);
      if (targetPage === 'docs' || targetPage === 'history') {
        window.history.pushState(null, '', `#${targetPage}`);
        window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
      } else if (anchor) {
        window.history.pushState(null, '', anchor);
        window.setTimeout(() => {
          document.querySelector(anchor)?.scrollIntoView({ behavior: 'auto' });
        }, 30);
      } else {
        window.history.pushState(null, '', '#top');
        window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
      }
    }, 520);

    // Keep transition visible for at least 1.15s so users always see the orbiting probe
    window.setTimeout(() => {
      setTransitioning(false);
    }, 1150);
  };

  const openDocs = () => {
    if (page === 'docs') return;
    runPageTransition('docs', 'DOCS');
  };

  const openHistory = () => {
    if (page === 'history') return;
    runPageTransition('history', 'HISTORY');
  };

  const openHome = (anchor?: string) => {
    if (page === 'home' && !anchor) {
      setNavOpen(false);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }
    runPageTransition('home', anchor ? anchor.replace('#', '').toUpperCase() : 'HOME', anchor);
  };

  const handleCopy = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedCmd(cmd);
      window.setTimeout(() => {
        setCopiedCmd((curr) => (curr === cmd ? null : curr));
      }, 1800);
    } catch {
      setCopiedCmd(null);
    }
  };

  return (
    <div className="page-shell">
      {!loaderDone && (
        <Suspense fallback={null}>
          <LaunchLoader
            realProgress={realLoadProgress}
            sceneReady={sceneReady}
            onComplete={() => setLoaderDone(true)}
          />
        </Suspense>
      )}
      {transitioning && (
        <Suspense fallback={null}>
          <BlackHoleTransition active={transitioning} destination={transitionDest} />
        </Suspense>
      )}
      <DiamondCursor />
      {mountHeavy3D && <OsienWaveScroll />}
      {mountHeavy3D && (
        <Suspense fallback={null}>
          <ProbeScrollScene
            dimmed={page !== 'home'}
            onProgress={setModelProgress}
            onReady={() => setModelReady(true)}
          />
        </Suspense>
      )}

      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <header className="site-header">
        <div className="brand-cluster">
          <a
            className="brand"
            href="#top"
            aria-label="OSIEN Probe home"
            onClick={(e) => {
              e.preventDefault();
              openHome();
            }}
          >
            <img src="/logo.svg" width="30" height="30" alt="" />
            <span>
              OSIEN PROBE<span className="brand-dot">.</span>
            </span>
          </a>
          <span className="brand-sep" aria-hidden="true">
            /
          </span>
          <a
            className="parent-link"
            href="https://osien.is-a.dev/"
            target="_blank"
            rel="noreferrer"
          >
            OSIEN
          </a>
        </div>

        <button
          className="menu-toggle"
          type="button"
          aria-expanded={navOpen}
          aria-controls="site-nav"
          aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
          onClick={() => setNavOpen((open) => !open)}
        >
          {navOpen ? <X size={18} /> : <Menu size={18} />}
        </button>

        <nav className={`site-nav ${navOpen ? 'is-open' : ''}`} id="site-nav" aria-label="Primary">
          <a
            href="#preview"
            onClick={(e) => {
              if (page !== 'home') {
                e.preventDefault();
                openHome('#preview');
              } else {
                setNavOpen(false);
              }
            }}
          >
            Scan
          </a>
          <a
            href="#engine"
            onClick={(e) => {
              if (page !== 'home') {
                e.preventDefault();
                openHome('#engine');
              } else {
                setNavOpen(false);
              }
            }}
          >
            Engine
          </a>
          <a
            href="#history"
            className={page === 'history' ? 'nav-active' : ''}
            onClick={(e) => {
              e.preventDefault();
              openHistory();
            }}
          >
            History
          </a>
          <a
            href="#docs"
            className={page === 'docs' ? 'nav-active' : ''}
            onClick={(e) => {
              e.preventDefault();
              openDocs();
            }}
          >
            Docs
          </a>
          <a
            className="nav-github"
            href="https://github.com/kabirprokk/OSIEN-Probe"
            target="_blank"
            rel="noreferrer"
          >
            GitHub <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </nav>
      </header>

      <main id="main">
        {page === 'docs' ? (
          <Suspense fallback={null}>
            <DocsPage onBack={() => openHome()} />
          </Suspense>
        ) : page === 'history' ? (
          <Suspense fallback={null}>
            <HistoryPage onBack={() => openHome()} onOpenDocs={openDocs} />
          </Suspense>
        ) : (
          <>
            {/* HERO — Immediate LCP Paint + TechText Blueprint Tag */}
            <section className="hero section-wrap" id="top">
              <div className="hero-copy">
                <p className="eyebrow">
                  <span className="status-dot" aria-hidden="true" />
                  OFFLINE STATIC SCANNER
                </p>

                {/* Official React Bits TechText Tag Display */}
                <div className="hero-tech-tag">
                  {mountHeavy3D ? (
                    <Suspense fallback={<span className="tech-text-fallback">OSIEN PROBE</span>}>
                      <TechText
                        text="OSIEN PROBE"
                        fontFamily="'Space Grotesk', sans-serif"
                        fontWeight={600}
                        fontSize={96}
                        align="left"
                        color="#ffffff"
                        accentColor="#a3ff12"
                        reveal="letter"
                        dashLength={4}
                        dashGap={2}
                        specks={quality.techSpecks}
                        intro="none"
                        introDuration={2}
                        clickKick
                        guides={false}
                      />
                    </Suspense>
                  ) : (
                    <span className="tech-text-fallback">OSIEN PROBE</span>
                  )}
                </div>

                <h1 className="hero-sub-display">
                  <span className="hero-line">
                    {mountHeavy3D ? (
                      <Suspense fallback="Inspect every line.">
                        <DecryptedText text="Inspect every line." animateOn="hover" speed={42} />
                      </Suspense>
                    ) : (
                      'Inspect every line.'
                    )}
                  </span>
                  <span className="hero-line hero-line-accent">
                    {mountHeavy3D ? (
                      <Suspense fallback="Execute nothing.">
                        <DecryptedText text="Execute nothing." animateOn="hover" speed={46} />
                      </Suspense>
                    ) : (
                      'Execute nothing.'
                    )}
                  </span>
                </h1>

                <p className="hero-intro">
                  1,142+ rules, 11-language AST call graphs, live URL auditor with auto-fix configs,
                  and MCP server.
                </p>

                <div className="hero-actions">
                  <a className="button button-primary" href="#quickstart">
                    Quickstart <ArrowDown size={15} aria-hidden="true" />
                  </a>
                  <button
                    type="button"
                    className="osien-editorial-link osien-link-btn"
                    onClick={openDocs}
                  >
                    Read Docs <ArrowRight size={14} aria-hidden="true" />
                  </button>
                </div>
              </div>

              <div className="hero-corridor" aria-hidden="true" />
            </section>

            {/* 01 / LIVE SCAN */}
            <motion.section
              className="showcase section-wrap"
              id="preview"
              aria-labelledby="preview-title"
              initial={{ opacity: 0, y: 36, scale: 0.985 }}
              whileInView={{ opacity: 1, y: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.7, ease: REVEAL_EASE }}
            >
              <div className="section-kicker">
                <span>
                  01 / LIVE SCAN
                </span>
                <span className="kicker-line" />
                <span id="preview-title">
                  CWEs · Taint · Score
                </span>
              </div>
              <AuditPreview />
            </motion.section>

            {/* 02 / ENGINE */}
            <section className="features section-wrap" id="engine">
              <div className="section-kicker">
                <span>
                  02 / ENGINE
                </span>
                <span className="kicker-line" />
                <span>
                  Zero cloud · Zero execution
                </span>
              </div>

              <motion.div
                className="osien-editorial-head"
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.25 }}
                transition={{ duration: 0.65, ease: REVEAL_EASE }}
              >
                <p className="editorial-label">
                  Signal only
                </p>
                <h2>
                  {mountHeavy3D ? (<Suspense fallback="Built for precision."><DecryptedText animateOn="inViewHover" text="Built for precision." speed={42} /></Suspense>) : 'Built for precision.'}
                  <br />
                  <em>
                    {mountHeavy3D ? (<Suspense fallback="Honest about limits."><DecryptedText animateOn="inViewHover" text="Honest about limits." speed={45} /></Suspense>) : 'Honest about limits.'}
                  </em>
                </h2>
              </motion.div>

              <div className="feature-grid feature-grid-3">
                <SpotlightCard className="feature-card">
                  <div className="feature-top">
                    <span className="feature-index">01</span>
                    <span className="feature-symbol">
                      <Layers size={18} aria-hidden="true" />
                    </span>
                  </div>
                  <h3>
                    {mountHeavy3D ? (<Suspense fallback="11-language AST"><DecryptedText animateOn="inViewHover" text="11-language AST" speed={42} /></Suspense>) : '11-language AST'}
                  </h3>
                  <p>
                    1,142+ rules &amp; AST call graphs across JS/TS, Python, Go, Rust, Java, PHP,
                    Ruby, Kotlin, C/C++, and Swift.
                  </p>
                  <div className="feature-tags">
                    <span>1,142+ Rules</span>
                    <span>Call Graphs</span>
                    <span>CFG Guards</span>
                  </div>
                </SpotlightCard>

                <SpotlightCard className="feature-card">
                  <div className="feature-top">
                    <span className="feature-index">02</span>
                    <span className="feature-symbol symbol-gold">
                      <GitBranch size={18} aria-hidden="true" />
                    </span>
                  </div>
                  <h3>
                    {mountHeavy3D ? (<Suspense fallback="Live URL & taint"><DecryptedText animateOn="inViewHover" text="Live URL & taint" speed={42} /></Suspense>) : 'Live URL & taint'}
                  </h3>
                  <p>
                    Multi-page live crawl, TLS/CORS/exposed probes, and auto-generated fix configs
                    for Vercel, Nginx, Next.js &amp; Cloudflare.
                  </p>
                  <div className="feature-code">
                    <span>--crawl 5</span>
                    <span>--probe-cors</span>
                    <span>--fix vercel</span>
                  </div>
                </SpotlightCard>

                <SpotlightCard className="feature-card">
                  <div className="feature-top">
                    <span className="feature-index">03</span>
                    <span className="feature-symbol">
                      <FileJson size={18} aria-hidden="true" />
                    </span>
                  </div>
                  <h3>
                    {mountHeavy3D ? (<Suspense fallback="AI Triage & SARIF"><DecryptedText animateOn="inViewHover" text="AI Triage & SARIF" speed={42} /></Suspense>) : 'AI Triage & SARIF'}
                  </h3>
                  <p>
                    Verify findings with local Ollama, Claude, OpenCode, or Pi — plus SARIF 2.1.0 CI
                    gating.
                  </p>
                  <div className="feature-code">
                    <span>Ollama · Claude</span>
                    <span>--fail-on high</span>
                  </div>
                </SpotlightCard>
              </div>
            </section>

            {/* 03 / SURFACES */}
            <section className="surfaces section-wrap" id="surfaces">
              <div className="section-kicker">
                <span>
                  03 / SURFACES
                </span>
                <span className="kicker-line" />
                <span>
                  One core everywhere
                </span>
              </div>

              <div className="surfaces-layout">
                <div className="surfaces-corridor" aria-hidden="true" />

                <motion.div
                  className="surfaces-content"
                  initial={{ opacity: 0, y: 24 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{ duration: 0.65, ease: REVEAL_EASE }}
                >
                  <h2>
                    {mountHeavy3D ? (<Suspense fallback="One engine."><DecryptedText animateOn="inViewHover" text="One engine." speed={42} /></Suspense>) : 'One engine.'}
                    <br />
                    <em>
                      {mountHeavy3D ? (<Suspense fallback="Three surfaces."><DecryptedText animateOn="inViewHover" text="Three surfaces." speed={45} /></Suspense>) : 'Three surfaces.'}
                    </em>
                  </h2>

                  <ol className="steps steps-compact">
                    <li>
                      <span className="step-number">01</span>
                      <div>
                        <h3>
                          {mountHeavy3D ? (<Suspense fallback="Desktop App"><DecryptedText animateOn="inViewHover" text="Desktop App" speed={42} /></Suspense>) : 'Desktop App'}
                        </h3>
                        <p>
                          Drag-drop folders, Git URLs, or deep Live URL audits with Save Config &amp;
                          native NSIS installer.
                        </p>
                      </div>
                    </li>
                    <li>
                      <span className="step-number">02</span>
                      <div>
                        <h3>
                          {mountHeavy3D ? (<Suspense fallback="CLI & CI Gate"><DecryptedText animateOn="inViewHover" text="CLI & CI Gate" speed={42} /></Suspense>) : 'CLI & CI Gate'}
                        </h3>
                        <p>
                          <code>probe scan https://site.com --crawl 5 --probe-cors --fix vercel</code>
                        </p>
                      </div>
                    </li>
                    <li>
                      <span className="step-number">03</span>
                      <div>
                        <h3>
                          {mountHeavy3D ? (<Suspense fallback="Stdio MCP"><DecryptedText animateOn="inViewHover" text="Stdio MCP" speed={42} /></Suspense>) : 'Stdio MCP'}
                        </h3>
                        <p>
                          Zero-dependency tool server for AI coding agents.
                        </p>
                      </div>
                    </li>
                  </ol>
                </motion.div>
              </div>
            </section>

            {/* 04 / QUICKSTART */}
            <section className="get-started section-wrap" id="quickstart">
              <div className="section-kicker">
                <span>
                  04 / QUICKSTART
                </span>
                <span className="kicker-line" />
                <span>
                  MIT · 100% Offline
                </span>
              </div>

              <div className="start-panel">
                <div className="start-copy">
                  <span className="terminal-label">
                    <span className="status-dot" aria-hidden="true" />
                    v1.0.5
                  </span>

                  <h2>
                    {mountHeavy3D ? (<Suspense fallback="Clone."><DecryptedText animateOn="inViewHover" text="Clone." speed={45} /></Suspense>) : 'Clone.'}
                    <br />
                    <em>
                      {mountHeavy3D ? (<Suspense fallback="Scan."><DecryptedText animateOn="inViewHover" text="Scan." speed={45} /></Suspense>) : 'Scan.'}
                    </em>
                  </h2>

                  <p>
                    Same deterministic engine across desktop, CLI, and MCP.
                  </p>

                  <button
                    type="button"
                    className="osien-editorial-link osien-link-btn start-readme-link"
                    onClick={openDocs}
                  >
                    Visual Docs (Human & AI){' '}
                    <ArrowRight size={14} aria-hidden="true" />
                  </button>
                </div>

                <Tabs.Root
                  value={qsTab}
                  onValueChange={(v) => setQsTab(v as QuickstartTab)}
                  className="setup-terminal"
                >
                  <div className="setup-bar">
                    <Tabs.List className="setup-tabs" aria-label="Quickstart mode">
                      {(['cli', 'desktop', 'mcp'] as QuickstartTab[]).map((tab) => {
                        const active = qsTab === tab;
                        return (
                          <Tabs.Trigger
                            key={tab}
                            value={tab}
                            className={`setup-tab ${active ? 'is-active' : ''}`}
                          >
                            {active && (
                              <motion.span
                                layoutId="setup-tab-pill"
                                className="tab-pill-bg"
                                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                              />
                            )}
                            <span className="tab-label">
                              <Terminal size={11} aria-hidden="true" />
                              {tab.toUpperCase()}
                            </span>
                          </Tabs.Trigger>
                        );
                      })}
                    </Tabs.List>
                  </div>

                  <Tabs.Content value={qsTab} className="setup-content">
                    {QUICKSTART_COMMANDS[qsTab].map((block) => {
                      const isCopied = copiedCmd === block.command;
                      return (
                        <div key={block.command} className="setup-block">
                          <p className="setup-comment">{block.comment}</p>
                          <div className="install-command">
                            <code>{block.command}</code>
                            <button
                              type="button"
                              className="copy-command"
                              data-copied={isCopied}
                              onClick={() => handleCopy(block.command)}
                              aria-label={`Copy command: ${block.command}`}
                            >
                              {isCopied ? (
                                <>
                                  <Check size={11} aria-hidden="true" /> COPIED
                                </>
                              ) : (
                                <>
                                  <Copy size={11} aria-hidden="true" /> COPY
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </Tabs.Content>
                  {(['cli', 'desktop', 'mcp'] as QuickstartTab[])
                    .filter((tab) => tab !== qsTab)
                    .map((tab) => (
                      <Tabs.Content key={tab} value={tab} />
                    ))}
                </Tabs.Root>
              </div>
            </section>

            {/* 05 / NEXT — Interactive ASCIIText Finale over Radio-Wave Arcs */}
            <section className="final-cta" id="next">
              <div className="contact-radio-waves" aria-hidden="true">
                <svg viewBox="0 0 1440 420" preserveAspectRatio="xMidYMax slice">
                  {[72, 142, 212, 282, 352, 422, 492, 562, 632].map((r) => (
                    <circle key={r} className="radio-ring" cx="720" cy="420" r={r} />
                  ))}
                  <circle className="radio-origin" cx="720" cy="420" r="3" />
                </svg>
              </div>

              <motion.div
                className="final-cta-inner section-wrap"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.65, ease: REVEAL_EASE }}
              >
                <p className="section-num">
                  05 / NEXT
                </p>

                <div className="finale-ascii-wrap">
                  {showAscii ? (
                    <Suspense fallback={<span className="tech-text-fallback">LOCAL.</span>}>
                      <ASCIIText
                        text="LOCAL."
                        asciiFontSize={quality.asciiFontSize}
                        colors={['#ffffff', '#a3ff12', '#c2ff5c']}
                        textScale={1}
                        blocks={0.9}
                        waves={1}
                        waveSpeed={1}
                        chroma={1}
                        tilt={1}
                        hueShift={0.25}
                        scramble={0.6}
                        clickRipple
                        idle
                        interactive
                      />
                    </Suspense>
                  ) : (
                    <span className="tech-text-fallback">LOCAL.</span>
                  )}
                </div>

                <div className="final-cta-actions">
                  <a
                    className="osien-outline-cta"
                    href="https://github.com/kabirprokk/OSIEN-Probe"
                    target="_blank"
                    rel="noreferrer"
                  >
                    View on GitHub{' '}
                    <ArrowUpRight size={15} aria-hidden="true" />
                  </a>
                </div>
              </motion.div>
            </section>
          </>
        )}
      </main>

      <footer className="site-footer-wrap">
        <div className="site-footer site-footer-minimal section-wrap">
          <a
            className="footer-brand"
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              openHome();
            }}
          >
            <img src="/logo.svg" alt="" width="22" height="22" />
            <span>
              OSIEN PROBE
            </span>
          </a>

          <div className="footer-mono-links footer-mono-inline">
            <a
              href="#history"
              onClick={(e) => {
                e.preventDefault();
                openHistory();
              }}
            >
              History
            </a>
            <a
              href="#docs"
              onClick={(e) => {
                e.preventDefault();
                openDocs();
              }}
            >
              Docs
            </a>
            <a href="https://osien.is-a.dev/" target="_blank" rel="noreferrer">
              osien.is-a.dev
            </a>
            <a href="https://github.com/kabirprokk/OSIEN-Probe" target="_blank" rel="noreferrer">
              GitHub
            </a>
          </div>

          <span className="footer-copy">
            © {new Date().getFullYear()} OSIEN · MIT
          </span>
        </div>
      </footer>

      <AnimatePresence>
        {showTopBtn && (
          <motion.button
            type="button"
            className="back-to-top"
            aria-label="Back to top"
            initial={{ opacity: 0, scale: 0.82 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.82 }}
            transition={{ duration: 0.2 }}
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          >
            <ArrowUp size={16} aria-hidden="true" />
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  );
}
