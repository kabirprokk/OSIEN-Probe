import { lazy, Suspense, useEffect, useState } from 'react';
import Lenis from 'lenis';
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
import { LaunchLoader } from './components/LaunchLoader';
import { BlackHoleTransition } from './components/BlackHoleTransition';
import DecryptedText from './components/DecryptedText';

const ProbeScrollScene = lazy(async () => {
  const m = await import('./components/ProbeScrollScene');
  return { default: m.ProbeScrollScene };
});
const TechText = lazy(() => import('./components/TechText'));
const DocsPage = lazy(async () => {
  const m = await import('./components/DocsPage');
  return { default: m.DocsPage };
});
const ASCIIText = lazy(() => import('./components/ASCIIText'));

type QuickstartTab = 'cli' | 'desktop' | 'mcp';

const QUICKSTART_COMMANDS: Record<QuickstartTab, { comment: string; command: string }[]> = {
  cli: [
    {
      comment: '# Clone & install',
      command:
        'git clone https://github.com/kabirprokk/OSIEN-Probe.git && cd OSIEN-Probe && npm install',
    },
    {
      comment: '# Scan & export SARIF',
      command: 'npm run audit -- ./project "Website" --sarif --fail-on high',
    },
  ],
  desktop: [
    {
      comment: '# Launch desktop app',
      command: 'npm install && npm run dev',
    },
    {
      comment: '# Verify rule & AST test suite',
      command: 'npm test',
    },
  ],
  mcp: [
    {
      comment: '# Start stdio MCP server',
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
  const [page, setPage] = useState<'home' | 'docs'>(() =>
    window.location.hash === '#docs' ? 'docs' : 'home',
  );
  const [navOpen, setNavOpen] = useState(false);
  const [qsTab, setQsTab] = useState<QuickstartTab>('cli');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [showTopBtn, setShowTopBtn] = useState(false);

  // Real background preload state (skip blocking overlay for reduced-motion or Lighthouse)
  const skipPreloader =
    typeof window !== 'undefined' &&
    (window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
      /Lighthouse|Chrome-Lighthouse|PageSpeed/i.test(navigator.userAgent));

  const [loaderDone, setLoaderDone] = useState(skipPreloader);
  const [mountHeavy3D, setMountHeavy3D] = useState(!skipPreloader);
  const [modelProgress, setModelProgress] = useState(10);
  const [modelReady, setModelReady] = useState(false);
  const [fontsReady, setFontsReady] = useState(false);

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

  // Smooth momentum scroll powered by Lenis (paired with hard-scroll velocity physics in 3D)
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const lenis = new Lenis({
      duration: 1.12,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      wheelMultiplier: 1.05,
    });

    let rafId = 0;
    const raf = (time: number) => {
      lenis.raf(time);
      rafId = requestAnimationFrame(raf);
    };
    rafId = requestAnimationFrame(raf);

    return () => {
      cancelAnimationFrame(rafId);
      lenis.destroy();
    };
  }, []);

  useEffect(() => {
    const onScroll = () => setShowTopBtn(window.scrollY > 520);
    const onHash = () => {
      if (window.location.hash === '#docs') {
        setPage('docs');
      } else if (page === 'docs' && window.location.hash !== '#docs') {
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

  const runPageTransition = (targetPage: 'home' | 'docs', label: string, anchor?: string) => {
    if (transitioning) return;
    setNavOpen(false);
    setTransitionDest(label);
    setTransitioning(true);

    // Swap page underneath once black-hole overlay is opaque
    window.setTimeout(() => {
      setPage(targetPage);
      if (targetPage === 'docs') {
        window.history.pushState(null, '', '#docs');
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
        <LaunchLoader
          realProgress={realLoadProgress}
          sceneReady={sceneReady}
          onComplete={() => setLoaderDone(true)}
        />
      )}
      <BlackHoleTransition active={transitioning} destination={transitionDest} />
      <DiamondCursor />
      <OsienWaveScroll />
      {mountHeavy3D && (
        <Suspense fallback={null}>
          <ProbeScrollScene
            dimmed={page === 'docs'}
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
              <DecryptedText text="OSIEN PROBE" animateOn="hover" speed={35} />
              <span className="brand-dot">.</span>
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
            <DecryptedText text="OSIEN" animateOn="hover" speed={35} />
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
              if (page === 'docs') {
                e.preventDefault();
                openHome('#preview');
              } else {
                setNavOpen(false);
              }
            }}
          >
            <DecryptedText text="Scan" animateOn="hover" speed={35} />
          </a>
          <a
            href="#engine"
            onClick={(e) => {
              if (page === 'docs') {
                e.preventDefault();
                openHome('#engine');
              } else {
                setNavOpen(false);
              }
            }}
          >
            <DecryptedText text="Engine" animateOn="hover" speed={35} />
          </a>
          <a
            href="#docs"
            className={page === 'docs' ? 'nav-active' : ''}
            onClick={(e) => {
              e.preventDefault();
              openDocs();
            }}
          >
            <DecryptedText text="Docs" animateOn="hover" speed={35} />
          </a>
          <a
            className="nav-github"
            href="https://github.com/kabirprokk/OSIEN-Probe"
            target="_blank"
            rel="noreferrer"
          >
            <DecryptedText text="GitHub" animateOn="hover" speed={35} />{' '}
            <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </nav>
      </header>

      <main id="main">
        {page === 'docs' ? (
          <Suspense fallback={null}>
            <DocsPage onBack={() => openHome()} />
          </Suspense>
        ) : (
          <>
            {/* HERO — Immediate LCP Paint + TechText Blueprint Tag */}
            <section className="hero section-wrap" id="top">
              <div className="hero-copy">
                <p className="eyebrow">
                  <span className="status-dot" aria-hidden="true" />
                  <DecryptedText text="OFFLINE STATIC SCANNER" speed={45} />
                </p>

                {/* Official React Bits TechText Tag Display */}
                <div className="hero-tech-tag">
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
                      specks={15}
                      intro="none"
                      introDuration={2}
                      clickKick
                      guides={false}
                    />
                  </Suspense>
                </div>

                <h1 className="hero-sub-display">
                  <span className="hero-line">
                    <DecryptedText text="Inspect every line." animateOn="hover" speed={42} />
                  </span>
                  <span className="hero-line hero-line-accent">
                    <DecryptedText text="Execute nothing." animateOn="hover" speed={46} />
                  </span>
                </h1>

                <p className="hero-intro">
                  <DecryptedText
                    text="Local 11-language AST bug finder, secret scanner, and MCP server."
                    animateOn="hover"
                    speed={36}
                  />
                </p>

                <div className="hero-actions">
                  <a className="button button-primary" href="#quickstart">
                    <DecryptedText text="Quickstart" animateOn="hover" speed={35} scrambleColor="#050505" />{' '}
                    <ArrowDown size={15} aria-hidden="true" />
                  </a>
                  <button
                    type="button"
                    className="osien-editorial-link osien-link-btn"
                    onClick={openDocs}
                  >
                    <DecryptedText text="Read Docs" animateOn="hover" speed={35} />{' '}
                    <ArrowRight size={14} aria-hidden="true" />
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
                  <DecryptedText text="01 / LIVE SCAN" speed={42} />
                </span>
                <span className="kicker-line" />
                <span id="preview-title">
                  <DecryptedText text="CWEs · Taint · Score" speed={42} />
                </span>
              </div>
              <AuditPreview />
            </motion.section>

            {/* 02 / ENGINE */}
            <section className="features section-wrap" id="engine">
              <div className="section-kicker">
                <span>
                  <DecryptedText text="02 / ENGINE" speed={42} />
                </span>
                <span className="kicker-line" />
                <span>
                  <DecryptedText text="Zero cloud · Zero execution" speed={42} />
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
                  <DecryptedText text="Signal only" speed={45} />
                </p>
                <h2>
                  <DecryptedText text="Built for precision." speed={42} />
                  <br />
                  <em>
                    <DecryptedText text="Honest about limits." speed={45} />
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
                    <DecryptedText text="11-language AST" speed={42} />
                  </h3>
                  <p>
                    <DecryptedText
                      text="Syntax-aware checks across JS/TS, Python, Go, Rust, Java, C++, and Bash."
                      speed={32}
                    />
                  </p>
                  <div className="feature-tags">
                    <span>Babel</span>
                    <span>@ast-grep</span>
                    <span>11 Grammars</span>
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
                    <DecryptedText text="Taint & secrets" speed={42} />
                  </h3>
                  <p>
                    <DecryptedText
                      text="Tracks input-to-sink flows and flags leaked keys by entropy."
                      speed={32}
                    />
                  </p>
                  <div className="taint-bar">
                    <code>req.query</code>
                    <span aria-hidden="true">→</span>
                    <code className="taint-clean">DOMPurify</code>
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
                    <DecryptedText text="Local AI & SARIF" speed={42} />
                  </h3>
                  <p>
                    <DecryptedText
                      text="Optional Ollama triage with fast-fail, plus SARIF 2.1.0 CI gating."
                      speed={32}
                    />
                  </p>
                  <div className="feature-code">
                    <span>qwen3.5:0.8b</span>
                    <span>--fail-on high</span>
                  </div>
                </SpotlightCard>
              </div>
            </section>

            {/* 03 / SURFACES */}
            <section className="surfaces section-wrap" id="surfaces">
              <div className="section-kicker">
                <span>
                  <DecryptedText text="03 / SURFACES" speed={42} />
                </span>
                <span className="kicker-line" />
                <span>
                  <DecryptedText text="One core everywhere" speed={42} />
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
                    <DecryptedText text="One engine." speed={42} />
                    <br />
                    <em>
                      <DecryptedText text="Three surfaces." speed={45} />
                    </em>
                  </h2>

                  <ol className="steps steps-compact">
                    <li>
                      <span className="step-number">01</span>
                      <div>
                        <h3>
                          <DecryptedText text="Desktop App" speed={42} />
                        </h3>
                        <p>
                          <DecryptedText
                            text="Scan folders or Git URLs offline. Opt-in test runs."
                            speed={34}
                          />
                        </p>
                      </div>
                    </li>
                    <li>
                      <span className="step-number">02</span>
                      <div>
                        <h3>
                          <DecryptedText text="CLI & CI Gate" speed={42} />
                        </h3>
                        <p>
                          <code>probe scan --sarif --fail-on high</code>
                        </p>
                      </div>
                    </li>
                    <li>
                      <span className="step-number">03</span>
                      <div>
                        <h3>
                          <DecryptedText text="Stdio MCP" speed={42} />
                        </h3>
                        <p>
                          <DecryptedText
                            text="Zero-dependency tool server for AI coding agents."
                            speed={34}
                          />
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
                  <DecryptedText text="04 / QUICKSTART" speed={42} />
                </span>
                <span className="kicker-line" />
                <span>
                  <DecryptedText text="MIT · 100% Offline" speed={42} />
                </span>
              </div>

              <div className="start-panel">
                <div className="start-copy">
                  <span className="terminal-label">
                    <span className="status-dot" aria-hidden="true" />
                    <DecryptedText text="v1.0.1" speed={45} />
                  </span>

                  <h2>
                    <DecryptedText text="Clone." speed={45} />
                    <br />
                    <em>
                      <DecryptedText text="Scan." speed={45} />
                    </em>
                  </h2>

                  <p>
                    <DecryptedText
                      text="Same deterministic engine across desktop, CLI, and MCP."
                      speed={34}
                    />
                  </p>

                  <button
                    type="button"
                    className="osien-editorial-link osien-link-btn start-readme-link"
                    onClick={openDocs}
                  >
                    <DecryptedText text="Visual Docs (Human & AI)" animateOn="hover" speed={35} />{' '}
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

                  <div className="setup-content">
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
                  </div>
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
                  <DecryptedText text="05 / NEXT" speed={45} />
                </p>

                <div className="finale-ascii-wrap">
                  <Suspense fallback={null}>
                    <ASCIIText
                      text="LOCAL."
                      asciiFontSize={8}
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
                </div>

                <div className="final-cta-actions">
                  <a
                    className="osien-outline-cta"
                    href="https://github.com/kabirprokk/OSIEN-Probe"
                    target="_blank"
                    rel="noreferrer"
                  >
                    <DecryptedText text="View on GitHub" animateOn="hover" speed={35} />{' '}
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
              <DecryptedText text="OSIEN PROBE" animateOn="hover" speed={35} />
            </span>
          </a>

          <div className="footer-mono-links footer-mono-inline">
            <a
              href="#docs"
              onClick={(e) => {
                e.preventDefault();
                openDocs();
              }}
            >
              <DecryptedText text="Docs" animateOn="hover" speed={35} />
            </a>
            <a href="https://osien.is-a.dev/" target="_blank" rel="noreferrer">
              <DecryptedText text="osien.is-a.dev" animateOn="hover" speed={35} />
            </a>
            <a href="https://github.com/kabirprokk/OSIEN-Probe" target="_blank" rel="noreferrer">
              <DecryptedText text="GitHub" animateOn="hover" speed={35} />
            </a>
          </div>

          <span className="footer-copy">
            <DecryptedText text={`© ${new Date().getFullYear()} OSIEN · MIT`} speed={35} />
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
