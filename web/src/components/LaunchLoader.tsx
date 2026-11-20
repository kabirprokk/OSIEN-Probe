import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';

interface LaunchLoaderProps {
  realProgress: number; // 0..100 from real GLB + Draco + WebGL shader warmup + fonts
  sceneReady: boolean;
  onComplete: () => void;
}

interface ThrusterParticle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  size: number;
  lime: boolean;
}

interface DiskParticle {
  angle: number;
  radius: number;
  speed: number;
  size: number;
  lime: boolean;
}

/**
 * Full-Bleed Cinematic Rocket-to-Black-Hole Preloader (Zero Cards / Zero Per-Frame React Re-renders)
 * Runs entirely on a 60fps canvas while the real 3D model, Draco WASM, shaders, and fonts finish loading.
 */
export function LaunchLoader({ realProgress, sceneReady, onComplete }: LaunchLoaderProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pctRef = useRef<HTMLSpanElement>(null);
  const statusRef = useRef<HTMLSpanElement>(null);
  const progressRef = useRef(realProgress);
  const readyRef = useRef(sceneReady);
  const onCompleteRef = useRef(onComplete);
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    progressRef.current = realProgress;
  }, [realProgress]);

  useEffect(() => {
    readyRef.current = sceneReady;
  }, [sceneReady]);

  useEffect(() => {
    onCompleteRef.current = onComplete;
  }, [onComplete]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = window.innerWidth;
    let height = window.innerHeight;
    let dpr = Math.min(window.devicePixelRatio || 1, 1.75);

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize, { passive: true });

    // Background stars
    const stars = Array.from({ length: 130 }, (_, i) => ({
      x: Math.random() * width,
      y: Math.random() * height,
      r: 0.6 + Math.random() * 1.3,
      a: 0.2 + Math.random() * 0.55,
      lime: i % 9 === 0,
    }));

    // Swirling accretion disk particles around the Black Hole
    const diskParticles: DiskParticle[] = Array.from({ length: 95 }, (_, i) => ({
      angle: Math.random() * Math.PI * 2,
      radius: 1.28 + Math.random() * 1.45,
      speed: 0.65 + Math.random() * 1.35,
      size: 1.0 + Math.random() * 1.8,
      lime: i % 3 !== 0,
    }));

    const trail: ThrusterParticle[] = [];
    let smoothPct = 0;
    let arrivedAt: number | null = null;
    let exitStarted = false;
    let rafId = 0;
    let lastTime = performance.now();

    const render = (now: number) => {
      rafId = requestAnimationFrame(render);
      const dt = Math.min(0.05, (now - lastTime) / 1000);
      lastTime = now;
      const tSec = now / 1000;

      // Advance smoothly toward real load progress
      const target = readyRef.current ? 100 : Math.min(93, Math.max(smoothPct, progressRef.current));
      smoothPct += (target - smoothPct) * (1 - Math.exp(-7 * dt));
      if (readyRef.current && 100 - smoothPct < 0.35) {
        smoothPct = 100;
      }

      if (smoothPct >= 99.8 && readyRef.current && arrivedAt === null) {
        arrivedAt = now;
      }

      const arrivalElapsed = arrivedAt !== null ? (now - arrivedAt) / 1000 : 0;
      if (arrivedAt !== null && arrivalElapsed >= 0.65 && !exitStarted) {
        exitStarted = true;
        setVisible(false);
        window.setTimeout(() => onCompleteRef.current(), 420);
      }

      // Direct DOM updates (zero React re-renders per frame!)
      const intPct = Math.round(smoothPct);
      if (pctRef.current) {
        pctRef.current.textContent = String(intPct).padStart(2, '0');
      }
      if (statusRef.current) {
        if (arrivedAt !== null) {
          statusRef.current.textContent = 'SINGULARITY REACHED · READY';
          statusRef.current.classList.add('is-reached');
        } else if (intPct < 45) {
          statusRef.current.textContent = 'LOADING 3D PARKER PROBE';
        } else if (intPct < 85) {
          statusRef.current.textContent = 'DECODING DRACO & SHADERS';
        } else {
          statusRef.current.textContent = 'ENTERING EVENT HORIZON';
        }
      }

      ctx.clearRect(0, 0, width, height);

      // Black Hole center & responsive scale
      const bhX = width < 720 ? width * 0.76 : width * 0.72;
      const bhY = height * 0.48;
      const bhR = Math.max(36, Math.min(68, Math.min(width, height) * 0.085));

      // 1. Subtle deep-space starfield with gentle gravitational pull
      for (const s of stars) {
        ctx.fillStyle = s.lime
          ? `rgba(163, 255, 18, ${s.a})`
          : `rgba(255, 255, 255, ${s.a})`;
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // 2. Curved hyperbolic flight trajectory (Left -> Black Hole Perimeter)
      const p0x = width * 0.12;
      const p0y = height * 0.62;
      const p1x = width * 0.42;
      const p1y = height * 0.22;
      const p2x = bhX - bhR * 1.48;
      const p2y = bhY - bhR * 0.16;

      // Dashed planned orbital path
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(p0x, p0y);
      ctx.quadraticCurveTo(p1x, p1y, p2x, p2y);
      ctx.setLineDash([4, 8]);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.11)';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.restore();

      // Active luminous trajectory progress curve
      const prog = Math.max(0, Math.min(1, smoothPct / 100));
      const omt = 1 - prog;
      const rx = omt * omt * p0x + 2 * omt * prog * p1x + prog * prog * p2x;
      const ry = omt * omt * p0y + 2 * omt * prog * p1y + prog * prog * p2y;
      const tx = 2 * omt * (p1x - p0x) + 2 * prog * (p2x - p1x);
      const ty = 2 * omt * (p1y - p0y) + 2 * prog * (p2y - p1y);
      const angle = Math.atan2(ty, tx);

      ctx.save();
      const arcGrad = ctx.createLinearGradient(p0x, p0y, rx, ry);
      arcGrad.addColorStop(0, 'rgba(163, 255, 18, 0.04)');
      arcGrad.addColorStop(0.65, 'rgba(163, 255, 18, 0.75)');
      arcGrad.addColorStop(1, '#ffffff');
      ctx.beginPath();
      const steps = 48;
      for (let i = 0; i <= steps; i++) {
        const u = (i / steps) * prog;
        const ou = 1 - u;
        const ux = ou * ou * p0x + 2 * ou * u * p1x + u * u * p2x;
        const uy = ou * ou * p0y + 2 * ou * u * p1y + u * u * p2y;
        if (i === 0) ctx.moveTo(ux, uy);
        else ctx.lineTo(ux, uy);
      }
      ctx.strokeStyle = 'rgba(163, 255, 18, 0.24)';
      ctx.lineWidth = 6;
      ctx.stroke();

      ctx.strokeStyle = arcGrad;
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.restore();

      // 3. Cinematic Black Hole (Gravitational Halo + Tilted Accretion Disk + Photon Sphere)
      ctx.save();
      const halo = ctx.createRadialGradient(bhX, bhY, bhR * 0.9, bhX, bhY, bhR * 3.4);
      halo.addColorStop(0, 'rgba(163, 255, 18, 0.32)');
      halo.addColorStop(0.28, 'rgba(255, 255, 255, 0.11)');
      halo.addColorStop(0.62, 'rgba(163, 255, 18, 0.04)');
      halo.addColorStop(1, 'rgba(5, 5, 5, 0)');
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(bhX, bhY, bhR * 3.4, 0, Math.PI * 2);
      ctx.fill();

      // Arrival shockwave pulse when rocket reaches Black Hole
      if (arrivedAt !== null) {
        const waveR = bhR * (1.2 + arrivalElapsed * 4.8);
        const waveAlpha = Math.max(0, 0.85 - arrivalElapsed * 0.9);
        ctx.beginPath();
        ctx.arc(bhX, bhY, waveR, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(163, 255, 18, ${waveAlpha})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Back half of tilted accretion disk
      ctx.translate(bhX, bhY);
      ctx.rotate(-0.34);

      for (let ring = 0; ring < 3; ring++) {
        const rxDisk = bhR * (1.75 + ring * 0.42);
        const ryDisk = bhR * (0.44 + ring * 0.11);
        ctx.beginPath();
        ctx.ellipse(0, 0, rxDisk, ryDisk, 0, Math.PI, Math.PI * 2);
        ctx.strokeStyle =
          ring === 0
            ? 'rgba(163, 255, 18, 0.85)'
            : ring === 1
              ? 'rgba(255, 255, 255, 0.42)'
              : 'rgba(163, 255, 18, 0.18)';
        ctx.lineWidth = ring === 0 ? 2.2 : 1.1;
        ctx.stroke();
      }

      // Swirling disk particles
      for (const dp of diskParticles) {
        dp.angle += dp.speed * dt * (arrivedAt !== null ? 2.1 : 1);
        const px = Math.cos(dp.angle) * bhR * dp.radius * 1.45;
        const py = Math.sin(dp.angle) * bhR * dp.radius * 0.36;
        ctx.fillStyle = dp.lime ? 'rgba(163, 255, 18, 0.72)' : 'rgba(255, 255, 255, 0.65)';
        ctx.beginPath();
        ctx.arc(px, py, dp.size, 0, Math.PI * 2);
        ctx.fill();
      }

      // Pitch-black Event Horizon Sphere + Crisp White/Lime Photon Ring
      ctx.rotate(0.34);
      ctx.beginPath();
      ctx.arc(0, 0, bhR, 0, Math.PI * 2);
      ctx.fillStyle = '#020202';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(0, 0, bhR + 1.2, 0, Math.PI * 2);
      ctx.strokeStyle = arrivedAt !== null ? '#a3ff12' : '#ffffff';
      ctx.lineWidth = arrivedAt !== null ? 2.4 : 1.5;
      ctx.stroke();

      // Front half of tilted accretion disk (crosses IN FRONT of the Event Horizon!)
      ctx.rotate(-0.34);
      ctx.beginPath();
      ctx.ellipse(0, 0, bhR * 1.75, bhR * 0.44, 0, 0, Math.PI);
      ctx.strokeStyle = 'rgba(163, 255, 18, 0.25)';
      ctx.lineWidth = 7;
      ctx.stroke();
      ctx.strokeStyle = '#a3ff12';
      ctx.lineWidth = 2.4;
      ctx.stroke();

      ctx.beginPath();
      ctx.ellipse(0, 0, bhR * 2.15, bhR * 0.55, 0, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.6)';
      ctx.lineWidth = 1.2;
      ctx.stroke();
      ctx.restore();

      // 4. Emit glowing ion particles behind the rocket
      if (arrivedAt === null && prog > 0.01) {
        for (let k = 0; k < 2; k++) {
          const spread = (Math.random() - 0.5) * 0.45;
          const speed = 45 + Math.random() * 65;
          trail.push({
            x: rx - Math.cos(angle) * 16,
            y: ry - Math.sin(angle) * 16,
            vx: -Math.cos(angle + spread) * speed,
            vy: -Math.sin(angle + spread) * speed,
            life: 1,
            size: 1.2 + Math.random() * 2,
            lime: Math.random() > 0.25,
          });
        }
      }

      for (let i = trail.length - 1; i >= 0; i--) {
        const pt = trail[i];
        pt.x += pt.vx * dt;
        pt.y += pt.vy * dt;
        pt.life -= dt * 2.4;
        if (pt.life <= 0) {
          trail.splice(i, 1);
          continue;
        }
        ctx.fillStyle = pt.lime
          ? `rgba(163, 255, 18, ${pt.life * 0.85})`
          : `rgba(255, 255, 255, ${pt.life * 0.8})`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, pt.size * pt.life, 0, Math.PI * 2);
        ctx.fill();
      }

      // 5. Sleek Aerospace Rocket Silhouette (locks into Black Hole orbit on arrival)
      ctx.save();
      const shipX =
        arrivedAt !== null
          ? bhX + Math.cos(Math.PI + arrivalElapsed * 3.1) * bhR * 1.48
          : rx;
      const shipY =
        arrivedAt !== null
          ? bhY + Math.sin(Math.PI + arrivalElapsed * 3.1) * bhR * 0.48
          : ry;
      const shipAngle =
        arrivedAt !== null ? Math.atan2(Math.cos(Math.PI + arrivalElapsed * 3.1) * 0.48, -Math.sin(Math.PI + arrivalElapsed * 3.1) * 1.48) : angle;

      ctx.translate(shipX, shipY);
      ctx.rotate(shipAngle);

      // Ion exhaust plume (zero shadowBlur!)
      const flameLen = 14 + Math.sin(tSec * 42) * 4;
      ctx.beginPath();
      ctx.moveTo(-13, -3.5);
      ctx.lineTo(-13 - flameLen, 0);
      ctx.lineTo(-13, 3.5);
      ctx.closePath();
      ctx.fillStyle = '#a3ff12';
      ctx.fill();

      // Delta wings
      ctx.fillStyle = '#a3ff12';
      ctx.beginPath();
      ctx.moveTo(-5, -4);
      ctx.lineTo(-14, -11);
      ctx.lineTo(-11, -3);
      ctx.closePath();
      ctx.fill();

      ctx.beginPath();
      ctx.moveTo(-5, 4);
      ctx.lineTo(-14, 11);
      ctx.lineTo(-11, 3);
      ctx.closePath();
      ctx.fill();

      // Sleek white fuselage
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.moveTo(19, 0);
      ctx.quadraticCurveTo(8, -6, -13, -4.5);
      ctx.lineTo(-13, 4.5);
      ctx.quadraticCurveTo(8, 6, 19, 0);
      ctx.closePath();
      ctx.fill();

      // Dark cockpit slit
      ctx.fillStyle = '#050505';
      ctx.beginPath();
      ctx.ellipse(5, 0, 3.5, 1.5, 0, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    };

    rafId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          className="launch-loader-fullscreen"
          role="status"
          aria-live="polite"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, transition: { duration: 0.42, ease: [0.22, 1, 0.36, 1] } }}
        >
          <canvas ref={canvasRef} className="launch-loader-canvas" aria-hidden="true" />

          <div className="launch-hud-top">
            <span className="launch-brand">
              <i className="status-dot" aria-hidden="true" />
              OSIEN PROBE
            </span>
            <span className="launch-tagline">OFFLINE STATIC ENGINE</span>
          </div>

          <div className="launch-hud-bottom">
            <div className="launch-big-pct">
              <span ref={pctRef}>00</span>
              <small>%</small>
            </div>
            <span ref={statusRef} className="launch-status-text">
              LOADING 3D PARKER PROBE
            </span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
