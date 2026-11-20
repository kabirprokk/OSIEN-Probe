import { type KeyboardEvent, useEffect, useRef } from 'react';

/**
 * OSIEN Signature Sine-Wave Scroll Bar — Interactive (Click & Drag to Scrub Page Scroll)
 * Replaces both the native browser scrollbar and traditional flat progress bars.
 */
export function OsienWaveScroll() {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let width = window.innerWidth;
    const height = 36;
    const padX = 20;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      width = window.innerWidth;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    let targetProgress = 0;
    let smoothProgress = 0;
    let lastScrollY = window.scrollY;
    let velocity = 0;
    let isDragging = false;
    let hoverX: number | null = null;

    const getPctFromClientX = (clientX: number) => {
      const usableW = Math.max(1, width - padX * 2);
      return Math.max(0, Math.min(1, (clientX - padX) / usableW));
    };

    const scrollToClientX = (clientX: number, smooth: boolean) => {
      const pct = getPctFromClientX(clientX);
      const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
      window.scrollTo({
        top: pct * maxScroll,
        behavior: smooth && !prefersReduced ? 'smooth' : 'auto',
      });
      targetProgress = pct;
    };

    const onScroll = () => {
      const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      targetProgress = Math.max(0, Math.min(1, window.scrollY / maxScroll));
      wrapRef.current?.setAttribute('aria-valuenow', String(Math.round(targetProgress * 100)));
      const dy = window.scrollY - lastScrollY;
      lastScrollY = window.scrollY;
      velocity = Math.max(-40, Math.min(40, velocity + dy * 0.14));
    };
    onScroll();

    const onPointerDown = (e: PointerEvent) => {
      isDragging = true;
      canvas.setPointerCapture(e.pointerId);
      scrollToClientX(e.clientX, true);
    };

    const onPointerMove = (e: PointerEvent) => {
      hoverX = e.clientX;
      if (isDragging) {
        scrollToClientX(e.clientX, false);
      }
    };

    const onPointerUp = (e: PointerEvent) => {
      if (!isDragging) return;
      isDragging = false;
      try {
        canvas.releasePointerCapture(e.pointerId);
      } catch {
        // ignore
      }
    };

    const onPointerLeave = () => {
      hoverX = null;
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('pointerleave', onPointerLeave);
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', resize, { passive: true });

    let rafId = 0;
    let lastDraw = 0;
    const start = performance.now();

    const draw = (now: number) => {
      rafId = requestAnimationFrame(draw);
      if (document.hidden) return;

      // Throttle idle redraw to ~20fps when not scrolling/hovering to keep CPU usage near 0%
      const active = isDragging || hoverX !== null || Math.abs(velocity) > 0.25 || Math.abs(targetProgress - smoothProgress) > 0.002;
      if (!active && now - lastDraw < 50) return;
      lastDraw = now;

      const t = (now - start) / 1000;
      smoothProgress += (targetProgress - smoothProgress) * (isDragging ? 0.35 : 0.14);
      velocity *= 0.88;

      ctx.clearRect(0, 0, width, height);

      const usableW = Math.max(1, width - padX * 2);
      const endX = padX + Math.max(0.015, smoothProgress) * usableW;
      const midY = height * 0.56;
      const baseAmp = prefersReduced ? 3.2 : 5.2 + Math.min(5.5, Math.abs(velocity) * 0.22);
      const phase = prefersReduced ? 0 : t * 1.45;
      const freq = (Math.PI * 2.35) / Math.max(360, width * 0.85);

      const waveY = (x: number) => midY + Math.sin(x * freq - phase) * baseAmp;

      // Full-track subtle white guide
      ctx.beginPath();
      for (let x = padX; x <= width - padX; x += 10) {
        const y = waveY(x);
        if (x === padX) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = hoverX !== null ? 'rgba(255, 255, 255, 0.18)' : 'rgba(255, 255, 255, 0.09)';
      ctx.lineWidth = hoverX !== null ? 1.25 : 1;
      ctx.stroke();

      // Zero-blur 2-pass luminous OSIEN Lime -> White sine wave (50x faster than shadowBlur)
      const grad = ctx.createLinearGradient(padX, 0, endX, 0);
      grad.addColorStop(0, 'rgba(163, 255, 18, 0.38)');
      grad.addColorStop(0.55, '#a3ff12');
      grad.addColorStop(1, '#ffffff');

      ctx.beginPath();
      for (let x = padX; x <= endX; x += 6) {
        const y = waveY(x);
        if (x === padX) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      const tipY = waveY(endX);
      ctx.lineTo(endX, tipY);

      ctx.lineCap = 'round';
      ctx.strokeStyle = 'rgba(163, 255, 18, 0.22)';
      ctx.lineWidth = 6;
      ctx.stroke();

      ctx.strokeStyle = grad;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Subtle hover preview marker along the wave
      if (hoverX !== null) {
        const clampedX = Math.max(padX, Math.min(width - padX, hoverX));
        const hy = waveY(clampedX);
        ctx.beginPath();
        ctx.arc(clampedX, hy, 2.6, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
        ctx.fill();
      }

      // Leading glowing orb at scroll tip (zero shadowBlur!)
      ctx.beginPath();
      ctx.arc(endX, tipY, isDragging ? 9 : 7.5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(163, 255, 18, 0.24)';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(endX, tipY, isDragging ? 4.2 : 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#a3ff12';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(endX, tipY, 1.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
    };

    rafId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(rafId);
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointermove', onPointerMove);
      canvas.removeEventListener('pointerup', onPointerUp);
      canvas.removeEventListener('pointercancel', onPointerUp);
      canvas.removeEventListener('pointerleave', onPointerLeave);
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', resize);
    };
  }, []);

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
    const step = window.innerHeight * 0.4;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault();
      window.scrollBy({ top: step, behavior: 'smooth' });
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault();
      window.scrollBy({ top: -step, behavior: 'smooth' });
    } else if (e.key === 'Home') {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (e.key === 'End') {
      e.preventDefault();
      window.scrollTo({ top: maxScroll, behavior: 'smooth' });
    }
  };

  return (
    <div
      ref={wrapRef}
      className="osien-wave-scroll"
      role="slider"
      tabIndex={0}
      aria-label="Page scroll progress"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={0}
      title="Click or drag to scroll"
      onKeyDown={handleKeyDown}
    >
      <canvas ref={canvasRef} aria-hidden="true" />
    </div>
  );
}
