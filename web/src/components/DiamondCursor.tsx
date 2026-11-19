import { useEffect, useRef } from 'react';

/**
 * Custom Diamond-Shaped Cursor in Black / White / Lime Green (#a3ff12)
 * Crisp zero-lag inner lime diamond + smooth damped white outer diamond.
 */
export function DiamondCursor() {
  const coreRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const core = coreRef.current;
    const ring = ringRef.current;
    if (!core || !ring) return;

    const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
    if (!finePointer.matches) return;

    const root = document.documentElement;
    root.classList.add('has-diamond-cursor');

    let targetX = -100;
    let targetY = -100;
    let ringX = -100;
    let ringY = -100;
    let visible = false;

    const onMove = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return;
      targetX = e.clientX;
      targetY = e.clientY;
      if (!visible) {
        ringX = targetX;
        ringY = targetY;
        visible = true;
        core.classList.add('is-visible');
        ring.classList.add('is-visible');
      }
      core.style.transform = `translate3d(${targetX}px, ${targetY}px, 0) translate(-50%, -50%) rotate(45deg)`;

      const el = e.target instanceof Element ? e.target : null;
      const isInteractive = Boolean(
        el?.closest('a, button, [role="tab"], [role="option"], .osien-wave-scroll'),
      );
      const isText = Boolean(el?.closest('input, textarea, select, [contenteditable="true"]'));

      core.classList.toggle('is-hover', isInteractive);
      ring.classList.toggle('is-hover', isInteractive);
      core.classList.toggle('is-hidden', isText);
      ring.classList.toggle('is-hidden', isText);
    };

    const onLeave = () => {
      visible = false;
      core.classList.remove('is-visible', 'is-hover', 'is-down');
      ring.classList.remove('is-visible', 'is-hover', 'is-down');
    };

    const onDown = () => {
      core.classList.add('is-down');
      ring.classList.add('is-down');
    };

    const onUp = () => {
      core.classList.remove('is-down');
      ring.classList.remove('is-down');
    };

    window.addEventListener('pointermove', onMove, { passive: true });
    document.addEventListener('mouseleave', onLeave);
    window.addEventListener('pointerdown', onDown, { passive: true });
    window.addEventListener('pointerup', onUp, { passive: true });

    let rafId = 0;
    const tick = () => {
      rafId = requestAnimationFrame(tick);
      if (!visible) return;
      ringX += (targetX - ringX) * 0.18;
      ringY += (targetY - ringY) * 0.18;
      ring.style.transform = `translate3d(${ringX}px, ${ringY}px, 0) translate(-50%, -50%) rotate(45deg)`;
    };
    rafId = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafId);
      root.classList.remove('has-diamond-cursor');
      window.removeEventListener('pointermove', onMove);
      document.removeEventListener('mouseleave', onLeave);
      window.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointerup', onUp);
    };
  }, []);

  return (
    <>
      <div ref={ringRef} className="diamond-cursor-ring" aria-hidden="true" />
      <div ref={coreRef} className="diamond-cursor-core" aria-hidden="true" />
    </>
  );
}
