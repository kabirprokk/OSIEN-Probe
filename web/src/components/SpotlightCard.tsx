import { type ReactNode, type MouseEvent, useRef } from 'react';

interface SpotlightCardProps {
  className?: string;
  children: ReactNode;
}

/**
 * Magic UI / Aceternity-inspired pointer spotlight card tuned to OSIEN's
 * restrained obsidian + acid-sage palette (no gaudy glow, crisp hairline focus).
 */
export function SpotlightCard({ className = '', children }: SpotlightCardProps) {
  const cardRef = useRef<HTMLElement>(null);

  const handleMouseMove = (e: MouseEvent<HTMLElement>) => {
    const el = cardRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty('--spot-x', `${e.clientX - rect.left}px`);
    el.style.setProperty('--spot-y', `${e.clientY - rect.top}px`);
  };

  return (
    <article
      ref={cardRef}
      className={`spotlight-card ${className}`.trim()}
      onMouseMove={handleMouseMove}
    >
      {children}
    </article>
  );
}
