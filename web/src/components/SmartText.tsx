import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { getDeviceQualityProfile } from '../lib/deviceProfile';

const DecryptedText = lazy(() => import('./DecryptedText'));

export type TextPriority = 'heading' | 'accent' | 'body';

interface SmartTextProps {
  text: string;
  /**
   * Device-adaptive placement priority:
   * - 'heading': Active on ultra, balanced, and eco (uses official React Bits DecryptedText)
   * - 'accent':  Active on ultra & balanced (nav, kickers, buttons, finding titles)
   * - 'body':    Active on ultra only (descriptions & body copy, zero-cost hover scramble)
   */
  priority?: TextPriority;
  animateOn?: 'hover' | 'inViewHover';
  scrambleColor?: string;
  speed?: number;
  active?: boolean;
}

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_+-';

/**
 * Zero-boot-cost adaptive text scramble component:
 * - Renders plain native text until hovered (0ms TBT on page load!)
 * - Scales coverage automatically to device tier (ultra = all text, balanced = headings + accents, eco = headings only)
 */
export function SmartText({
  text,
  priority = 'body',
  animateOn = 'hover',
  scrambleColor = '#a3ff12',
  speed = 40,
  active = true,
}: SmartTextProps) {
  const tier = getDeviceQualityProfile().tier;
  const enabled =
    active &&
    (priority === 'heading' ||
      (priority === 'accent' && tier !== 'eco') ||
      (priority === 'body' && tier === 'ultra'));

  const [hovered, setHovered] = useState(false);
  const [display, setDisplay] = useState(text);
  const [scrambling, setScrambling] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    setDisplay(text);
    return () => {
      if (timerRef.current !== null) window.clearInterval(timerRef.current);
    };
  }, [text]);

  if (!enabled) {
    return <>{text}</>;
  }

  // Primary headings upgrade to official React Bits DecryptedText (with hoverRadius=100)
  if (priority === 'heading') {
    return (
      <Suspense fallback={text}>
        <DecryptedText
          text={text}
          animateOn={animateOn}
          speed={speed}
          scrambleColor={scrambleColor}
        />
      </Suspense>
    );
  }

  // Accent & body text: 0ms boot cost, lightweight sequential hover scramble on mouseenter
  const startScramble = () => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (timerRef.current !== null) window.clearInterval(timerRef.current);
    setHovered(true);
    setScrambling(true);

    const chars = Array.from(text);
    const total = chars.length;
    const step = Math.max(1, Math.ceil(total / 12));
    let revealed = 0;

    timerRef.current = window.setInterval(() => {
      revealed = Math.min(total, revealed + step);
      const next = chars
        .map((ch, idx) => {
          if (ch === ' ' || idx < revealed) return ch;
          return CHARS[Math.floor(Math.random() * CHARS.length)];
        })
        .join('');
      setDisplay(next);

      if (revealed >= total) {
        if (timerRef.current !== null) {
          window.clearInterval(timerRef.current);
          timerRef.current = null;
        }
        setDisplay(text);
        setScrambling(false);
      }
    }, speed);
  };

  return (
    <span
      className={scrambling ? 'smart-text-scrambling' : undefined}
      style={scrambling && hovered ? { color: scrambleColor } : undefined}
      onMouseEnter={startScramble}
    >
      {display}
    </span>
  );
}
