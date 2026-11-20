import { lazy, Suspense, useState } from 'react';
import { getDeviceQualityProfile } from '../lib/deviceProfile';

const DecryptedText = lazy(() => import('./DecryptedText'));

export type TextPriority = 'heading' | 'accent' | 'body';

interface SmartTextProps {
  text: string;
  /**
   * Device-adaptive placement priority:
   * - 'heading': Active on ultra, balanced, and eco
   * - 'accent':  Active on ultra & balanced (nav, kickers, buttons, finding titles)
   * - 'body':    Active on ultra only (descriptions & body copy)
   */
  priority?: TextPriority;
  animateOn?: 'hover' | 'inViewHover';
  scrambleColor?: string;
  speed?: number;
  active?: boolean;
}

/**
 * Exact official React Bits DecryptedText everywhere, with 0ms boot cost:
 * - Headings mount official DecryptedText directly (with hoverRadius=100)
 * - Accent & body text render as zero-cost native text at boot, then upgrade
 *   on first pointer enter to the EXACT official React Bits DecryptedText
 *   with continuous 100px cursor hover-radius tracking.
 */
export function SmartText({
  text,
  priority = 'body',
  animateOn = 'hover',
  scrambleColor = '#a3ff12',
  speed = 60,
  active = true,
}: SmartTextProps) {
  const tier = getDeviceQualityProfile().tier;
  const enabled =
    active &&
    (priority === 'heading' ||
      (priority === 'accent' && tier !== 'eco') ||
      (priority === 'body' && tier === 'ultra'));

  const [upgraded, setUpgraded] = useState(priority === 'heading');

  if (!enabled) {
    return <>{text}</>;
  }

  if (!upgraded) {
    return (
      <span onPointerEnter={() => setUpgraded(true)}>
        {text}
      </span>
    );
  }

  return (
    <Suspense fallback={text}>
      <DecryptedText
        text={text}
        animateOn={priority === 'heading' ? animateOn : 'hover'}
        effect="scramble"
        sequential={true}
        revealDirection="start"
        speed={speed}
        maxIterations={10}
        hoverRadius={100}
        scrambleColor={scrambleColor}
        loop={false}
        loopDelay={2000}
        useOriginalCharsOnly={false}
        characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+"
        className="revealed"
        encryptedClassName="encrypted"
      />
    </Suspense>
  );
}
