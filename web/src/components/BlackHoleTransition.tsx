import { AnimatePresence, motion } from 'motion/react';

interface BlackHoleTransitionProps {
  active: boolean;
  destination: string;
}

/**
 * Page-Change Transition Overlay (>= 1 second guaranteed visibility)
 * Deep-black Event Horizon with white + lime accretion disk and OSIEN Probe orbiting it.
 */
export function BlackHoleTransition({ active, destination }: BlackHoleTransitionProps) {
  return (
    <AnimatePresence>
      {active && (
        <motion.div
          className="bh-transition"
          role="status"
          aria-live="polite"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="bh-stage">
            <svg viewBox="0 0 360 360" aria-hidden="true">
              <defs>
                <radialGradient id="bh-halo" cx="50%" cy="50%" r="50%">
                  <stop offset="36%" stopColor="#050505" stopOpacity="1" />
                  <stop offset="48%" stopColor="#a3ff12" stopOpacity="0.65" />
                  <stop offset="60%" stopColor="#ffffff" stopOpacity="0.22" />
                  <stop offset="100%" stopColor="#050505" stopOpacity="0" />
                </radialGradient>
                <filter id="bh-glow" x="-40%" y="-40%" width="180%" height="180%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Gravitational lensing halo */}
              <circle cx="180" cy="180" r="126" fill="url(#bh-halo)" />

              {/* Tilted Accretion Disk */}
              <g transform="translate(180, 180) rotate(-22)">
                <ellipse
                  cx="0"
                  cy="0"
                  rx="132"
                  ry="38"
                  fill="none"
                  stroke="rgba(255,255,255,0.22)"
                  strokeWidth="1.5"
                />
                <ellipse
                  className="bh-disk-spin"
                  cx="0"
                  cy="0"
                  rx="116"
                  ry="32"
                  fill="none"
                  stroke="#a3ff12"
                  strokeWidth="2"
                  strokeDasharray="64 26 24 18"
                  filter="url(#bh-glow)"
                />
                <ellipse
                  cx="0"
                  cy="0"
                  rx="96"
                  ry="25"
                  fill="none"
                  stroke="rgba(255,255,255,0.55)"
                  strokeWidth="1"
                  strokeDasharray="40 22"
                />
              </g>

              {/* Pure Black Event Horizon + Photon Ring */}
              <circle
                cx="180"
                cy="180"
                r="52"
                fill="#020202"
                stroke="#ffffff"
                strokeWidth="1.4"
              />
              <circle
                cx="180"
                cy="180"
                r="56"
                fill="none"
                stroke="#a3ff12"
                strokeWidth="1"
                strokeOpacity="0.7"
              />

              {/* Orbiting OSIEN Probe around the Black Hole */}
              <g transform="translate(180, 180) rotate(-22)">
                <g className="bh-probe-orbit">
                  <g transform="translate(132, 0)">
                    {/* Glowing probe diamond & wings */}
                    <polygon
                      points="0,-9 9,0 0,9 -9,0"
                      fill="#a3ff12"
                      filter="url(#bh-glow)"
                    />
                    <polygon points="-13,-5 -7,0 -13,5" fill="#ffffff" />
                    <polygon points="13,-5 7,0 13,5" fill="#ffffff" />
                    <circle cx="0" cy="0" r="2.6" fill="#050505" />
                  </g>
                </g>
              </g>
            </svg>

            <p className="bh-label">
              <span className="status-dot" aria-hidden="true" />
              ORBITING SINGULARITY · {destination}
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
