export type DeviceTier = 'ultra' | 'balanced' | 'eco';

export interface QualityProfile {
  tier: DeviceTier;
  maxDpr: number;
  antialias: boolean;
  starCount: number;
  targetFps: number;
  loaderDiskParticles: number;
  loaderStars: number;
  asciiFontSize: number;
  techSpecks: number;
  waveIdleIntervalMs: number;
  enableSmoothScroll: boolean;
}

const PROFILES: Record<DeviceTier, QualityProfile> = {
  ultra: {
    tier: 'ultra',
    maxDpr: 1.75,
    antialias: true,
    starCount: 240,
    targetFps: 60,
    loaderDiskParticles: 95,
    loaderStars: 130,
    asciiFontSize: 8,
    techSpecks: 15,
    waveIdleIntervalMs: 33,
    enableSmoothScroll: true,
  },
  balanced: {
    tier: 'balanced',
    maxDpr: 1.35,
    antialias: true,
    starCount: 140,
    targetFps: 60,
    loaderDiskParticles: 55,
    loaderStars: 80,
    asciiFontSize: 10,
    techSpecks: 10,
    waveIdleIntervalMs: 50,
    enableSmoothScroll: true,
  },
  eco: {
    tier: 'eco',
    maxDpr: 1.0,
    antialias: false,
    starCount: 70,
    targetFps: 30,
    loaderDiskParticles: 28,
    loaderStars: 45,
    asciiFontSize: 12,
    techSpecks: 6,
    waveIdleIntervalMs: 85,
    enableSmoothScroll: false,
  },
};

function isSoftwareGpu(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return true;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return false;
    const renderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '');
    return /swiftshader|llvmpipe|software|basic render|angle \(google/i.test(renderer);
  } catch {
    return false;
  }
}

let cachedProfile: QualityProfile | null = null;

/**
 * Automatically probes CPU cores, RAM, network save-data, GPU renderer, and viewport
 * to pick the highest fidelity tier the user's device can sustain smoothly
 * while keeping all visual details intact.
 */
export function getDeviceQualityProfile(): QualityProfile {
  if (cachedProfile) return cachedProfile;
  if (typeof window === 'undefined') return PROFILES.balanced;

  const nav = navigator as Navigator & {
    deviceMemory?: number;
    connection?: { saveData?: boolean; effectiveType?: string };
  };

  const cores = nav.hardwareConcurrency || 4;
  const mem = nav.deviceMemory ?? 8;
  const saveData = Boolean(nav.connection?.saveData);
  const slowNet = /2g|slow-2g/i.test(nav.connection?.effectiveType || '');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const softwareGpu = isSoftwareGpu();

  let tier: DeviceTier = 'balanced';

  if (reducedMotion || saveData || slowNet || softwareGpu || cores <= 3 || mem <= 3) {
    tier = 'eco';
  } else if (cores >= 8 && mem >= 8 && window.innerWidth >= 1024) {
    tier = 'ultra';
  }

  cachedProfile = PROFILES[tier];
  return cachedProfile;
}
