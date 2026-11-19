import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/examples/jsm/loaders/DRACOLoader.js';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';

interface ScrollKeyframe {
  t: number;
  pos: [number, number, number];
  rot: [number, number, number];
  scale: number;
}

const DESKTOP_KEYFRAMES: ScrollKeyframe[] = [
  { t: 0.0, pos: [1.75, 0.04, 0.12], rot: [0.24, -0.58, 0.1], scale: 1.04 },
  { t: 0.24, pos: [2.42, 0.48, -1.65], rot: [0.42, 0.65, -0.12], scale: 0.86 },
  { t: 0.5, pos: [-2.22, -0.08, -1.18], rot: [0.26, 1.95, 0.14], scale: 0.92 },
  { t: 0.74, pos: [-1.72, 0.06, 0.14], rot: [0.16, 3.15, -0.06], scale: 0.98 },
  { t: 0.9, pos: [2.25, 0.14, -0.88], rot: [0.3, 4.4, 0.1], scale: 0.88 },
  { t: 1.0, pos: [2.48, 0.4, -1.3], rot: [0.18, 5.25, 0.05], scale: 0.84 },
];

const MOBILE_KEYFRAMES: ScrollKeyframe[] = [
  { t: 0.0, pos: [0.5, 0.55, -1.7], rot: [0.22, -0.52, 0.08], scale: 0.72 },
  { t: 0.5, pos: [-0.55, 0.35, -2.3], rot: [0.28, 1.85, -0.08], scale: 0.64 },
  { t: 1.0, pos: [0.0, 0.45, -1.9], rot: [0.18, 4.75, 0.04], scale: 0.68 },
];

function smoothstep(edge0: number, edge1: number, x: number): number {
  const n = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0 || 1)));
  return n * n * (3 - 2 * n);
}

function sampleKeyframes(frames: ScrollKeyframe[], progress: number) {
  const p = Math.max(0, Math.min(1, progress));
  let i = 0;
  while (i < frames.length - 2 && p > frames[i + 1].t) {
    i += 1;
  }
  const a = frames[i];
  const b = frames[i + 1];
  const k = smoothstep(a.t, b.t, p);

  return {
    x: THREE.MathUtils.lerp(a.pos[0], b.pos[0], k),
    y: THREE.MathUtils.lerp(a.pos[1], b.pos[1], k),
    z: THREE.MathUtils.lerp(a.pos[2], b.pos[2], k),
    rx: THREE.MathUtils.lerp(a.rot[0], b.rot[0], k),
    ry: THREE.MathUtils.lerp(a.rot[1], b.rot[1], k),
    rz: THREE.MathUtils.lerp(a.rot[2], b.rot[2], k),
    scale: THREE.MathUtils.lerp(a.scale, b.scale, k),
  };
}

function enhanceParkerMaterial(mat: THREE.MeshStandardMaterial) {
  const name = (mat.name || '').toLowerCase();
  mat.envMapIntensity = 1.35;

  if (name.includes('foil') || name.includes('silver')) {
    mat.metalness = 0.88;
    mat.roughness = 0.24;
  } else if (name.includes('metal')) {
    mat.metalness = 0.82;
    mat.roughness = 0.28;
  } else if (name.includes('black') || name.includes('krinkle')) {
    mat.metalness = 0.42;
    mat.roughness = 0.42;
  } else {
    mat.metalness = Math.max(mat.metalness, 0.35);
    mat.roughness = Math.min(mat.roughness, 0.48);
  }
  mat.needsUpdate = true;
}

/**
 * Full-Viewport Borderless Scroll-Choreographed 3D Scene
 * Renders NASA's official public-domain Parker Solar Probe (.glb) with Draco decoding,
 * 60% Black / 30% White / 10% Electric Lime studio rim lighting, and smooth + hard scroll physics.
 */
interface ProbeScrollSceneProps {
  dimmed?: boolean;
  onProgress?: (pct: number) => void;
  onReady?: () => void;
}

export function ProbeScrollScene({ dimmed = false, onProgress, onReady }: ProbeScrollSceneProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const dimmedRef = useRef(dimmed);
  const onProgressRef = useRef(onProgress);
  const onReadyRef = useRef(onReady);

  useEffect(() => {
    dimmedRef.current = dimmed;
  }, [dimmed]);

  useEffect(() => {
    onProgressRef.current = onProgress;
    onReadyRef.current = onReady;
  }, [onProgress, onReady]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const width = window.innerWidth;
    const height = window.innerHeight;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(35, width / height, 0.1, 140);
    camera.position.set(0, 0, 7.6);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setSize(width, height);
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    host.appendChild(renderer.domElement);

    // Procedural studio reflections (zero external HDRI requests)
    const pmrem = new THREE.PMREMGenerator(renderer);
    const envRT = pmrem.fromScene(new RoomEnvironment(), 0.04);
    scene.environment = envRT.texture;
    pmrem.dispose();

    // 60% Black / 30% White / 10% Electric Lime Studio Lighting
    const hemi = new THREE.HemisphereLight('#ffffff', '#050505', 0.65);
    scene.add(hemi);

    const keyLight = new THREE.DirectionalLight('#ffffff', 2.45);
    keyLight.position.set(6, 7, 6);
    scene.add(keyLight);

    const limeRim = new THREE.DirectionalLight('#a3ff12', 2.6);
    limeRim.position.set(-7, 2.5, -4.5);
    scene.add(limeRim);

    const fillLight = new THREE.DirectionalLight('#e4e4e4', 0.9);
    fillLight.position.set(-3, -4, 4);
    scene.add(fillLight);

    // Calibrated deep-space White + 10% Lime starfield
    const starCount = 240;
    const positions = new Float32Array(starCount * 3);
    const colors = new Float32Array(starCount * 3);
    const cLime = new THREE.Color('#a3ff12');
    const cWhite = new THREE.Color('#ffffff');

    for (let i = 0; i < starCount; i++) {
      const i3 = i * 3;
      positions[i3] = (Math.random() - 0.5) * 32;
      positions[i3 + 1] = (Math.random() - 0.5) * 22;
      positions[i3 + 2] = -6 - Math.random() * 18;

      const c = Math.random() > 0.88 ? cLime : cWhite;
      const dim = 0.25 + Math.random() * 0.55;
      colors[i3] = c.r * dim;
      colors[i3 + 1] = c.g * dim;
      colors[i3 + 2] = c.b * dim;
    }

    const starGeo = new THREE.BufferGeometry();
    starGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    starGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    const starMat = new THREE.PointsMaterial({
      size: 0.055,
      vertexColors: true,
      transparent: true,
      opacity: 0.62,
      depthWrite: false,
    });
    const stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    // Master probe rig
    const probeRig = new THREE.Group();
    const initial = sampleKeyframes(
      window.innerWidth < 960 ? MOBILE_KEYFRAMES : DESKTOP_KEYFRAMES,
      0,
    );
    probeRig.position.set(initial.x, initial.y, initial.z);
    probeRig.rotation.set(initial.rx, initial.ry, initial.rz);
    probeRig.scale.setScalar(initial.scale);
    scene.add(probeRig);

    // Delicate dashed lime orbital telemetry ring + orbiting beacon
    const ringRadius = 1.95;
    const ringPts: THREE.Vector3[] = [];
    for (let i = 0; i <= 128; i++) {
      const a = (i / 128) * Math.PI * 2;
      ringPts.push(new THREE.Vector3(Math.cos(a) * ringRadius, 0, Math.sin(a) * ringRadius));
    }
    const orbitGeo = new THREE.BufferGeometry().setFromPoints(ringPts);
    const orbitMat = new THREE.LineDashedMaterial({
      color: '#a3ff12',
      dashSize: 0.14,
      gapSize: 0.14,
      transparent: true,
      opacity: 0.3,
    });
    const orbitRing = new THREE.Line(orbitGeo, orbitMat);
    orbitRing.computeLineDistances();
    orbitRing.rotation.set(0.45, 0.1, -0.32);
    probeRig.add(orbitRing);

    const beaconGeo = new THREE.SphereGeometry(0.036, 14, 14);
    const beaconMat = new THREE.MeshBasicMaterial({ color: '#a3ff12' });
    const beacon = new THREE.Mesh(beaconGeo, beaconMat);
    probeRig.add(beacon);

    const modelFloat = new THREE.Group();
    probeRig.add(modelFloat);

    // Load NASA Parker Solar Probe (.glb) with local offline Draco WASM decoder
    const dracoLoader = new DRACOLoader();
    dracoLoader.setDecoderPath('/draco/');
    dracoLoader.preload();

    const gltfLoader = new GLTFLoader();
    gltfLoader.setDRACOLoader(dracoLoader);

    let disposed = false;
    let modelLoaded = false;
    let readyNotified = false;

    onProgressRef.current?.(18);

    gltfLoader.load(
      '/models/parker-solar-probe.glb',
      (gltf) => {
        if (disposed) return;
        const model = gltf.scene;

        model.traverse((obj) => {
          if ((obj as THREE.Mesh).isMesh) {
            const mesh = obj as THREE.Mesh;
            const mats = Array.isArray(mesh.material) ? mesh.material : [mesh.material];
            for (const m of mats) {
              if (m instanceof THREE.MeshStandardMaterial) {
                enhanceParkerMaterial(m);
              }
            }
          }
        });

        const box = new THREE.Box3().setFromObject(model);
        const size = new THREE.Vector3();
        const center = new THREE.Vector3();
        box.getSize(size);
        box.getCenter(center);

        const maxAxis = Math.max(size.x, size.y, size.z) || 1;
        const scale = 3.15 / maxAxis;
        model.scale.setScalar(scale);
        model.position.set(-center.x * scale, -center.y * scale, -center.z * scale);
        modelFloat.add(model);

        // Pre-compile WebGL shaders & render one warm-up frame before signaling ready
        renderer.compile(scene, camera);
        renderer.render(scene, camera);
        modelLoaded = true;
        onProgressRef.current?.(100);
        if (!readyNotified) {
          readyNotified = true;
          requestAnimationFrame(() => onReadyRef.current?.());
        }
      },
      (evt) => {
        if (evt.total > 0) {
          const pct = Math.min(92, Math.round(20 + (evt.loaded / evt.total) * 70));
          onProgressRef.current?.(pct);
        }
      },
      () => {
        if (!disposed && !readyNotified) {
          readyNotified = true;
          onProgressRef.current?.(100);
          onReadyRef.current?.();
        }
      },
    );

    let targetScroll = 0;
    let smoothScroll = 0;
    let lastScrollY = window.scrollY;
    let scrollVelocity = 0;
    let targetPointerX = 0;
    let targetPointerY = 0;
    let smoothPointerX = 0;
    let smoothPointerY = 0;
    let currentOpacity = 0;

    const updateScrollTarget = () => {
      const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      targetScroll = Math.max(0, Math.min(1, window.scrollY / maxScroll));
      const dy = window.scrollY - lastScrollY;
      lastScrollY = window.scrollY;
      scrollVelocity = Math.max(-1.8, Math.min(1.8, scrollVelocity + dy * 0.0022));
    };
    updateScrollTarget();

    const onPointerMove = (e: PointerEvent) => {
      targetPointerX = (e.clientX / window.innerWidth - 0.5) * 2;
      targetPointerY = (e.clientY / window.innerHeight - 0.5) * 2;
    };

    const onResize = () => {
      const w = window.innerWidth;
      const h = window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
      updateScrollTarget();
    };

    window.addEventListener('scroll', updateScrollTarget, { passive: true });
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('resize', onResize, { passive: true });

    let rafId = 0;
    const clock = new THREE.Clock();

    const animate = () => {
      rafId = requestAnimationFrame(animate);
      if (document.hidden) return;

      const dt = Math.min(clock.getDelta(), 0.05);
      const elapsed = clock.getElapsedTime();
      const damp = 1 - Math.exp(-5.8 * dt);

      smoothScroll += (targetScroll - smoothScroll) * damp;
      smoothPointerX += (targetPointerX - smoothPointerX) * damp;
      smoothPointerY += (targetPointerY - smoothPointerY) * damp;
      scrollVelocity *= Math.exp(-6.5 * dt);

      const desiredOpacity = !modelLoaded ? 0 : dimmedRef.current ? 0.16 : 1;
      currentOpacity += (desiredOpacity - currentOpacity) * damp;
      host.style.opacity = String(currentOpacity);

      const frames = window.innerWidth < 960 ? MOBILE_KEYFRAMES : DESKTOP_KEYFRAMES;
      const pose = sampleKeyframes(frames, smoothScroll);

      probeRig.position.set(
        pose.x + smoothPointerX * 0.18,
        pose.y - smoothPointerY * 0.14,
        pose.z - Math.abs(scrollVelocity) * 0.22,
      );

      const idleSpin = prefersReduced ? 0 : elapsed * 0.11;
      probeRig.rotation.set(
        pose.rx + smoothPointerY * 0.14 + scrollVelocity * 0.22,
        pose.ry + idleSpin + smoothPointerX * 0.24,
        pose.rz - scrollVelocity * 0.12,
      );
      probeRig.scale.setScalar(pose.scale);

      if (!prefersReduced) {
        modelFloat.position.y = Math.sin(elapsed * 0.95) * 0.065;
        const ba = elapsed * 0.55;
        beacon.position
          .set(Math.cos(ba) * ringRadius, 0, Math.sin(ba) * ringRadius)
          .applyEuler(orbitRing.rotation);
        stars.rotation.y = elapsed * 0.007 + smoothScroll * 0.25;
        stars.rotation.x = smoothScroll * 0.12;
      }

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      disposed = true;
      cancelAnimationFrame(rafId);
      window.removeEventListener('scroll', updateScrollTarget);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('resize', onResize);
      dracoLoader.dispose();
      envRT.dispose();
      starGeo.dispose();
      starMat.dispose();
      orbitGeo.dispose();
      orbitMat.dispose();
      beaconGeo.dispose();
      beaconMat.dispose();
      modelFloat.traverse((obj) => {
        if ((obj as THREE.Mesh).isMesh) {
          const mesh = obj as THREE.Mesh;
          mesh.geometry.dispose();
          const mats = Array.isArray(mesh.material) ? mesh.material : [mesh.material];
          mats.forEach((m) => m.dispose());
        }
      });
      renderer.dispose();
      if (renderer.domElement.parentNode === host) {
        host.removeChild(renderer.domElement);
      }
    };
  }, []);

  return <div ref={hostRef} className="probe-scroll-scene" aria-hidden="true" />;
}
