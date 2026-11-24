import { useEffect, useRef, useState } from 'react'

type PowerKind = 'shield' | 'slow' | 'double' | 'mini'

type Obstacle = {
  x: number
  y: number
  w: number
  h: number
  vx: number
  vy: number
  kind: 'spike' | 'drone' | 'cloud'
}

type Pickup = {
  x: number
  y: number
  r: number
  vy: number
  kind: 'star' | PowerKind
}

const POWER_META: Record<PowerKind, { label: string; color: string; short: string }> = {
  shield: { label: 'Shield Bubble', color: '#38bdf8', short: 'S' },
  slow: { label: 'Slow-Mo Warp', color: '#a855f7', short: 'T' },
  double: { label: '2x Star Magnet', color: '#facc15', short: '2x' },
  mini: { label: 'Mini Balloon', color: '#34d399', short: 'M' },
}

export function BalloonGame({
  activeTaskLabel,
  onClose,
}: {
  activeTaskLabel?: string
  onClose?: () => void
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const [score, setScore] = useState(0)
  const [best, setBest] = useState(() => {
    try {
      return Number(localStorage.getItem('osien-balloon-best') || 0) || 0
    } catch (err) {
      void err
      return 0
    }
  })
  const [gameOver, setGameOver] = useState(false)
  const [paused, setPaused] = useState(false)
  const [activePowers, setActivePowers] = useState<string[]>([])
  const [runSeed, setRunSeed] = useState(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const W = canvas.width
    const H = canvas.height

    let raf = 0
    let alive = true
    let localScore = 0
    let frame = 0

    const balloon = {
      x: W / 2,
      y: H - 72,
      vx: 0,
      baseR: 17,
      shield: false,
      slowUntil: 0,
      doubleUntil: 0,
      miniUntil: 0,
    }

    const keys = { left: false, right: false, up: false, down: false }
    let pointerX: number | null = null
    const obstacles: Obstacle[] = []
    const pickups: Pickup[] = []
    const cloudsBg = Array.from({ length: 14 }, (_, i) => ({
      x: (i * 67) % W,
      y: (i * 43) % H,
      s: 0.4 + (i % 3) * 0.35,
    }))

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') keys.left = true
      if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') keys.right = true
      if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') keys.up = true
      if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') keys.down = true
    }
    const onKeyUp = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') keys.left = false
      if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') keys.right = false
      if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') keys.up = false
      if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') keys.down = false
    }
    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      pointerX = ((e.clientX - rect.left) / rect.width) * W
    }
    const onMouseLeave = () => {
      pointerX = null
    }

    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('keyup', onKeyUp)
    canvas.addEventListener('mousemove', onMouseMove)
    canvas.addEventListener('mouseleave', onMouseLeave)

    const spawnObstacle = () => {
      const difficulty = Math.min(2.4, 1 + frame / 1800)
      const roll = Math.random()
      const kind: Obstacle['kind'] = roll < 0.4 ? 'spike' : roll < 0.75 ? 'drone' : 'cloud'
      const w = kind === 'spike' ? 24 : kind === 'drone' ? 54 : 68
      const h = kind === 'spike' ? 24 : kind === 'drone' ? 14 : 22
      const x = 16 + Math.random() * (W - w - 32)
      const vx = kind === 'drone' ? (Math.random() < 0.5 ? -1.7 : 1.7) * difficulty : (Math.random() - 0.5) * 0.7
      const vy = (1.9 + Math.random() * 1.4) * difficulty
      obstacles.push({ x, y: -30, w, h, vx, vy, kind })
    }

    const spawnPickup = () => {
      const isPower = Math.random() < 0.34
      const kinds: PowerKind[] = ['shield', 'slow', 'double', 'mini']
      const kind: Pickup['kind'] = isPower ? kinds[Math.floor(Math.random() * kinds.length)] : 'star'
      pickups.push({
        x: 24 + Math.random() * (W - 48),
        y: -20,
        r: isPower ? 12 : 9,
        vy: 1.7 + Math.random() * 0.8,
        kind,
      })
    }

    const step = () => {
      if (!alive) return
      if (paused) {
        raf = requestAnimationFrame(step)
        return
      }

      frame++
      const isSlow = balloon.slowUntil > frame
      const isDouble = balloon.doubleUntil > frame
      const isMini = balloon.miniUntil > frame
      const speedScale = isSlow ? 0.52 : 1
      const r = isMini ? balloon.baseR * 0.58 : balloon.baseR

      if (pointerX !== null) {
        balloon.x += (pointerX - balloon.x) * 0.18
      } else {
        const accel = 0.65
        if (keys.left) balloon.vx -= accel
        if (keys.right) balloon.vx += accel
        balloon.vx *= 0.84
        balloon.x += balloon.vx
      }
      if (keys.up) balloon.y = Math.max(48, balloon.y - 2.6)
      if (keys.down) balloon.y = Math.min(H - 36, balloon.y + 2.6)
      balloon.x = Math.max(r + 8, Math.min(W - r - 8, balloon.x))

      if (frame % Math.max(18, Math.floor(38 / speedScale)) === 0) spawnObstacle()
      if (frame % 75 === 0) spawnPickup()

      if (frame % 6 === 0) {
        localScore += isDouble ? 2 : 1
        setScore(localScore)
        const badges: string[] = []
        if (balloon.shield) badges.push('Shield Ready')
        if (isSlow) badges.push('Slow-Mo')
        if (isDouble) badges.push('2x + Magnet')
        if (isMini) badges.push('Mini Size')
        setActivePowers(badges)
      }

      // Background sky
      const grad = ctx.createLinearGradient(0, 0, 0, H)
      grad.addColorStop(0, '#090d16')
      grad.addColorStop(1, '#111c2d')
      ctx.fillStyle = grad
      ctx.fillRect(0, 0, W, H)

      // Rising altitude streaks
      ctx.fillStyle = 'rgba(148, 163, 184, 0.14)'
      for (const c of cloudsBg) {
        c.y += (1.2 + c.s) * speedScale
        if (c.y > H + 10) {
          c.y = -10
          c.x = Math.random() * W
        }
        ctx.beginPath()
        ctx.arc(c.x, c.y, 2 + c.s * 2, 0, Math.PI * 2)
        ctx.fill()
      }

      // Update & draw pickups
      for (let i = pickups.length - 1; i >= 0; i--) {
        const p = pickups[i]
        p.y += p.vy * speedScale
        if (isDouble && p.kind === 'star') {
          const dx = balloon.x - p.x
          const dy = balloon.y - p.y
          if (dx * dx + dy * dy < 150 * 150) {
            p.x += dx * 0.09
            p.y += dy * 0.09
          }
        }
        const dx = balloon.x - p.x
        const dy = balloon.y - p.y
        if (Math.hypot(dx, dy) < r + p.r) {
          if (p.kind === 'star') {
            localScore += isDouble ? 50 : 25
            setScore(localScore)
          } else if (p.kind === 'shield') {
            balloon.shield = true
          } else if (p.kind === 'slow') {
            balloon.slowUntil = frame + 320
          } else if (p.kind === 'double') {
            balloon.doubleUntil = frame + 360
          } else if (p.kind === 'mini') {
            balloon.miniUntil = frame + 360
          }
          pickups.splice(i, 1)
          continue
        }
        if (p.y > H + 25) {
          pickups.splice(i, 1)
          continue
        }

        ctx.save()
        if (p.kind === 'star') {
          ctx.fillStyle = '#fde047'
          ctx.beginPath()
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
          ctx.fill()
          ctx.fillStyle = '#090d16'
          ctx.font = 'bold 10px sans-serif'
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillText('★', p.x, p.y + 0.5)
        } else {
          const meta = POWER_META[p.kind]
          ctx.fillStyle = meta.color
          ctx.beginPath()
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
          ctx.fill()
          ctx.fillStyle = '#090d16'
          ctx.font = 'bold 10px sans-serif'
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillText(meta.short, p.x, p.y + 0.5)
        }
        ctx.restore()
      }

      // Update & draw obstacles
      for (let i = obstacles.length - 1; i >= 0; i--) {
        const o = obstacles[i]
        o.x += o.vx * speedScale
        o.y += o.vy * speedScale
        if (o.x <= 8 || o.x + o.w >= W - 8) o.vx *= -1
        if (o.y > H + 40) {
          obstacles.splice(i, 1)
          continue
        }

        // Draw obstacle
        ctx.save()
        if (o.kind === 'spike') {
          ctx.fillStyle = '#f43f5e'
          ctx.beginPath()
          ctx.arc(o.x + o.w / 2, o.y + o.h / 2, o.w / 2, 0, Math.PI * 2)
          ctx.fill()
        } else if (o.kind === 'drone') {
          ctx.fillStyle = '#fb923c'
          ctx.fillRect(o.x, o.y, o.w, o.h)
        } else {
          ctx.fillStyle = '#64748b'
          ctx.fillRect(o.x, o.y, o.w, o.h)
        }
        ctx.restore()

        // Circle-rect collision
        const closestX = Math.max(o.x, Math.min(balloon.x, o.x + o.w))
        const closestY = Math.max(o.y, Math.min(balloon.y, o.y + o.h))
        const dist = Math.hypot(balloon.x - closestX, balloon.y - closestY)
        if (dist < r - 2) {
          if (balloon.shield) {
            balloon.shield = false
            obstacles.splice(i, 1)
            continue
          }
          alive = false
          setGameOver(true)
          setBest((prev) => {
            const next = Math.max(prev, localScore)
            try {
              localStorage.setItem('osien-balloon-best', String(next))
            } catch (err) {
              void err
            }
            return next
          })
          return
        }
      }

      // Draw Balloon string
      ctx.strokeStyle = 'rgba(226, 232, 240, 0.65)'
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.moveTo(balloon.x, balloon.y + r)
      ctx.quadraticCurveTo(balloon.x - balloon.vx * 2, balloon.y + r + 14, balloon.x, balloon.y + r + 24)
      ctx.stroke()

      // Draw Balloon body
      ctx.fillStyle = isDouble ? '#facc15' : '#ef4444'
      ctx.beginPath()
      ctx.ellipse(balloon.x, balloon.y, r * 0.88, r * 1.08, 0, 0, Math.PI * 2)
      ctx.fill()

      // Balloon highlight
      ctx.fillStyle = 'rgba(255,255,255,0.35)'
      ctx.beginPath()
      ctx.ellipse(balloon.x - r * 0.3, balloon.y - r * 0.3, r * 0.2, r * 0.34, -0.3, 0, Math.PI * 2)
      ctx.fill()

      // Shield aura
      if (balloon.shield) {
        ctx.strokeStyle = '#38bdf8'
        ctx.lineWidth = 2.5
        ctx.beginPath()
        ctx.arc(balloon.x, balloon.y, r + 6, 0, Math.PI * 2)
        ctx.stroke()
      }

      raf = requestAnimationFrame(step)
    }

    raf = requestAnimationFrame(step)
    return () => {
      alive = false
      cancelAnimationFrame(raf)
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('keyup', onKeyUp)
      canvas.removeEventListener('mousemove', onMouseMove)
      canvas.removeEventListener('mouseleave', onMouseLeave)
    }
  }, [runSeed, paused])

  const restart = () => {
    setScore(0)
    setGameOver(false)
    setPaused(false)
    setActivePowers([])
    setRunSeed((s) => s + 1)
  }

  return (
    <section className="extreme-shell" style={{ marginBottom: 14 }}>
      <div className="extreme-head">
        <div className="extreme-title">
          <span className={`live-dot ${gameOver ? 'live-dot-idle' : ''}`}/>
          <div>
            <strong>Balloon Dodge Mini-Game {activeTaskLabel ? `· ${activeTaskLabel}` : ''}</strong>
            <small>Steer with Mouse or Arrow/WASD keys · Collect Shield (S), Slow-Mo (T), 2x Magnet (2x), Mini (M) &amp; Stars (★)</small>
          </div>
        </div>
        <div className="export-actions">
          <span className="badge sev-info">Altitude: {score}m</span>
          <span className="badge sev-low">Best: {best}m</span>
          {activePowers.map((p) => (
            <span key={p} className="badge sev-medium">{p}</span>
          ))}
          <button className="filter-button" onClick={() => setPaused((p) => !p)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button className="filter-button" onClick={restart}>Restart</button>
          {onClose && <button className="filter-button" onClick={onClose}>Hide Game</button>}
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'center', marginTop: 10, position: 'relative' }}>
        <canvas
          ref={canvasRef}
          width={620}
          height={250}
          style={{ borderRadius: 10, border: '1px solid rgba(148,163,184,0.22)', background: '#090d16', cursor: 'ew-resize', maxWidth: '100%' }}
        />
        {gameOver && (
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(9, 13, 22, 0.78)',
            borderRadius: 10,
            gap: 8,
          }}>
            <strong>Balloon Popped at {score}m! (Best: {best}m)</strong>
            <button className="primary" onClick={restart}>Fly Again</button>
          </div>
        )}
      </div>
    </section>
  )
}
