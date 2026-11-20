import { useEffect, useMemo, useState } from 'react'
import { Activity, ArrowUpRight, Bug, Check, ChevronDown, CircleHelp, Code2, Download, ExternalLink, Eye, FileCode2, Folder, Gauge, GitBranch, Globe2, History, Layers3, Play, Plus, RefreshCw, Search, Shield, ShieldCheck, SlidersHorizontal, Terminal, Trash2, X } from 'lucide-react'
import './App.css'
import './Working.css'
import './UIOverrides.css'

type Kind = 'Website' | 'Software' | 'API / backend' | 'Mobile app' | 'Library' | 'Data / ML' | 'Cloud / DevOps' | 'Blockchain / Web3' | 'Desktop / Electron' | 'CLI / Automation'
type AiAssessment = { verdict: 'likely_real' | 'likely_false_positive' | 'uncertain'; confidence: number; rationale: string; evidence: string; reviewAdvice: string; model: string; reviewedAt: string }
type Finding = { id: string; title: string; severity: string; file: string; line: number; excerpt: string; ruleId?: string; cwe?: string; hint?: string; confidence?: string; reason?: string; isNew?: boolean; fixed?: boolean; aiAssessment?: AiAssessment; aiReviewError?: string }
type AiProviderId = 'local' | 'cloud-codex' | 'cloud-claude' | 'cloud-opencode' | 'cloud-pi'
type AiConfig = { provider: AiProviderId; model: string; codexConnected?: boolean; claudeConnected?: boolean; opencodeConnected?: boolean; piConnected?: boolean; connectedByProvider?: Record<string, boolean>; hasApiKey: boolean; apiKeyMasked: string; localModels: string[]; localAvailable?: boolean; codexModels: string[]; claudeModels?: string[]; opencodeModels?: string[]; piModels?: string[] }
type FindingFixPreview = { projectId: string; findingId: string; file: string; explanation: string; target: string; replacement: string; model: string }
type TestTarget = { file: string; runner: 'node' | 'npm' | 'pytest' | 'go' | 'cargo'; names?: string[]; command: string }
type SeverityCounts = { critical: number; high: number; medium: number; low: number; info: number }
type ScanHistoryEntry = { id: string; completedAt: string; score: number; filesScanned: number; findingsCount: number; durationMs?: number; severityCounts?: SeverityCounts }
type Scan = { id: string; completedAt: string; durationMs?: number; filesScanned: number; rulesEvaluated: number; rulesAvailable?: number; languagesScanned?: string[]; severityCounts?: SeverityCounts; scoreDelta?: number; findings: Finding[]; truncated: boolean; testCommand: string | null; testFiles?: TestTarget[]; testFilesTruncated?: boolean; testResults?: TestResult[]; score: number; testResult?: TestResult }
type TestResult = { file?: string; command: string; exitCode: number; output: string; durationMs?: number }
type Project = { id: string; name: string; root: string; kind: Kind; addedAt: string; latestRun: Scan | null; scanHistory?: ScanHistoryEntry[] }
type ContextLine = { number: number; text: string; isTarget: boolean }
type SourceContext = { context: string; lines?: ContextLine[]; totalLines: number }
type AiHealth = { available: boolean; modelInstalled: boolean; model: string; endpoint: string; models: string[]; message: string }
type Route = 'Projects' | 'Test runs' | 'Findings' | 'Security' | 'Rule catalog' | 'Environments' | 'Settings'
type CatalogRule = { id: string; title: string; severity: string; cwe: string; lang: string; category: string; hint: string; bad: string; good: string }
type CatalogPayload = { total: number; categories: string[]; rules: CatalogRule[] }
type SystemProfile = { cpuModel: string; cpuCores: number; totalMemGb: number; freeMemGb: number; tier: 'high' | 'balanced' | 'light'; maxSteps: number; stepDelayMs: number }
type ExtremeFinding = { ruleId: string; title: string; severity: string; cwe: string; detail: string }
type ExtremeStats = { pages: number; clicks: number; inputsFuzzed: number; findings: number }
type ExtremeState = {
  projectId: string
  projectName: string
  running: boolean
  step: number
  maxSteps: number
  url: string
  action: string
  targetLabel: string
  frameUrl: string
  stats: ExtremeStats
  logs: { level: string; text: string }[]
  findings: ExtremeFinding[]
  error?: string
}
type ConfirmState = {
  title: string
  body: string
  detail?: string
  confirmLabel: string
  tone: 'danger' | 'primary'
  onConfirm: () => Promise<void> | void
} | null
type WebRemediation = { url: string; issueCount: number; actions: { ruleId: string; severity: string; title: string; fix: string }[]; configs: Record<'nginx' | 'apache' | 'express' | 'nextjs' | 'vercel' | 'cloudflare', string> }
type Bridge = {
  pickFolder(): Promise<string | null>
  listProjects(): Promise<Project[]>
  addProject(p: { root: string; kind: Kind }): Promise<Project>
  cloneRepo(p: { url: string; kind: Kind }): Promise<Project>
  removeProject(id: string): Promise<Project>
  openProject(id: string): Promise<boolean>
  openDataFolder(): Promise<boolean>
  scanProject(id: string): Promise<Scan>
  generateWebRemediation?(id: string): Promise<WebRemediation>
  verifyFinding(p: { projectId: string; findingId: string }): Promise<AiAssessment>
  getFindingContext?(p: { projectId: string; findingId: string }): Promise<SourceContext>
  checkAiStatus?(): Promise<AiHealth>
  getAiConfig?(): Promise<AiConfig>
  saveAiConfig?(p: { provider: AiProviderId; model: string; apiKey?: string; clearApiKey?: boolean }): Promise<{ config: AiConfig; health: AiHealth }>
  connectCodex?(): Promise<{ config: AiConfig; health: AiHealth }>
  disconnectCodex?(): Promise<{ config: AiConfig; health: AiHealth }>
  connectProvider?(provider: AiProviderId): Promise<{ config: AiConfig; health: AiHealth }>
  disconnectProvider?(provider: AiProviderId): Promise<{ config: AiConfig; health: AiHealth }>
  generateFindingFix?(p: { projectId: string; findingId: string }): Promise<{ explanation: string; target: string; replacement: string; file: string; model: string }>
  applyFindingFix?(p: { projectId: string; findingId: string; file: string; target: string; replacement: string }): Promise<{ applied: boolean; file: string }>
  fixAllFindings?(p: { projectId: string }): Promise<{ total: number; fixed: number; failed: number }>
  onFixAllProgress?(cb: (p: { projectId: string; total: number; done: number; fixed: number; failed: number; currentTitle: string; state: string }) => void): () => void
  listRules?(): Promise<CatalogPayload>
  getSystemProfile?(): Promise<SystemProfile>
  startExtremeTest?(projectId: string): Promise<{ cancelled: boolean; stats: ExtremeStats }>
  stopExtremeTest?(projectId: string): Promise<boolean>
  onExtremeTestEvent?(cb: (ev: { projectId: string; type: string; [k: string]: unknown }) => void): () => void
  exportReport?(p: { projectId?: string; format: 'sarif' | 'markdown' | 'json' }): Promise<{ saved: boolean; filePath: string | null }>
  runProjectTests(id: string): Promise<TestResult>
  runProjectTestFile(p: { projectId: string; file: string }): Promise<TestResult>
  cancelAiReview?(projectId: string): Promise<boolean>
  aiReviewStatus?(): Promise<Record<string, { total: number; done: number; scanId: string }>>
  onAiReviewProgress?(cb: (p: ReviewProgress) => void): () => void
}
type ReviewProgress = { projectId: string; scanId: string; total: number; done: number; state: 'running' | 'done' | 'cancelled' | 'idle' }
declare global { interface Window { deepcheck?: Bridge } }

const kinds: { name: Kind; detail: string; Icon: typeof Globe2 }[] = [
  { name: 'Website', detail: 'Web UI, accessibility, security', Icon: Globe2 },
  { name: 'Software', detail: 'Application source and dependencies', Icon: Code2 },
  { name: 'API / backend', detail: 'Services, auth, and data handling', Icon: Terminal },
  { name: 'Mobile app', detail: 'Mobile source and configuration', Icon: Layers3 },
  { name: 'Library', detail: 'Public API and package configuration', Icon: FileCode2 },
  { name: 'Data / ML', detail: 'Pipelines, data, and model code', Icon: Activity },
  { name: 'Cloud / DevOps', detail: 'Docker, Kubernetes, Terraform, CI/CD', Icon: Shield },
  { name: 'Blockchain / Web3', detail: 'Smart contracts, Solidity, wallets', Icon: ShieldCheck },
  { name: 'Desktop / Electron', detail: 'BrowserWindow isolation, IPC, preload', Icon: Code2 },
  { name: 'CLI / Automation', detail: 'Shell safety, argv, temp files', Icon: Terminal },
]
const icons: Record<Kind, typeof Globe2> = Object.fromEntries(kinds.map(({ name, Icon }) => [name, Icon])) as Record<Kind, typeof Globe2>
const nav: { name: Route; Icon: typeof Layers3 }[] = [
  { name: 'Projects', Icon: Layers3 },
  { name: 'Test runs', Icon: Activity },
  { name: 'Findings', Icon: Bug },
  { name: 'Security', Icon: Shield },
  { name: 'Rule catalog', Icon: ShieldCheck },
  { name: 'Environments', Icon: Terminal },
  { name: 'Settings', Icon: SlidersHorizontal },
]
const dateLabel = (value?: string | null) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Not scanned'

function App() {
  const bridge = window.deepcheck
  const [projects, setProjects] = useState<Project[]>([])
  const [route, setRoute] = useState<Route>('Projects')
  const [loading, setLoading] = useState(() => Boolean(bridge))
  const [dialog, setDialog] = useState(false)
  const [source, setSource] = useState<'folder' | 'repo' | 'url'>('folder')
  const [url, setUrl] = useState('')
  const [folder, setFolder] = useState('')
  const [kind, setKind] = useState<Kind | null>(null)
  const [busy, setBusy] = useState('')
  const [message, setMessage] = useState(() => bridge ? '' : 'DeepCheck requires its Windows desktop app.')
  const [filter, setFilter] = useState('')
  const [category, setCategory] = useState('All categories')
  const [page, setPage] = useState(0)
  const [selectedProject, setSelectedProject] = useState<Project | null>(null)
  const [workspaceOpen, setWorkspaceOpen] = useState(false)
  const [help, setHelp] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)
  const [confirmState, setConfirmState] = useState<ConfirmState>(null)
  const [aiHealth, setAiHealth] = useState<AiHealth | null>(null)
  const [aiConfig, setAiConfig] = useState<AiConfig | null>(null)
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [fixPreview, setFixPreview] = useState<FindingFixPreview | null>(null)
  const [fixAllState, setFixAllState] = useState<{ projectId: string; total: number; done: number; fixed: number; failed: number; currentTitle: string; state: string } | null>(null)
  const [reviews, setReviews] = useState<Record<string, ReviewProgress>>({})
  const [catalog, setCatalog] = useState<CatalogPayload | null>(null)
  const [sysProfile, setSysProfile] = useState<SystemProfile | null>(null)
  const [extremeChoice, setExtremeChoice] = useState<Project | null>(null)
  const [extreme, setExtreme] = useState<ExtremeState | null>(null)
  const [webFixPack, setWebFixPack] = useState<WebRemediation | null>(null)
  const [webFixPlatform, setWebFixPlatform] = useState<'nginx' | 'apache' | 'express' | 'nextjs' | 'vercel' | 'cloudflare'>('nginx')
  const [webFixCopied, setWebFixCopied] = useState(false)

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setDialog(false)
        setHelp(false)
        setConfirmClear(false)
        setConfirmState(null)
        setWorkspaceOpen(false)
        return
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        const input = document.querySelector<HTMLInputElement>('.search input')
        input?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  useEffect(() => {
    if (!bridge?.onAiReviewProgress) return undefined
    const off = bridge.onAiReviewProgress(p => {
      setReviews(current => {
        const next = { ...current }
        if (p.state === 'running') next[p.projectId] = p
        else delete next[p.projectId]
        return next
      })
      bridge.listProjects().then(fresh => {
        setProjects(fresh)
        setSelectedProject(current => current ? fresh.find(item => item.id === current.id) || null : null)
      }).catch(() => undefined)
    })
    return off
  }, [bridge])

  useEffect(() => {
    if (!bridge) return undefined
    let active = true
    bridge.listProjects().then(list => { if (active) setProjects(list) }).catch(e => { if (active) setMessage(errorText(e)) }).finally(() => { if (active) setLoading(false) })
    if (bridge.checkAiStatus) {
      bridge.checkAiStatus().then(status => { if (active) setAiHealth(status) }).catch(() => undefined)
    }
    return () => { active = false }
  }, [bridge])

  const findings = useMemo(() => projects.flatMap(p => (p.latestRun?.findings || []).map(f => ({ ...f, projectName: p.name, projectId: p.id }))), [projects])
  const shown = useMemo(() => projects.filter(p => `${p.name} ${p.kind} ${p.root}`.toLowerCase().includes(filter.toLowerCase()) && (category === 'All categories' || p.kind === category)), [projects, filter, category])
  const pages = Math.max(1, Math.ceil(shown.length / 8))
  const pageRows = shown.slice(page * 8, page * 8 + 8)
  const totalChecks = projects.reduce((n, p) => n + (p.latestRun?.rulesEvaluated || 0), 0)
  const scannedProjects = projects.filter(p => p.latestRun)
  const average = scannedProjects.length ? Math.round(scannedProjects.reduce((n, p) => n + (p.latestRun?.score || 0), 0) / scannedProjects.length) : null

  const reload = async () => {
    const fresh = await bridge!.listProjects()
    setProjects(fresh)
    setSelectedProject(current => current ? fresh.find(p => p.id === current.id) || null : null)
    return fresh
  }
  const refreshAll = async () => {
    setBusy('refresh')
    setMessage('')
    try {
      await reload()
      if (bridge?.checkAiStatus) setAiHealth(await bridge.checkAiStatus())
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const scan = async (p: Project) => {
    const resetRun = (run: Scan): Scan => ({ ...run, testResult: undefined, findings: run.findings.map(({ aiAssessment: _assessment, aiReviewError: _error, ...finding }) => finding) })
    setBusy(`scan:${p.id}`)
    setMessage('')
    setProjects(current => current.map(item => item.id === p.id && item.latestRun ? { ...item, latestRun: resetRun(item.latestRun) } : item))
    setSelectedProject(current => current?.id === p.id && current.latestRun ? { ...current, latestRun: resetRun(current.latestRun) } : current)
    try {
      await bridge!.scanProject(p.id)
      const fresh = await reload()
      setSelectedProject(fresh.find(item => item.id === p.id) || null)
      setRoute('Test runs')
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const verifyFinding = async (projectId: string, findingId: string) => {
    setBusy(`verify:${findingId}`)
    setMessage('')
    try {
      await bridge!.verifyFinding({ projectId, findingId })
      await reload()
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const exportReport = async (format: 'sarif' | 'markdown' | 'json', projectId?: string) => {
    if (!bridge?.exportReport) return
    setBusy(`export:${format}`)
    setMessage('')
    try {
      const res = await bridge.exportReport({ projectId, format })
      if (res.saved && res.filePath) setMessage(`Report exported to ${res.filePath}`)
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const runTests = async (p: Project) => {
    if (!p.latestRun?.testCommand) return
    const cmd = p.latestRun.testCommand
    setConfirmState({
      title: `Run ${p.name} test suite?`,
      body: 'This executes the project’s own test script on this device.',
      detail: `${cmd} · ${p.root}`,
      confirmLabel: 'Run full suite',
      tone: 'primary',
      onConfirm: async () => {
        setBusy(`test:${p.id}`)
        setMessage('')
        try {
          await bridge!.runProjectTests(p.id)
          const fresh = await reload()
          setSelectedProject(fresh.find(item => item.id === p.id) || null)
          setRoute('Test runs')
        } catch (e) {
          setMessage(errorText(e))
        } finally {
          setBusy('')
        }
      },
    })
  }
  const runTestFile = async (p: Project, target: TestTarget) => {
    setConfirmState({
      title: `Run ${target.file}?`,
      body: 'Test code can modify files or access the network. Only run tests from projects you trust.',
      detail: target.command,
      confirmLabel: 'Run test file',
      tone: 'primary',
      onConfirm: async () => {
        setBusy(`testfile:${p.id}:${target.file}`)
        setMessage('')
        try {
          await bridge!.runProjectTestFile({ projectId: p.id, file: target.file })
          const fresh = await reload()
          setSelectedProject(fresh.find(item => item.id === p.id) || null)
        } catch (e) {
          setMessage(errorText(e))
        } finally {
          setBusy('')
        }
      },
    })
  }
  useEffect(() => {
    if (!bridge?.listRules) return
    void bridge.listRules().then(setCatalog).catch((e) => setMessage(errorText(e)))
  }, [bridge])
  useEffect(() => {
    if (!bridge?.getSystemProfile) return
    void bridge.getSystemProfile().then(setSysProfile).catch((e) => setMessage(errorText(e)))
  }, [bridge])
  useEffect(() => {
    if (!bridge?.getAiConfig) return
    void bridge.getAiConfig().then(setAiConfig).catch((e) => setMessage(errorText(e)))
  }, [bridge])
  const CLOUD_PROVIDER_INFO: Record<Exclude<AiProviderId, 'local'>, { label: string; short: string; connectBtn: string; connectedTitle: string; connectTitle: string; connectedDesc: string; connectDesc: string; placeholder: string }> = {
    'cloud-codex': {
      label: 'Codex (OpenAI)',
      short: 'Codex',
      connectBtn: 'Connect Codex (ChatGPT)',
      connectedTitle: 'ChatGPT account connected ✓',
      connectTitle: 'Sign in with your ChatGPT account',
      connectedDesc: 'Using your ChatGPT subscription via Codex OAuth (~/.codex/auth.json) — no API key needed.',
      connectDesc: 'Opens your browser to sign in with ChatGPT (Plus / Pro / Team) — no API key required.',
      placeholder: 'sk-...',
    },
    'cloud-claude': {
      label: 'Claude (Anthropic)',
      short: 'Claude',
      connectBtn: 'Connect Claude Code',
      connectedTitle: 'Claude Code account connected ✓',
      connectTitle: 'Sign in with Claude Code',
      connectedDesc: 'Using your Claude subscription via Claude Code CLI (~/.claude/.credentials.json) — no API key needed.',
      connectDesc: 'Opens your browser to sign in with your Claude Pro/Max/Team subscription — no API key required.',
      placeholder: 'sk-ant-...',
    },
    'cloud-opencode': {
      label: 'OpenCode',
      short: 'OpenCode',
      connectBtn: 'Connect OpenCode',
      connectedTitle: 'OpenCode account connected ✓',
      connectTitle: 'Sign in with OpenCode CLI',
      connectedDesc: 'Using your OpenCode CLI credentials (~/.local/share/opencode/auth.json).',
      connectDesc: 'Opens your browser to sign in with OpenCode — no API key required.',
      placeholder: 'oc-...',
    },
    'cloud-pi': {
      label: 'Pi Agent',
      short: 'Pi',
      connectBtn: 'Connect Pi Agent',
      connectedTitle: 'Pi Agent connected ✓',
      connectTitle: 'Sign in with Pi Coding Agent',
      connectedDesc: 'Using your Pi Agent credentials (~/.pi/agent/auth.json).',
      connectDesc: 'Opens your browser to sign in with Pi Coding Agent — no API key required.',
      placeholder: 'sk-...',
    },
  }
  const isCloudAi = Boolean(aiConfig && aiConfig.provider !== 'local')
  const cloudModelsFor = (p: AiProviderId): string[] => {
    if (!aiConfig) return []
    if (p === 'cloud-claude') return aiConfig.claudeModels || ['claude-sonnet-4-5']
    if (p === 'cloud-opencode') return aiConfig.opencodeModels || ['opencode/big-pickle']
    if (p === 'cloud-pi') return aiConfig.piModels || ['claude-sonnet-4-5']
    if (p === 'cloud-codex') return aiConfig.codexModels || ['gpt-5.2-codex']
    return aiConfig.localModels || []
  }
  const isProviderConnected = (p: AiProviderId): boolean => {
    if (!aiConfig || p === 'local') return false
    if (aiConfig.connectedByProvider && typeof aiConfig.connectedByProvider[p] === 'boolean') return aiConfig.connectedByProvider[p]
    if (p === 'cloud-codex') return Boolean(aiConfig.codexConnected)
    if (p === 'cloud-claude') return Boolean(aiConfig.claudeConnected)
    if (p === 'cloud-opencode') return Boolean(aiConfig.opencodeConnected)
    if (p === 'cloud-pi') return Boolean(aiConfig.piConnected)
    return false
  }
  const saveAiSettings = async (nextProvider: AiProviderId, nextModel: string, newKey?: string, clearApiKey?: boolean) => {
    if (!bridge?.saveAiConfig) return
    setBusy('save-ai')
    setMessage('')
    try {
      const res = await bridge.saveAiConfig({ provider: nextProvider, model: nextModel, apiKey: newKey, clearApiKey })
      setAiConfig(res.config)
      setAiHealth(res.health)
      if (newKey) setApiKeyInput('')
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const connectCloudProvider = async (providerId: Exclude<AiProviderId, 'local'>) => {
    setBusy('connect-provider')
    setMessage('')
    try {
      const res = bridge?.connectProvider
        ? await bridge.connectProvider(providerId)
        : await bridge!.connectCodex!()
      setAiConfig(res.config)
      setAiHealth(res.health)
      setMessage(`${CLOUD_PROVIDER_INFO[providerId].short} connected! "Fix finding" is now unlocked.`)
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const disconnectCloudProvider = async (providerId: Exclude<AiProviderId, 'local'>) => {
    setBusy('connect-provider')
    setMessage('')
    try {
      const res = bridge?.disconnectProvider
        ? await bridge.disconnectProvider(providerId)
        : await bridge!.disconnectCodex!()
      setAiConfig(res.config)
      setAiHealth(res.health)
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const requestFix = async (projectId: string, findingId: string) => {
    if (!bridge?.generateFindingFix) return
    setBusy(`fix:${findingId}`)
    setMessage('')
    try {
      const res = await bridge.generateFindingFix({ projectId, findingId })
      setFixPreview({ projectId, findingId, ...res })
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  useEffect(() => {
    if (!bridge?.onFixAllProgress) return
    return bridge.onFixAllProgress((p) => {
      setFixAllState(p.state === 'done' ? null : p)
    })
  }, [bridge])
  const fixAllWithAi = (p: Project) => {
    if (!bridge?.fixAllFindings || !p.latestRun) return
    const count = p.latestRun.findings.filter(f => !f.fixed && ['critical', 'high', 'medium'].includes(f.severity)).length
    if (!count) {
      setMessage('No unfixed critical, high, or medium findings remain in this project.')
      return
    }
    setConfirmState({
      title: `Fix ${count} findings in ${p.name} with Codex?`,
      body: 'Codex will generate minimal patches and apply them to your project files, then re-scan.',
      detail: `${aiConfig?.model || 'Codex'} · ${p.root}`,
      confirmLabel: `Fix ${count} findings`,
      tone: 'primary',
      onConfirm: async () => {
        setBusy(`fixall:${p.id}`)
        setMessage('')
        try {
          const res = await bridge.fixAllFindings!({ projectId: p.id })
          await bridge.scanProject(p.id)
          const fresh = await reload()
          setSelectedProject(fresh.find(item => item.id === p.id) || null)
          setMessage(`Codex fixed ${res.fixed} of ${res.total} finding(s)${res.failed ? ` (${res.failed} skipped)` : ''} and re-scanned ${p.name}.`)
        } catch (e) {
          setMessage(errorText(e))
        } finally {
          setBusy('')
          setFixAllState(null)
        }
      },
    })
  }
  const confirmApplyFix = async () => {
    if (!fixPreview || !bridge?.applyFindingFix) return
    setBusy(`apply:${fixPreview.findingId}`)
    setMessage('')
    try {
      await bridge.applyFindingFix({
        projectId: fixPreview.projectId,
        findingId: fixPreview.findingId,
        file: fixPreview.file,
        target: fixPreview.target,
        replacement: fixPreview.replacement,
      })
      await reload()
      setMessage(`Fix applied to ${fixPreview.file}. Re-scan to verify the updated score.`)
      setFixPreview(null)
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  useEffect(() => {
    if (!bridge?.onExtremeTestEvent) return
    return bridge.onExtremeTestEvent((ev) => {
      setExtreme((prev) => {
        if (!prev || prev.projectId !== ev.projectId) return prev
        if (ev.type === 'frame' && typeof ev.dataUrl === 'string') {
          return { ...prev, frameUrl: ev.dataUrl }
        }
        if (ev.type === 'log' && typeof ev.text === 'string') {
          const nextLogs = [{ level: String(ev.level || 'info'), text: ev.text }, ...prev.logs].slice(0, 60)
          return { ...prev, logs: nextLogs }
        }
        if (ev.type === 'finding' && ev.finding) {
          return { ...prev, findings: [ev.finding as ExtremeFinding, ...prev.findings] }
        }
        if (ev.type === 'step') {
          const stats = (ev.stats as ExtremeStats) || prev.stats
          const label = typeof ev.targetLabel === 'string' && ev.targetLabel ? ` · ${ev.targetLabel}` : ''
          const stepLog = { level: 'step', text: `[${ev.step}/${ev.maxSteps}] ${ev.action}${label}` }
          return {
            ...prev,
            step: Number(ev.step || prev.step),
            maxSteps: Number(ev.maxSteps || prev.maxSteps),
            url: String(ev.url || prev.url),
            action: String(ev.action || ''),
            targetLabel: String(ev.targetLabel || ''),
            stats,
            logs: [stepLog, ...prev.logs].slice(0, 60),
          }
        }
        if (ev.type === 'done') {
          return { ...prev, running: false, stats: (ev.stats as ExtremeStats) || prev.stats }
        }
        return prev
      })
    })
  }, [bridge])
  const startExtremeTest = async (_p: Project) => {
    setExtremeChoice(null)
    setMessage('Extreme Live Sandbox Test is currently under development and locked.')
  }
  const stopExtremeTest = async (projectId: string) => {
    try {
      await bridge?.stopExtremeTest?.(projectId)
    } catch (e) {
      setMessage(errorText(e))
    }
  }
  const openWebFix = async (p: Project) => {
    if (!bridge?.generateWebRemediation) return
    setBusy(`webfix:${p.id}`)
    try {
      const pack = await bridge.generateWebRemediation(p.id)
      setWebFixPack(pack)
      setWebFixCopied(false)
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const triggerProjectTest = (p: Project) => {
    if (p.kind === 'Website' && bridge?.startExtremeTest && !/^https?:\/\//i.test(p.root)) {
      setExtremeChoice(p)
      return
    }
    void scan(p)
  }
  const addProject = async () => {
    const effectiveKind = kind || (source === 'url' ? 'Website' : null)
    if (!effectiveKind) return
    setBusy('add')
    setMessage('')
    try {
      const p = source === 'repo'
        ? await bridge!.cloneRepo({ url, kind: effectiveKind })
        : source === 'url'
          ? await bridge!.addProject({ root: url.trim(), kind: 'Website' })
          : await bridge!.addProject({ root: folder, kind: effectiveKind })
      setProjects(current => [p, ...current])
      setDialog(false)
      setKind(null)
      setFolder('')
      setUrl('')
      if (source === 'url') {
        void scan(p)
        return
      }
      if (p.kind === 'Website' && bridge?.startExtremeTest) {
        setExtremeChoice(p)
        return
      }
      if (source === 'repo') {
        setBusy(`scan:${p.id}`)
        try {
          const result = await bridge!.scanProject(p.id)
          const refreshed = await bridge!.listProjects()
          setProjects(refreshed)
          setSelectedProject(refreshed.find(item => item.id === p.id) || { ...p, latestRun: result })
          setRoute('Test runs')
          setMessage('Repository cloned and scanned. Review detected test command before running tests.')
        } catch (e) {
          setMessage(errorText(e))
        }
      }
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const removeProject = (p: Project) => {
    setConfirmState({
      title: `Remove ${p.name} from OSIEN Probe?`,
      body: 'OSIEN Probe will forget this connected project entry and its scan history. Your files on disk will not be deleted.',
      detail: p.root,
      confirmLabel: 'Remove project',
      tone: 'danger',
      onConfirm: async () => {
        try {
          await bridge!.removeProject(p.id)
          setProjects(await bridge!.listProjects())
          if (selectedProject?.id === p.id) setSelectedProject(null)
        } catch (e) {
          setMessage(errorText(e))
        }
      },
    })
  }
  const clearProjects = async () => {
    for (const p of projects) await bridge!.removeProject(p.id)
    setProjects([])
    setConfirmClear(false)
    setRoute('Projects')
  }
  const scanAll = async () => {
    if (!projects.length) return
    setBusy('scan-all')
    setMessage('')
    try {
      for (const p of projects) await bridge!.scanProject(p.id)
      setProjects(await bridge!.listProjects())
    } catch (e) {
      setMessage(errorText(e))
    } finally {
      setBusy('')
    }
  }
  const navTo = (item: Route) => { setRoute(item); setPage(0); setMessage('') }
  const securityCount = findings.filter(f => ['critical', 'high'].includes(f.severity)).length

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><img className="brand-logo" src="./logo.png" alt="OSIEN Probe"/><span>OSIEN Probe</span></div>
      <div className="workspace-wrap">
        <button className="workspace" onClick={() => setWorkspaceOpen(v => !v)}>
          <div className="workspace-icon"><Folder size={15}/></div>
          <div><strong>Local workspace</strong><small>{projects.length} {projects.length === 1 ? 'project' : 'projects'}</small></div>
          <ChevronDown size={15}/>
        </button>
        {workspaceOpen && <div className="workspace-menu">
          <div className="workspace-menu-title">Local workspace</div>
          <div className="workspace-menu-row"><span>Projects</span><b>{projects.length}</b></div>
          <div className="workspace-menu-row"><span>Scanned files</span><b>{projects.reduce((n, p) => n + (p.latestRun?.filesScanned || 0), 0).toLocaleString()}</b></div>
          <button onClick={() => { setWorkspaceOpen(false); void bridge!.openDataFolder() }}>Open data folder</button>
          <button onClick={() => { setWorkspaceOpen(false); void refreshAll() }}>Refresh projects</button>
          <button onClick={() => { setWorkspaceOpen(false); setRoute('Settings') }}>Settings</button>
        </div>}
      </div>
      <div className="nav-label">Workspace</div>
      <nav>
        {nav.slice(0, 4).map(({ name, Icon }) => <button key={name} className={route === name ? 'active' : ''} onClick={() => navTo(name)}>
          <Icon size={17}/>{name}
          {name === 'Projects' && <span className="nav-count">{projects.length}</span>}
          {name === 'Findings' && <span className="nav-count">{findings.length}</span>}
          {name === 'Security' && securityCount > 0 && <span className="nav-count issue">{securityCount}</span>}
        </button>)}
      </nav>
      <div className="nav-label tools-label">Tools</div>
      <nav>{nav.slice(4).map(({ name, Icon }) => <button key={name} className={route === name ? 'active' : ''} onClick={() => navTo(name)}><Icon size={17}/>{name}</button>)}</nav>
      <div className="side-bottom">
        <div className="plan">
          <div className="plan-top"><span>Scanned source files</span><span>{projects.reduce((n, p) => n + (p.latestRun?.filesScanned || 0), 0).toLocaleString()}</span></div>
          <small>Across connected projects</small>
        </div>
        <div className="profile">
          <div className="avatar"><img className="avatar-logo" src="./logo.png" alt="OSIEN Probe"/></div>
          <div><strong>Local analysis</strong><small>{aiHealth?.modelInstalled ? `AI ready (${aiHealth.model})` : 'Data stays on this device'}</small></div>
        </div>
      </div>
    </aside>
    <main className="main-area">
      <header className="topbar">
        <div className="breadcrumbs">Local workspace <span>/</span> <b>{route}</b></div>
        <div className="top-actions">
          <button
            type="button"
            className={`ai-pill ${aiHealth?.modelInstalled ? 'ai-pill-ready' : ''}`}
            onClick={() => setRoute('Environments')}
            title={aiHealth?.message || 'Inspect local AI engine status'}
          >
            <i/>
            <span>{aiHealth?.modelInstalled ? `AI · ${aiHealth.model}` : 'Static engine'}</span>
          </button>
          <button className="icon-button" aria-label="Help" onClick={() => setHelp(true)}><CircleHelp size={17}/></button>
          <span className="top-divider"/>
          <span className="local-indicator"><i/> On this device</span>
        </div>
      </header>
      <section className="content">
        <div className="page-heading">
          <div>
            <div className="eyebrow"><span className="live-dot"/> LOCAL CODE ANALYSIS</div>
            <h1>{route}</h1>
            <p>{pageDescription(route)}</p>
          </div>
          <div className="heading-actions">
            {selectedProject && route === 'Test runs' && <button className="filter-button" onClick={() => setSelectedProject(null)}>Show all projects</button>}
            {route === 'Projects' && projects.length > 1 && <button className="filter-button" onClick={() => void scanAll()} disabled={!!busy}><Play size={13}/> {busy === 'scan-all' ? 'Scanning all…' : 'Scan all'}</button>}
            <button className="filter-button" onClick={() => void refreshAll()} disabled={!!busy}><RefreshCw size={14} className={busy === 'refresh' ? 'spinning' : ''}/> Refresh data</button>
            {route === 'Projects' && <button className="primary" onClick={() => { setDialog(true); setMessage('') }}><Plus size={17}/> Add project</button>}
          </div>
        </div>
        {message && <div className="global-message" role="alert">{message}<button className="icon-button" onClick={() => setMessage('')}><X size={15}/></button></div>}
        {fixAllState && <div className="review-banner">
          <RefreshCw size={13} className="spinning"/>
          <span>Codex is fixing findings ({fixAllState.done}/{fixAllState.total} · {fixAllState.fixed} applied): {fixAllState.currentTitle}</span>
        </div>}
        {Object.values(reviews).map(r => {
          const name = projects.find(p => p.id === r.projectId)?.name || 'project'
          return <div className="review-banner" key={r.projectId}>
            <RefreshCw size={13} className="spinning"/>
            <span>Local AI is double-checking {name}'s critical/high findings in the background · {r.done}/{r.total} done. Results are already usable.</span>
            <button className="filter-button" onClick={() => void bridge?.cancelAiReview?.(r.projectId)}>Stop AI review</button>
          </div>
        })}
        {loading ? <div className="empty-state">Loading saved projects…</div> : route === 'Projects' ? <>
          <div className="metrics">
            <Metric label="Connected projects" value={projects.length.toString()} note="Saved on this device"/>
            <Metric label="Checks evaluated" value={totalChecks.toLocaleString()} note="From completed scans"/>
            <Metric label="Open findings" value={findings.length.toString()} note={securityCount ? `${securityCount} critical/high severity` : 'Latest scan per project'}/>
            <Metric label="Average scan score" value={average === null ? '—' : `${average}/100`} note={average === null ? 'Run a scan to calculate' : 'From completed scans'} featured/>
          </div>
          <div className="section-heading">
            <div><h2>Your projects</h2><span>{shown.length} shown</span></div>
            <div className="list-actions">
              <label className="search"><Search size={15}/><input aria-label="Search projects" placeholder="Search projects" value={filter} onChange={e => { setFilter(e.target.value); setPage(0) }}/></label>
              <select className="filter-button" aria-label="Filter by category" value={category} onChange={e => { setCategory(e.target.value); setPage(0) }}>
                <option>All categories</option>
                {kinds.map(k => <option key={k.name}>{k.name}</option>)}
              </select>
            </div>
          </div>
          <div className="project-table">
            <div className="table-head"><span>Project</span><span>Category</span><span>Latest scan</span><span>Checks</span><span>Score</span><span>Actions</span></div>
            {pageRows.map(p => {
              const Icon = icons[p.kind]
              const delta = p.latestRun?.scoreDelta
              return <div className="project-row" key={p.id}>
                <button className="project-name project-open" onClick={() => void bridge!.openProject(p.id)} title="Open project folder">
                  <div className="project-icon icon-code"><Icon size={17}/></div>
                  <div><strong>{p.name}</strong><small>{p.root}</small></div>
                </button>
                <div><span className="category"><span className="category-dot"/>{p.kind}</span></div>
                <div className="run-state"><span className={`state-dot ${p.latestRun ? '' : 'queued'}`}/><span>{dateLabel(p.latestRun?.completedAt)}</span></div>
                <div className="checks-count">{p.latestRun ? p.latestRun.rulesEvaluated.toLocaleString() : '—'} <span>{p.latestRun ? 'checks' : ''}</span></div>
                <div className="score-cell">
                  {p.latestRun ? <>
                    <div className={`score-ring ${p.latestRun.score >= 80 ? 'score-good' : p.latestRun.score >= 50 ? 'score-warn' : 'score-bad'}`}><span>{p.latestRun.score}</span></div>
                    <span className="score-label">{typeof delta === 'number' && delta !== 0 ? `${delta > 0 ? '+' : ''}${delta}` : 'Score'}</span>
                  </> : <span className="muted">—</span>}
                </div>
                <div className="row-actions">
                  <button className="row-action" aria-label={`Scan ${p.name}`} title={p.kind === 'Website' ? 'Choose Traditional or Extreme Sandbox Test' : 'Run source scan'} disabled={busy === `scan:${p.id}`} onClick={() => triggerProjectTest(p)}>
                    {busy === `scan:${p.id}` ? <RefreshCw size={14} className="spinning"/> : <Play size={14}/>}
                  </button>
                  <button className="row-action danger-action" aria-label={`Remove ${p.name}`} title="Remove project" onClick={() => void removeProject(p)}>
                    <Trash2 size={14}/>
                  </button>
                </div>
              </div>
            })}
            {!pageRows.length && <div className="empty-state">{projects.length ? 'No projects match these filters' : <>No projects connected yet<br/><button className="text-action" onClick={() => setDialog(true)}>Add a folder or Git repository</button></>}</div>}
          </div>
          <div className="table-foot">
            <span>Page {page + 1} of {pages}</span>
            <div>
              <button disabled={page === 0} onClick={() => setPage(n => Math.max(0, n - 1))}>Previous</button>
              <button disabled={page + 1 >= pages} onClick={() => setPage(n => Math.min(pages - 1, n + 1))}>Next</button>
            </div>
          </div>
          <div className="bottom-note">
            <div className="note-icon"><Gauge size={18}/></div>
            <div><strong>Scans report what they actually inspect</strong><p>Source checks are static analysis; your test suite only runs when you choose Run tests</p></div>
            <button onClick={() => setHelp(true)}>Scan details <ArrowUpRight size={14}/></button>
          </div>
        </> : route === 'Findings' || route === 'Security' ? (
          <FindingList
            findings={route === 'Security' ? findings.filter(f => ['critical', 'high'].includes(f.severity)) : findings}
            projects={projects}
            busy={busy}
            bridge={bridge}
            isCloudCodex={isCloudAi}
            onVerify={verifyFinding}
            onFix={requestFix}
            onExport={exportReport}
            onOpen={p => { setSelectedProject(p); setRoute('Test runs') }}
          />
        ) : route === 'Test runs' ? (
          <>
            {extreme && <ExtremeSandboxView extreme={extreme} sysProfile={sysProfile} onStop={stopExtremeTest} onClose={() => setExtreme(null)}/>}
            <Runs projects={projects} selected={selectedProject} busy={busy} isCloudCodex={isCloudAi} onScan={scan} onExtreme={startExtremeTest} onFixAll={fixAllWithAi} onWebFix={openWebFix} onTest={runTests} onRunFile={runTestFile} onExport={exportReport}/>
          </>
        ) : route === 'Rule catalog' ? (
          <RuleCatalog catalog={catalog}/>
        ) : route === 'Environments' ? (
          <Environments projects={projects} aiHealth={aiHealth} onCheckAi={refreshAll} onOpen={p => void bridge!.openProject(p.id)} onTest={runTests} busy={busy}/>
        ) : (
          <div className="settings-panel">
            <h2>AI Provider &amp; Models</h2>
            <p>Choose between 100% offline local Ollama models or Cloud Coding Agents (Claude, Codex, OpenCode, Pi) to unlock direct one-click finding fixes.</p>
            {aiConfig && <div className="ai-provider-card">
              <div className="provider-tabs" style={{ flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className={aiConfig.provider === 'local' ? 'selected' : ''}
                  onClick={() => void saveAiSettings('local', aiConfig.localModels[0] || 'qwen2.5-coder:1.5b')}
                >
                  Local (Ollama)
                </button>
                {(['cloud-claude', 'cloud-codex', 'cloud-opencode', 'cloud-pi'] as const).map(pid => (
                  <button
                    key={pid}
                    type="button"
                    className={aiConfig.provider === pid ? 'selected' : ''}
                    onClick={() => void saveAiSettings(pid, cloudModelsFor(pid)[0] || '')}
                  >
                    {CLOUD_PROVIDER_INFO[pid].short}
                  </button>
                ))}
              </div>
              <div className="provider-fields">
                <label className="field-label">
                  Active model
                  {aiConfig.provider === 'local' && !aiConfig.localModels.length ? (
                    <small className="empty-model-note">No local Ollama models installed yet. Run <code>ollama pull qwen2.5-coder:1.5b</code> and click Refresh.</small>
                  ) : (
                    <select
                      className="filter-button"
                      value={aiConfig.model}
                      onChange={e => void saveAiSettings(aiConfig.provider, e.target.value)}
                    >
                      {cloudModelsFor(aiConfig.provider).map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  )}
                </label>
                {aiConfig.provider !== 'local' && (() => {
                  const pid = aiConfig.provider as Exclude<AiProviderId, 'local'>
                  const pinfo = CLOUD_PROVIDER_INFO[pid]
                  const connected = isProviderConnected(pid)
                  return <div className="codex-auth-box">
                    <div className="codex-oauth-row">
                      <div>
                        <strong>{connected ? pinfo.connectedTitle : pinfo.connectTitle}</strong>
                        <small>{connected ? pinfo.connectedDesc : pinfo.connectDesc}</small>
                      </div>
                      <div className="export-actions">
                        {connected ? (
                          <button type="button" className="filter-button" disabled={busy === 'connect-provider'} onClick={() => void disconnectCloudProvider(pid)}>
                            Disconnect
                          </button>
                        ) : (
                          <button type="button" className="primary" disabled={busy === 'connect-provider'} onClick={() => void connectCloudProvider(pid)}>
                            <ExternalLink size={14}/> {busy === 'connect-provider' ? 'Connecting…' : pinfo.connectBtn}
                          </button>
                        )}
                      </div>
                    </div>
                    <details className="codex-api-fallback">
                      <summary>Advanced: Or use an API key instead {aiConfig.hasApiKey ? `(saved: ${aiConfig.apiKeyMasked})` : ''}</summary>
                      <div className="codex-key-row">
                        <input
                          type="password"
                          className="text-field"
                          placeholder={aiConfig.hasApiKey ? 'Enter new key to replace…' : pinfo.placeholder}
                          value={apiKeyInput}
                          onChange={e => setApiKeyInput(e.target.value)}
                        />
                        <div className="export-actions">
                          <button
                            type="button"
                            className="filter-button"
                            disabled={!apiKeyInput.trim() || busy === 'save-ai'}
                            onClick={() => void saveAiSettings(pid, aiConfig.model, apiKeyInput)}
                          >
                            Save key
                          </button>
                          {aiConfig.hasApiKey && (
                            <button
                              type="button"
                              className="filter-button"
                              disabled={busy === 'save-ai'}
                              onClick={() => void saveAiSettings(pid, aiConfig.model, undefined, true)}
                            >
                              Clear key
                            </button>
                          )}
                        </div>
                      </div>
                    </details>
                  </div>
                })()}
              </div>
            </div>}
            {aiHealth && <div className="settings-row">
              <div>
                <strong>{aiConfig && aiConfig.provider !== 'local' ? `${CLOUD_PROVIDER_INFO[aiConfig.provider].label} (${aiHealth.model})` : `Local Ollama review engine (${aiHealth.model})`}</strong>
                <small>{aiHealth.message}</small>
              </div>
              <button className="filter-button" onClick={() => void refreshAll()} disabled={busy === 'refresh'}>Check status</button>
            </div>}
            <div className="settings-row">
              <div><strong>Export workspace report</strong><small>Save all current project findings as SARIF 2.1.0 or Markdown</small></div>
              <div className="export-actions">
                <button className="filter-button" onClick={() => void exportReport('sarif')} disabled={!findings.length || !!busy}><Download size={13}/> SARIF</button>
                <button className="filter-button" onClick={() => void exportReport('markdown')} disabled={!findings.length || !!busy}><Download size={13}/> Markdown</button>
              </div>
            </div>
            <div className="settings-row">
              <div><strong>Remove all connected projects</strong><small>Does not delete project folders or cloned repositories</small></div>
              <button className="filter-button danger-button" onClick={() => setConfirmClear(true)} disabled={!projects.length}>Remove all</button>
            </div>
          </div>
        )}
      </section>
      <footer><span>OSIEN Probe <span className="footer-sep">·</span> Local desktop app</span><span><span className="footer-status"/> Local analysis</span></footer>
    </main>
    {dialog && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget && busy !== 'add') setDialog(false) }}>
      <section className="dialog">
        <div className="dialog-head">
          <div><div className="dialog-icon"><Plus size={18}/></div><h2>Add a project</h2><p>Connect a local folder, clone a repository, or audit a live URL</p></div>
          <button className="icon-button" onClick={() => setDialog(false)}><X size={18}/></button>
        </div>
        <div className="source-tabs">
          <button className={source === 'folder' ? 'selected' : ''} onClick={() => setSource('folder')}><Folder size={16}/> Local folder</button>
          <button className={source === 'repo' ? 'selected' : ''} onClick={() => setSource('repo')}><GitBranch size={16}/> Git repository</button>
          <button className={source === 'url' ? 'selected' : ''} onClick={() => { setSource('url'); setKind('Website') }}><Globe2 size={16}/> Live URL</button>
        </div>
        {source === 'repo' ? (
          <label className="field-label">Repository URL<input className="text-field" placeholder="https://github.com/owner/repository" value={url} onChange={e => setUrl(e.target.value)}/></label>
        ) : source === 'url' ? (
          <label className="field-label">Website URL (passive HTTP & HTML audit)<input className="text-field" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)}/></label>
        ) : (
          <div className="folder-picker">
            <div><Folder size={17}/><span>{folder || 'No folder selected'}</span></div>
            <button onClick={async () => { try { const picked = await bridge!.pickFolder(); if (picked) setFolder(picked) } catch (e) { setMessage(errorText(e)) } }}>Browse</button>
          </div>
        )}
        <div className="field-label category-label">Project category <span>Required</span></div>
        <div className="kind-grid">
          {kinds.map(({ name, detail, Icon }) => <button key={name} className={`kind-option ${kind === name ? 'chosen' : ''}`} onClick={() => setKind(name)}>
            <Icon size={17}/><span><strong>{name}</strong><small>{detail}</small></span>{kind === name && <Check size={15}/>}
          </button>)}
        </div>
        {message && <div className="form-error">{message}</div>}
        <div className="dialog-foot">
          <span>{source === 'url' ? 'Performs a single polite GET request; no intrusive fuzzing' : 'Scans inspect files; they do not execute project code'}</span>
          <button className="primary" disabled={(!kind && source !== 'url') || busy === 'add' || (source === 'folder' ? !folder : !url)} onClick={() => void addProject()}>
            {busy === 'add' ? 'Adding…' : source === 'repo' ? 'Clone and add' : source === 'url' ? 'Add & audit URL' : 'Add project'} <ArrowUpRight size={15}/>
          </button>
        </div>
      </section>
    </div>}
    {help && <InfoDialog onClose={() => setHelp(false)}/>}
    {confirmClear && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) setConfirmClear(false) }}><section className="dialog confirm-dialog">
      <div className="dialog-brand"><img className="dialog-logo" src="./logo.png" alt="OSIEN Probe"/><div><h2>Remove all projects?</h2><p>OSIEN Probe will forget all connected entries and scan results.</p></div></div>
      <p>Your folders and cloned repositories on disk will not be deleted.</p>
      <div className="dialog-foot">
        <button className="filter-button" onClick={() => setConfirmClear(false)}>Cancel</button>
        <button className="danger-button" onClick={() => void clearProjects()}>Remove all</button>
      </div>
    </section></div>}
    {confirmState && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) setConfirmState(null) }}><section className="dialog confirm-dialog">
      <div className="dialog-brand"><img className="dialog-logo" src="./logo.png" alt="OSIEN Probe"/><div><h2>{confirmState.title}</h2><p>{confirmState.body}</p></div></div>
      {confirmState.detail && <code className="confirm-detail">{confirmState.detail}</code>}
      <div className="dialog-foot">
        <button className="filter-button" onClick={() => setConfirmState(null)}>Cancel</button>
        <button
          className={confirmState.tone === 'danger' ? 'danger-button' : 'primary'}
          onClick={() => {
            const action = confirmState.onConfirm
            setConfirmState(null)
            void action()
          }}
        >
          {confirmState.confirmLabel}
        </button>
      </div>
    </section></div>}
    {fixPreview && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) setFixPreview(null) }}><section className="dialog choice-dialog">
      <div className="dialog-brand">
        <img className="dialog-logo" src="./logo.png" alt="OSIEN Probe"/>
        <div>
          <h2>Codex Fix Preview · {fixPreview.file}</h2>
          <p>{fixPreview.explanation} ({fixPreview.model})</p>
        </div>
      </div>
      <div className="fix-diff-grid">
        <div className="fix-diff-pane fix-before">
          <span>Current code</span>
          <pre><code>{fixPreview.target}</code></pre>
        </div>
        <div className="fix-diff-pane fix-after">
          <span>Proposed Codex fix</span>
          <pre><code>{fixPreview.replacement}</code></pre>
        </div>
      </div>
      <div className="dialog-foot">
        <button className="filter-button" onClick={() => setFixPreview(null)}>Cancel</button>
        <button className="primary" disabled={busy === `apply:${fixPreview.findingId}`} onClick={() => void confirmApplyFix()}>
          {busy === `apply:${fixPreview.findingId}` ? 'Applying…' : 'Apply fix to file'}
        </button>
      </div>
    </section></div>}
    {webFixPack && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) setWebFixPack(null) }}><section className="dialog" style={{ maxWidth: 760 }}>
      <div className="dialog-head">
        <div><div className="dialog-icon"><ShieldCheck size={18}/></div><h2>Fix Live Website URL</h2><p>{webFixPack.url} · {webFixPack.issueCount} issue{webFixPack.issueCount === 1 ? '' : 's'} addressed</p></div>
        <button className="icon-button" onClick={() => setWebFixPack(null)}><X size={18}/></button>
      </div>
      <div className="source-tabs" style={{ flexWrap: 'wrap' }}>
        {(['nginx', 'apache', 'express', 'nextjs', 'vercel', 'cloudflare'] as const).map(plat => (
          <button key={plat} className={webFixPlatform === plat ? 'selected' : ''} onClick={() => { setWebFixPlatform(plat); setWebFixCopied(false) }}>
            {plat === 'nextjs' ? 'Next.js' : plat === 'cloudflare' ? 'Cloudflare' : plat.charAt(0).toUpperCase() + plat.slice(1)}
          </button>
        ))}
      </div>
      <pre style={{ maxHeight: 300, overflow: 'auto', background: 'rgba(0,0,0,0.35)', padding: 12, borderRadius: 8, fontSize: 12, lineHeight: 1.5, margin: '8px 0' }}>{webFixPack.configs[webFixPlatform]}</pre>
      <div className="dialog-foot">
        <span>Apply this config to your server, CDN, or framework</span>
        <div className="export-actions">
          <button className="filter-button" onClick={() => setWebFixPack(null)}>Close</button>
          <button className="primary" onClick={async () => { try { await navigator.clipboard.writeText(webFixPack.configs[webFixPlatform]); setWebFixCopied(true); setTimeout(() => setWebFixCopied(false), 1800) } catch { /* ignore */ } }}>
            {webFixCopied ? 'Copied!' : 'Copy Fix Config'}
          </button>
        </div>
      </div>
    </section></div>}
    {extremeChoice && <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) setExtremeChoice(null) }}><section className="dialog choice-dialog">
      <div className="dialog-brand">
        <img className="dialog-logo" src="./logo.png" alt="OSIEN Probe"/>
        <div>
          <h2>Choose test mode for {extremeChoice.name}</h2>
          <p>Run a traditional static analysis or launch an Extreme Live Sandbox Test on your PC.</p>
        </div>
      </div>
      <div className="mode-grid">
        <button className="mode-card" onClick={() => { const target = extremeChoice; setExtremeChoice(null); void scan(target) }}>
          <div className="mode-badge">Fast · Static</div>
          <strong>Traditional Test</strong>
          <small>Evaluates 550+ static rules, AST checks, taint tracking, and detects your unit test suite without running the app.</small>
        </button>
        <button
          className="mode-card mode-card-extreme"
          disabled
          title="Extreme Live Sandbox Test is currently under development"
          style={{ opacity: 0.55, cursor: 'not-allowed' }}
        >
          <div className="mode-badge mode-badge-extreme">Under Development · Locked</div>
          <strong>Extreme Live Sandbox Test</strong>
          <small>
            Temporarily locked while in active development. Use Traditional Test for static, AST, taint, and CVE analysis.
          </small>
        </button>
      </div>
      <div className="dialog-foot">
        <span>Sandbox blocks external network requests and isolates storage</span>
        <button className="filter-button" onClick={() => setExtremeChoice(null)}>Cancel</button>
      </div>
    </section></div>}
  </div>
}

function Metric({ label, value, note, featured = false }: { label: string; value: string; note: string; featured?: boolean }) {
  return <div className={`metric ${featured ? 'featured-metric' : ''}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>
}

function FindingList({
  findings,
  projects,
  busy,
  bridge,
  isCloudCodex,
  onVerify,
  onFix,
  onExport,
  onOpen,
}: {
  findings: (Finding & { projectId: string; projectName: string })[]
  projects: Project[]
  busy: string
  bridge?: Bridge
  isCloudCodex: boolean
  onVerify(projectId: string, findingId: string): void
  onFix(projectId: string, findingId: string): void
  onExport(format: 'sarif' | 'markdown' | 'json', projectId?: string): void
  onOpen(p: Project): void
}) {
  const [copied, setCopied] = useState(false)
  const [copiedRule, setCopiedRule] = useState('')
  const [query, setQuery] = useState('')
  const [projectFilter, setProjectFilter] = useState('All projects')
  const [severityFilter, setSeverityFilter] = useState('All severities')
  const [confidenceFilter, setConfidenceFilter] = useState('All confidence')
  const [verdictFilter, setVerdictFilter] = useState('All verdicts')
  const [openContextKey, setOpenContextKey] = useState<string | null>(null)
  const [contexts, setContexts] = useState<Record<string, SourceContext>>({})
  const [contextError, setContextError] = useState<Record<string, string>>({})

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const order = ['critical', 'high', 'medium', 'low', 'info']
    return findings
      .filter(f => {
        if (projectFilter !== 'All projects' && f.projectId !== projectFilter) return false
        if (severityFilter !== 'All severities' && f.severity !== severityFilter) return false
        if (confidenceFilter !== 'All confidence' && (f.confidence || 'medium') !== confidenceFilter) return false
        if (verdictFilter !== 'All verdicts') {
          const v = f.aiAssessment?.verdict || 'unreviewed'
          if (v !== verdictFilter) return false
        }
        if (!q) return true
        return `${f.title} ${f.file}:${f.line} ${f.cwe || ''} ${f.ruleId || ''} ${f.excerpt} ${f.projectName}`.toLowerCase().includes(q)
      })
      .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))
  }, [findings, query, projectFilter, severityFilter, confidenceFilter, verdictFilter])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(formatFindings(filtered))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  const toggleContext = async (projectId: string, findingId: string) => {
    const key = `${projectId}:${findingId}`
    if (openContextKey === key) {
      setOpenContextKey(null)
      return
    }
    setOpenContextKey(key)
    if (contexts[key] || !bridge?.getFindingContext) return
    try {
      const ctx = await bridge.getFindingContext({ projectId, findingId })
      setContexts(prev => ({ ...prev, [key]: ctx }))
    } catch (e) {
      setContextError(prev => ({ ...prev, [key]: errorText(e) }))
    }
  }

  const copySuppression = async (ruleId?: string) => {
    const text = `// deepcheck-disable-next-line${ruleId ? ` ${ruleId}` : ''}`
    try {
      await navigator.clipboard.writeText(text)
      setCopiedRule(ruleId || '*')
      setTimeout(() => setCopiedRule(''), 1400)
    } catch {
      setCopiedRule('')
    }
  }

  return <div className="detail-panel">
    <div className="detail-summary">
      <span>{filtered.length} of {findings.length} finding{findings.length === 1 ? '' : 's'} shown · critical/high findings are double-checked by local AI in the background</span>
      <div className="export-actions">
        {bridge?.exportReport && <>
          <button className="filter-button copy-button" disabled={!filtered.length || !!busy} onClick={() => onExport('sarif', projectFilter !== 'All projects' ? projectFilter : undefined)}><Download size={12}/> SARIF</button>
          <button className="filter-button copy-button" disabled={!filtered.length || !!busy} onClick={() => onExport('markdown', projectFilter !== 'All projects' ? projectFilter : undefined)}><Download size={12}/> Markdown</button>
        </>}
        <button className="filter-button copy-button" disabled={!filtered.length} onClick={() => void copy()}>{copied ? 'Copied' : 'Copy findings'}</button>
      </div>
    </div>
    {findings.length > 0 && <div className="severity-strip">
      {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
        const count = findings.filter(f => f.severity === sev).length
        const active = severityFilter === sev
        return <button
          key={sev}
          type="button"
          className={`sev-pill severity-${sev} ${active ? 'sev-pill-active' : ''}`}
          onClick={() => setSeverityFilter(active ? 'All severities' : sev)}
        >
          <span>{sev}</span>
          <b>{count}</b>
        </button>
      })}
    </div>}
    {findings.length > 0 && <div className="triage-bar">
      <label className="search triage-search">
        <Search size={14}/>
        <input aria-label="Search findings" placeholder="Filter by file, rule, CWE, or code…" value={query} onChange={e => setQuery(e.target.value)}/>
      </label>
      <select className="filter-button" aria-label="Filter findings by project" value={projectFilter} onChange={e => setProjectFilter(e.target.value)}>
        <option value="All projects">All projects</option>
        {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
      <select className="filter-button" aria-label="Filter findings by severity" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
        <option value="All severities">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select className="filter-button" aria-label="Filter findings by confidence" value={confidenceFilter} onChange={e => setConfidenceFilter(e.target.value)}>
        <option value="All confidence">All confidence</option>
        <option value="high">High confidence</option>
        <option value="medium">Medium confidence</option>
        <option value="low">Low confidence</option>
      </select>
      <select className="filter-button" aria-label="Filter findings by AI verdict" value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
        <option value="All verdicts">All verdicts</option>
        <option value="likely_real">Likely true</option>
        <option value="likely_false_positive">Likely false positive</option>
        <option value="uncertain">Uncertain (50/50)</option>
        <option value="unreviewed">Unreviewed</option>
      </select>
      {(query || projectFilter !== 'All projects' || severityFilter !== 'All severities' || confidenceFilter !== 'All confidence' || verdictFilter !== 'All verdicts') && (
        <button className="filter-button" onClick={() => { setQuery(''); setProjectFilter('All projects'); setSeverityFilter('All severities'); setConfidenceFilter('All confidence'); setVerdictFilter('All verdicts') }}>
          Clear filters
        </button>
      )}
    </div>}
    {filtered.map(f => {
      const project = projects.find(item => item.id === f.projectId)
      const assessment = f.aiAssessment
      const label = assessment?.verdict === 'likely_real' ? 'Likely true' : assessment?.verdict === 'likely_false_positive' ? 'Likely false · possible scanner false positive' : 'Not confirmed · 50/50'
      const ctxKey = `${f.projectId}:${f.id}`
      const isExpanded = openContextKey === ctxKey
      const ctx = contexts[ctxKey]
      const ctxErr = contextError[ctxKey]
      return <div className="finding-row" key={ctxKey}>
        <span className={`severity severity-${f.severity}`}>{f.severity}</span>
        <button className="finding-open" onClick={() => { if (project) onOpen(project) }}>
          <span className="finding-main">
            <strong>
              {f.title}{f.cwe ? ` · ${f.cwe}` : ''}
              {f.isNew && <span className="new-badge">NEW</span>}
            </strong>
            <small>{f.projectName} · {f.file}:{f.line} · {f.confidence || 'medium'} scanner confidence{f.ruleId ? ` · ${f.ruleId}` : ''}</small>
            <code>{f.excerpt}</code>
            {f.reason && <small>{f.reason}</small>}
            {f.hint && <small className="finding-hint">Fix: {f.hint}</small>}
          </span>
          <ExternalLink size={15}/>
        </button>
        <div className="ai-review-action">
          <div className="finding-toolbar">
            {bridge?.getFindingContext && <button className="filter-button" onClick={() => void toggleContext(f.projectId, f.id)}>
              <Eye size={12}/> {isExpanded ? 'Hide code context' : 'Inspect code'}
            </button>}
            {f.ruleId && <button className="filter-button" onClick={() => void copySuppression(f.ruleId)}>
              {copiedRule === f.ruleId ? 'Copied directive' : `Copy suppress (${f.ruleId})`}
            </button>}
            {isCloudCodex && (f.fixed ? (
              <span className="fixed-badge">Fixed ✓</span>
            ) : (
              <button
                className="filter-button fix-finding-btn"
                disabled={busy === `fix:${f.id}`}
                onClick={() => onFix(f.projectId, f.id)}
              >
                {busy === `fix:${f.id}` ? 'Generating fix…' : 'Fix finding'}
              </button>
            ))}
          </div>
          {isExpanded && <div className="context-inspector">
            {ctx?.lines ? <pre className="context-code">{ctx.lines.map(line => (
              <div key={line.number} className={`context-line ${line.isTarget ? 'context-line-target' : ''}`}>
                <span className="context-lineno">{line.number}</span>
                <span>{line.text || ' '}</span>
              </div>
            ))}</pre> : ctxErr ? <small className="run-ai-error">{ctxErr}</small> : <small>Loading source lines…</small>}
          </div>}
          {assessment ? <div className={`ai-assessment verdict-${assessment.verdict}`}>
            <strong>{label} · {assessment.confidence}%</strong>
            <span>{assessment.rationale}</span>
            {assessment.evidence && <small>Evidence: {assessment.evidence}</small>}
            {assessment.reviewAdvice && <small>Review: {assessment.reviewAdvice}</small>}
            <small>{assessment.model} · Local only · Snippet context only</small>
            <button className="filter-button" disabled={busy === `verify:${f.id}`} onClick={() => onVerify(f.projectId, f.id)}>{busy === `verify:${f.id}` ? 'Rechecking…' : 'Recheck finding'}</button>
          </div> : f.aiReviewError ? <div className="ai-assessment ai-review-error">
            <strong>AI review unavailable</strong>
            <span>{f.aiReviewError}</span>
            <small>Finding remains a scanner result and is not AI-confirmed.</small>
            <button className="filter-button" disabled={busy === `verify:${f.id}`} onClick={() => onVerify(f.projectId, f.id)}>Retry review</button>
          </div> : <div className="ai-assessment">
            <strong>{['critical', 'high'].includes(f.severity) ? 'AI review queued' : 'Not AI-reviewed'}</strong>
            <span>{['critical', 'high'].includes(f.severity) ? 'Critical/high findings are double-checked automatically in the background.' : 'Lower-severity findings are reviewed on demand to keep scans fast.'}</span>
            <button className="filter-button" disabled={busy === `verify:${f.id}`} onClick={() => onVerify(f.projectId, f.id)}>{busy === `verify:${f.id}` ? 'Reviewing…' : 'Review with AI now'}</button>
          </div>}
        </div>
      </div>
    })}
    {!filtered.length && <div className="empty-state">{findings.length ? 'No findings match the selected filters' : 'No findings reported by completed scans'}</div>}
  </div>
}

function Runs({
  projects,
  selected,
  busy,
  isCloudCodex,
  onScan,
  onExtreme,
  onFixAll,
  onWebFix,
  onTest,
  onRunFile,
  onExport,
}: {
  projects: Project[]
  selected: Project | null
  busy: string
  isCloudCodex: boolean
  onScan(p: Project): void
  onExtreme(p: Project): void
  onFixAll(p: Project): void
  onWebFix(p: Project): void
  onTest(p: Project): void
  onRunFile(p: Project, target: TestTarget): void
  onExport(format: 'sarif' | 'markdown' | 'json', projectId?: string): void
}) {
  const list = selected ? projects.filter(p => p.id === selected.id) : projects.filter(p => p.latestRun)
  return <div className="detail-panel">
    {list.map(p => <div className="run-card" key={p.id}>
      <div className="run-card-head">
        <div><strong>{p.name}</strong><small>{p.root}</small></div>
        <div className="export-actions">
          {p.latestRun && <>
            <button className="filter-button" onClick={() => onExport('sarif', p.id)} disabled={!!busy}><Download size={13}/> SARIF</button>
            <button className="filter-button" onClick={() => onExport('markdown', p.id)} disabled={!!busy}><Download size={13}/> Report</button>
          </>}
          {p.kind === 'Website' && (
            <button
              className="filter-button extreme-btn"
              onClick={() => onExtreme(p)}
              disabled
              title="Extreme Live Sandbox Test is currently under development"
              style={{ opacity: 0.55, cursor: 'not-allowed' }}
            >
              <Activity size={13}/> Extreme sandbox (Under dev)
            </button>
          )}
          {p.latestRun && /^https?:\/\//i.test(p.root) && (
            <button className="filter-button fix-finding-btn" onClick={() => onWebFix(p)} disabled={!!busy}>
              <ShieldCheck size={13}/> {busy === `webfix:${p.id}` ? 'Generating…' : 'Fix Live URL'}
            </button>
          )}
          {isCloudCodex && p.latestRun && p.latestRun.findings.some(f => !f.fixed && ['critical', 'high', 'medium'].includes(f.severity)) && (
            <button className="filter-button fix-finding-btn" onClick={() => onFixAll(p)} disabled={!!busy}>
              <ShieldCheck size={13}/> {busy === `fixall:${p.id}` ? 'Fixing all…' : 'Fix all with AI'}
            </button>
          )}
          <button className="primary" onClick={() => onScan(p)} disabled={busy === `scan:${p.id}`}>
            <RefreshCw size={14} className={busy === `scan:${p.id}` ? 'spinning' : ''}/>
            {busy === `scan:${p.id}` ? 'Scanning…' : 'Scan source'}
          </button>
        </div>
      </div>
      {p.latestRun ? <>
        <div className="run-stats">
          <span><b>{p.latestRun.filesScanned}</b> files scanned</span>
          <span><b>{p.latestRun.rulesEvaluated.toLocaleString()}</b> rule evaluations</span>
          <span><b>{p.latestRun.findings.length}</b> findings</span>
          <span>
            <b>{p.latestRun.score}</b> score
            {typeof p.latestRun.scoreDelta === 'number' && p.latestRun.scoreDelta !== 0 && (
              <em className={`delta-badge ${p.latestRun.scoreDelta > 0 ? 'delta-up' : 'delta-down'}`}>
                {p.latestRun.scoreDelta > 0 ? `+${p.latestRun.scoreDelta}` : p.latestRun.scoreDelta}
              </em>
            )}
          </span>
        </div>
        <p className="run-meta">
          Source scan completed {dateLabel(p.latestRun.completedAt)}
          {p.latestRun.durationMs ? ` · ${p.latestRun.durationMs} ms` : ''}
          {p.latestRun.languagesScanned?.length ? ` · Languages: ${p.latestRun.languagesScanned.join(', ')}` : ''}
          {p.latestRun.truncated ? ' · Finding display capped at 1,000' : ''}
        </p>
        {(p.scanHistory || []).length > 1 && <details className="history-details">
          <summary><History size={12}/> Scan history ({p.scanHistory!.length} runs)</summary>
          <div className="history-list">
            {p.scanHistory!.map(entry => <div className="history-row" key={entry.id}>
              <span>{dateLabel(entry.completedAt)}</span>
              <span>{entry.filesScanned} files</span>
              <span>{entry.findingsCount} findings</span>
              <b>Score {entry.score}/100</b>
            </div>)}
          </div>
        </details>}
        <div className="test-action">
          <div>
            <strong>Project tests</strong>
            <span>Each test file and the full suite require separate confirmation.</span>
            <code>{p.latestRun.testCommand || 'No supported test runner detected.'}</code>
          </div>
          {p.latestRun.testCommand && <button className="filter-button" disabled={busy === `test:${p.id}`} onClick={() => onTest(p)}>
            <Play size={14}/>{busy === `test:${p.id}` ? 'Running tests…' : 'Run full suite'}
          </button>}
        </div>
        {(p.latestRun.testFiles || []).length > 0 && <div className="test-file-list">
          <strong>Individual test files ({p.latestRun.testFiles!.length}{p.latestRun.testFilesTruncated ? '+' : ''})</strong>
          {p.latestRun.testFiles!.map(target => {
            const result = p.latestRun!.testResults?.find(item => item.file === target.file)
            const key = `testfile:${p.id}:${target.file}`
            return <div className="test-file-row" key={target.file}>
              <code>{target.file}</code>
              <span>{result ? result.exitCode === 0 ? 'Passed' : `Failed (${result.exitCode})` : target.command}</span>
              <button className="filter-button" disabled={!!busy} onClick={() => onRunFile(p, target)}>{busy === key ? 'Running…' : 'Run file'}</button>
              {result && <details><summary>{result.durationMs ? `${result.durationMs} ms · ` : ''}Output</summary><pre>{result.output || 'No output.'}</pre></details>}
            </div>
          })}
        </div>}
        {p.latestRun.testFilesTruncated && <p className="run-meta">Only the first 200 individually runnable test files are listed.</p>}
        {p.latestRun.testResult && <div className="terminal-output">
          <div>
            <strong>{p.latestRun.testResult.command}</strong>
            <span className={p.latestRun.testResult.exitCode === 0 ? 'test-pass' : 'test-fail'}>{p.latestRun.testResult.exitCode === 0 ? 'Passed' : `Exited ${p.latestRun.testResult.exitCode}`}</span>
          </div>
          <pre>{p.latestRun.testResult.output || 'Test command completed without output.'}</pre>
        </div>}
        {p.latestRun.findings.length > 0 && <div className="run-findings">
          <div className="run-findings-head">
            <h3>Source scan findings · automatic local AI review</h3>
            <button className="filter-button copy-button" onClick={() => void navigator.clipboard.writeText(formatFindings(p.latestRun!.findings.map(f => ({ ...f, projectName: p.name }))))}>Copy findings</button>
          </div>
          {p.latestRun.findings.map(f => <div className="run-finding" key={f.id}>
            <span className={`severity severity-${f.severity}`}>{f.severity}</span>
            <div>
              <strong>{f.title}{f.isNew && <span className="new-badge">NEW</span>}</strong>
              <small>{f.file}:{f.line}{f.ruleId ? ` · ${f.ruleId}` : ''}</small>
              <code>{f.excerpt}</code>
              {f.aiAssessment && <small className="run-ai-result">AI: {f.aiAssessment.verdict === 'likely_real' ? 'Likely true' : f.aiAssessment.verdict === 'likely_false_positive' ? 'Likely false · possible scanner false positive' : 'Not confirmed · 50/50'} · {f.aiAssessment.confidence}%</small>}
              {f.aiReviewError && <small className="run-ai-error">AI review unavailable: {f.aiReviewError}</small>}
            </div>
          </div>)}
        </div>}
      </> : <p className="run-meta">No scan has been run for this project yet.</p>}
    </div>)}
    {!list.length && <div className="empty-state">No scans yet. Add a project and choose Scan source.</div>}
  </div>
}

function Environments({
  projects,
  aiHealth,
  onCheckAi,
  onOpen,
  onTest,
  busy,
}: {
  projects: Project[]
  aiHealth: AiHealth | null
  onCheckAi(): void
  onOpen(p: Project): void
  onTest(p: Project): void
  busy: string
}) {
  return <div className="detail-panel">
    {aiHealth && <div className="environment-row">
      <div className="project-icon icon-web"><ShieldCheck size={17}/></div>
      <div className="environment-main">
        <strong>Local AI review engine · {aiHealth.model}</strong>
        <small>{aiHealth.endpoint}</small>
        <span>{aiHealth.message}</span>
      </div>
      <button className="filter-button" onClick={onCheckAi} disabled={busy === 'refresh'}><RefreshCw size={14}/> Check AI</button>
    </div>}
    {projects.map(p => <div className="environment-row" key={p.id}>
      <div className="project-icon icon-code"><Code2 size={17}/></div>
      <div className="environment-main">
        <strong>{p.name}</strong>
        <small>{p.root}</small>
        <span>{p.latestRun?.testCommand ? `Detected: ${p.latestRun.testCommand}` : 'Run a scan to detect available test scripts'}</span>
      </div>
      <button className="filter-button" onClick={() => onOpen(p)}><Folder size={14}/> Open folder</button>
      {p.latestRun?.testCommand && <button className="filter-button" disabled={busy === `test:${p.id}`} onClick={() => onTest(p)}><Play size={14}/> Run tests</button>}
    </div>)}
    {!projects.length && <div className="empty-state">Add a project to inspect its available test environment</div>}
  </div>
}

function InfoDialog({ onClose }: { onClose(): void }) {
  return <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
    <section className="dialog">
      <div className="dialog-head">
        <div className="dialog-brand"><img className="dialog-logo" src="./logo.png" alt="OSIEN Probe"/><div><h2>About OSIEN Probe scans</h2><p>Local source checks, AI review, and project tests are separate steps</p></div></div>
        <button className="icon-button" onClick={onClose}><X size={18}/></button>
      </div>
      <div className="help-copy">
        <p><strong>Source scan</strong> walks supported source files, skips common generated/dependency folders, and evaluates the displayed rule set plus multi-language AST checks and same-file taint tracking. It does not run code or claim to prove a project is bug-free.</p>
        <p><strong>Background AI review</strong> double-checks up to 15 critical/high findings after each scan without blocking results. Lower-severity findings can be reviewed on demand. Each local AI request receives only that finding and a small nearby source excerpt. Results are guidance, not proof.</p>
        <p><strong>Run tests</strong> starts a detected project test command only after you confirm. Test scripts can execute arbitrary code, so only run scripts from projects you trust.</p>
        <p>Source code is not uploaded. Review requests go only to local Ollama.</p>
      </div>
      <div className="dialog-foot"><span>OSIEN Probe · Local analysis</span><button className="primary" onClick={onClose}>Close</button></div>
    </section>
  </div>
}

function ExtremeSandboxView({
  extreme,
  sysProfile,
  onStop,
  onClose,
}: {
  extreme: ExtremeState
  sysProfile: SystemProfile | null
  onStop(projectId: string): void
  onClose(): void
}) {
  return <section className="extreme-shell">
    <div className="extreme-head">
      <div className="extreme-title">
        <span className={`live-dot ${extreme.running ? '' : 'live-dot-idle'}`}/>
        <div>
          <strong>Extreme Live Sandbox · {extreme.projectName}</strong>
          <small>
            {sysProfile ? `${sysProfile.cpuCores} cores · ${sysProfile.totalMemGb} GB RAM (${sysProfile.tier} tier)` : 'Local PC sandbox'} · Step {extreme.step}/{extreme.maxSteps} · {extreme.running ? 'Autonomous stress test running' : 'Completed'}
          </small>
        </div>
      </div>
      <div className="export-actions">
        {extreme.running
          ? <button className="danger-button" onClick={() => onStop(extreme.projectId)}>Stop sandbox</button>
          : <button className="filter-button" onClick={onClose}>Close view</button>}
      </div>
    </div>
    {extreme.error && <div className="form-error">{extreme.error}</div>}
    <div className="extreme-split">
      <div className="extreme-telemetry">
        <div className="extreme-stats">
          <div><span>Pages</span><b>{extreme.stats.pages}</b></div>
          <div><span>Clicks</span><b>{extreme.stats.clicks}</b></div>
          <div><span>Forms fuzzed</span><b>{extreme.stats.inputsFuzzed}</b></div>
          <div><span>Findings</span><b>{extreme.findings.length}</b></div>
        </div>
        {extreme.findings.length > 0 && <div className="extreme-findings">
          <strong>Live findings ({extreme.findings.length})</strong>
          {extreme.findings.map((f, i) => (
            <div key={`${f.ruleId}-${i}`} className="extreme-finding-row">
              <span className={`severity severity-${f.severity}`}>{f.severity}</span>
              <div>
                <strong>{f.title}</strong>
                <small>{f.cwe} · {f.detail}</small>
              </div>
            </div>
          ))}
        </div>}
        <div className="extreme-logs">
          <strong>Autonomous action feed</strong>
          <div className="extreme-log-list">
            {extreme.logs.map((l, i) => (
              <div key={i} className={`extreme-log-line log-${l.level}`}>{l.text}</div>
            ))}
          </div>
        </div>
      </div>
      <div className="extreme-viewport">
        <div className="extreme-urlbar">
          <span className="sandbox-pill">127.0.0.1 SANDBOX</span>
          <code>{extreme.url}</code>
        </div>
        <div className="extreme-screen">
          {extreme.frameUrl
            ? <img src={extreme.frameUrl} alt="Live sandbox viewport"/>
            : <div className="extreme-placeholder"><RefreshCw size={18} className="spinning"/><span>Booting isolated Chromium sandbox…</span></div>}
        </div>
      </div>
    </div>
  </section>
}

function RuleCatalog({ catalog }: { catalog: CatalogPayload | null }) {
  const [query, setQuery] = useState('')
  const [catFilter, setCatFilter] = useState('All')
  const [sevFilter, setSevFilter] = useState('All')
  const [langFilter, setLangFilter] = useState('All')
  const [limit, setLimit] = useState(60)

  const rules = useMemo(() => catalog?.rules || [], [catalog])
  const langs = useMemo(() => ['All', ...Array.from(new Set(rules.map(r => r.lang))).sort()], [rules])
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return rules.filter(r => {
      if (catFilter !== 'All' && r.category !== catFilter) return false
      if (sevFilter !== 'All' && r.severity !== sevFilter) return false
      if (langFilter !== 'All' && r.lang !== langFilter) return false
      if (!q) return true
      return `${r.id} ${r.title} ${r.cwe} ${r.lang} ${r.category} ${r.hint}`.toLowerCase().includes(q)
    })
  }, [rules, query, catFilter, sevFilter, langFilter])

  const shown = filtered.slice(0, limit)

  return <div className="detail-panel">
    <div className="detail-summary">
      <span>
        {catalog
          ? `${filtered.length} of ${catalog.total} catalog rules shown · plus Babel JS/TS AST & 11-language Tree-sitter AST checks`
          : 'Loading rule catalog…'}
      </span>
      <span className="catalog-badge">100% local · Zero telemetry</span>
    </div>
    <div className="triage-bar">
      <label className="search triage-search">
        <Search size={14}/>
        <input aria-label="Search rules" placeholder="Search rules by ID, CWE, title, or hint…" value={query} onChange={e => { setQuery(e.target.value); setLimit(60) }}/>
      </label>
      <select className="filter-button" aria-label="Filter rules by category" value={catFilter} onChange={e => { setCatFilter(e.target.value); setLimit(60) }}>
        <option value="All">All categories</option>
        {(catalog?.categories || []).map(c => <option key={c} value={c}>{c}</option>)}
      </select>
      <select className="filter-button" aria-label="Filter rules by severity" value={sevFilter} onChange={e => { setSevFilter(e.target.value); setLimit(60) }}>
        <option value="All">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select className="filter-button" aria-label="Filter rules by language" value={langFilter} onChange={e => { setLangFilter(e.target.value); setLimit(60) }}>
        {langs.map(l => <option key={l} value={l}>{l === 'All' ? 'All languages' : l}</option>)}
      </select>
    </div>
    <div className="rule-grid">
      {shown.map(r => (
        <details key={r.id} className="rule-card">
          <summary className="rule-card-head">
            <span className={`severity severity-${r.severity}`}>{r.severity}</span>
            <div className="rule-card-title">
              <strong>{r.title}</strong>
              <small>{r.id} · {r.cwe} · {r.category} · {r.lang}</small>
            </div>
          </summary>
          <div className="rule-card-body">
            <p className="finding-hint">{r.hint}</p>
            <div className="rule-samples">
              <div><span>Flagged pattern</span><code>{r.bad}</code></div>
              <div><span>Recommended fix</span><code>{r.good}</code></div>
            </div>
          </div>
        </details>
      ))}
    </div>
    {filtered.length > limit && (
      <div className="catalog-more">
        <button className="filter-button" onClick={() => setLimit(n => n + 80)}>
          Show more ({filtered.length - limit} remaining)
        </button>
      </div>
    )}
    {catalog && !filtered.length && <div className="empty-state">No rules match your current search filters</div>}
  </div>
}

function formatFindings(findings: (Finding & { projectName?: string; projectId?: string })[]) {
  return findings.map(f => `[${f.severity.toUpperCase()}] ${f.title}${f.cwe ? ` (${f.cwe})` : ''} · confidence ${f.confidence || 'medium'}\nProject: ${f.projectName || ''}\nFile: ${f.file}:${f.line}\nCode: ${f.excerpt}${f.reason ? `\nWhy: ${f.reason}` : ''}${f.hint ? `\nSuggested review: ${f.hint}` : ''}`).join('\n\n')
}
function pageDescription(route: Route) {
  return ({
    Projects: 'Connect folders and inspect source on this device',
    'Test runs': 'Review scans, history, and run detected project test scripts',
    Findings: 'Search, filter, inspect code context, and export findings from latest scans',
    Security: 'High-severity security heuristics from latest scans',
    'Rule catalog': 'Browse all static rules, CWEs, and safe vs. flagged code examples',
    Environments: 'Local AI review engine status, detected project folders, and test commands',
    Settings: 'Manage local project data and workspace exports',
  })[route]
}
function errorText(e: unknown) { return e instanceof Error ? e.message : String(e) }
export default App
