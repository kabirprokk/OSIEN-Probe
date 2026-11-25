import { useMemo, useState } from 'react';
import { ShieldAlert, GitBranch, Layers } from 'lucide-react';

export interface AttackGraphFinding {
  ruleId: string;
  title: string;
  severity: string;
  cwe?: string;
  file: string;
  line: number;
  hint?: string;
  reason?: string;
}

interface AttackGraphProps {
  findings: AttackGraphFinding[];
  onSelectFinding?: (finding: AttackGraphFinding) => void;
}

interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  column: 'source' | 'module' | 'sink';
  severity: string;
  count: number;
  findings: AttackGraphFinding[];
  x: number;
  y: number;
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  severity: string;
  count: number;
}

const SEV_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
  info: '#94a3b8',
};

function classifySource(f: AttackGraphFinding): string {
  const txt = `${f.ruleId} ${f.title} ${f.reason || ''}`.toLowerCase();
  if (/route|auth|idor|endpoint|cors|header/.test(txt)) return 'HTTP Route / API';
  if (/secret|key|token|password|credential|env/.test(txt)) return 'Config / Secrets';
  if (/sql|query|db|schema|prisma|drizzle|nosql/.test(txt)) return 'Request Params';
  if (/xss|html|dom|script|postmessage|url|href/.test(txt)) return 'Browser / User Input';
  if (/cve|dep|supply|package|typosquat|license/.test(txt)) return 'Third-Party Package';
  return 'Untrusted Input';
}

function classifySink(f: AttackGraphFinding): string {
  const txt = `${f.ruleId} ${f.title} ${f.cwe || ''}`.toLowerCase();
  if (/sql|nosql|prisma|drizzle|ledger|db|query/.test(txt)) return 'Database / SQL Sink';
  if (/xss|innerhtml|html|dom|cwe-79|script|href/.test(txt)) return 'DOM / Script Execution';
  if (/exec|spawn|shell|cmd|eval|function|cwe-78|cwe-94/.test(txt)) return 'OS Shell / Code Eval';
  if (/auth|idor|jwt|session|cors|csrf|access/.test(txt)) return 'Auth / Access Control';
  if (/secret|key|token|password|cwe-798|crypto|hash/.test(txt)) return 'Secrets & Crypto';
  if (/ssrf|fetch|redirect|url|path|traversal/.test(txt)) return 'Network / File System';
  return 'Application Runtime';
}

function worstSeverity(a: string, b: string): string {
  return (SEV_RANK[a] || 0) >= (SEV_RANK[b] || 0) ? a : b;
}

export function AttackGraph({ findings, onSelectFinding }: AttackGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [minSev, setMinSev] = useState<'all' | 'high'>('all');

  const filtered = useMemo(() => {
    if (minSev === 'high') {
      return findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    }
    return findings;
  }, [findings, minSev]);

  const { nodes, edges, height } = useMemo(() => {
    const sourceMap = new Map<string, GraphNode>();
    const moduleMap = new Map<string, GraphNode>();
    const sinkMap = new Map<string, GraphNode>();
    const edgeMap = new Map<string, GraphEdge>();

    const topFindings = filtered.slice(0, 120);
    for (const f of topFindings) {
      const srcName = classifySource(f);
      const fileShort = f.file.split(/[\\/]/).slice(-2).join('/') || f.file;
      const sinkName = classifySink(f);

      const srcId = `src:${srcName}`;
      const modId = `mod:${fileShort}`;
      const sinkId = `sink:${sinkName}`;

      const upsert = (map: Map<string, GraphNode>, id: string, label: string, sublabel: string, column: GraphNode['column']) => {
        const cur = map.get(id);
        if (cur) {
          cur.count += 1;
          cur.severity = worstSeverity(cur.severity, f.severity);
          cur.findings.push(f);
        } else {
          map.set(id, { id, label, sublabel, column, severity: f.severity, count: 1, findings: [f], x: 0, y: 0 });
        }
      };

      upsert(sourceMap, srcId, srcName, 'Entry / Source', 'source');
      upsert(moduleMap, modId, fileShort, 'Code Hop / File', 'module');
      upsert(sinkMap, sinkId, sinkName, 'Impact / Sink', 'sink');

      const addEdge = (from: string, to: string) => {
        const key = `${from}->${to}`;
        const cur = edgeMap.get(key);
        if (cur) {
          cur.count += 1;
          cur.severity = worstSeverity(cur.severity, f.severity);
        } else {
          edgeMap.set(key, { id: key, from, to, severity: f.severity, count: 1 });
        }
      };
      addEdge(srcId, modId);
      addEdge(modId, sinkId);
    }

    const srcList = [...sourceMap.values()].sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)).slice(0, 7);
    const modList = [...moduleMap.values()].sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || b.count - a.count).slice(0, 8);
    const sinkList = [...sinkMap.values()].sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)).slice(0, 7);

    const maxRows = Math.max(srcList.length, modList.length, sinkList.length, 1);
    const computedHeight = Math.max(280, maxRows * 68 + 64);

    const placeCol = (list: GraphNode[], x: number) => {
      const gap = (computedHeight - 54) / Math.max(list.length, 1);
      list.forEach((n, idx) => {
        n.x = x;
        n.y = 48 + gap * idx + gap / 2;
      });
    };

    placeCol(srcList, 125);
    placeCol(modList, 450);
    placeCol(sinkList, 775);

    const allNodes = [...srcList, ...modList, ...sinkList];
    const nodeIds = new Set(allNodes.map((n) => n.id));
    const validEdges = [...edgeMap.values()].filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to));

    return { nodes: allNodes, edges: validEdges, height: computedHeight };
  }, [filtered]);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const selectedNode = selectedNodeId ? nodeById.get(selectedNodeId) || null : null;

  if (findings.length === 0) {
    return (
      <div style={{ padding: 24, textAlign: 'center', border: '1px solid rgba(148,163,184,0.18)', borderRadius: 12, background: 'rgba(15,23,42,0.45)' }}>
        <ShieldAlert size={24} style={{ color: '#22c55e', marginBottom: 8 }} />
        <div style={{ fontWeight: 600, marginBottom: 4 }}>Zero Attack Paths Detected</div>
        <div style={{ fontSize: 12.5, opacity: 0.72 }}>Run a scan on a project with findings to visualize interactive Source → File → Sink attack paths.</div>
      </div>
    );
  }

  return (
    <div style={{ border: '1px solid rgba(148,163,184,0.2)', borderRadius: 12, background: 'rgba(6,13,26,0.72)', padding: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10, flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <GitBranch size={15} style={{ color: '#38bdf8' }} />
          <strong style={{ fontSize: 13.5 }}>Interactive Attack-Graph · Source → File → Sink</strong>
          <span style={{ fontSize: 11.5, opacity: 0.7 }}>({nodes.length} nodes · {edges.length} paths)</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            type="button"
            className={minSev === 'all' ? 'filter-button filter-active' : 'filter-button'}
            onClick={() => setMinSev('all')}
          >
            All ({findings.length})
          </button>
          <button
            type="button"
            className={minSev === 'high' ? 'filter-button filter-active' : 'filter-button'}
            onClick={() => setMinSev('high')}
          >
            Critical &amp; High
          </button>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <svg viewBox={`0 0 900 ${height}`} style={{ width: '100%', minWidth: 680, height: 'auto', display: 'block' }}>
          {/* Column Headers */}
          <text x="125" y="22" textAnchor="middle" fill="#7dd3fc" fontSize="11" fontFamily="monospace" letterSpacing="1.6">1 · ENTRY SOURCES</text>
          <text x="450" y="22" textAnchor="middle" fill="#cbd5e1" fontSize="11" fontFamily="monospace" letterSpacing="1.6">2 · AFFECTED MODULES</text>
          <text x="775" y="22" textAnchor="middle" fill="#fca5a5" fontSize="11" fontFamily="monospace" letterSpacing="1.6">3 · DANGEROUS SINKS</text>

          {/* Curved Dataflow Edges */}
          {edges.map((e) => {
            const a = nodeById.get(e.from);
            const b = nodeById.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + 98;
            const x2 = b.x - 98;
            const midX = (x1 + x2) / 2;
            const highlighted = !selectedNodeId || selectedNodeId === e.from || selectedNodeId === e.to;
            const color = SEV_COLOR[e.severity] || '#38bdf8';
            return (
              <path
                key={e.id}
                d={`M ${x1} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${x2} ${b.y}`}
                fill="none"
                stroke={color}
                strokeWidth={highlighted ? Math.min(3.5, 1.4 + e.count * 0.35) : 1}
                strokeOpacity={highlighted ? 0.72 : 0.14}
              />
            );
          })}

          {/* Clickable Nodes */}
          {nodes.map((n) => {
            const color = SEV_COLOR[n.severity] || '#38bdf8';
            const isSel = selectedNodeId === n.id;
            const shortLabel = n.label.length > 22 ? `…${n.label.slice(-21)}` : n.label;
            return (
              <g
                key={n.id}
                role="button"
                tabIndex={0}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedNodeId((curr) => (curr === n.id ? null : n.id))}
                onKeyDown={(ev) => {
                  if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault();
                    setSelectedNodeId((curr) => (curr === n.id ? null : n.id));
                  }
                }}
              >
                <rect
                  x={n.x - 98}
                  y={n.y - 22}
                  width="196"
                  height="44"
                  rx="8"
                  fill={isSel ? 'rgba(14, 42, 71, 0.96)' : 'rgba(11, 22, 40, 0.9)'}
                  stroke={color}
                  strokeWidth={isSel ? 2.2 : 1.1}
                />
                <circle cx={n.x - 84} cy={n.y} r="4.5" fill={color} />
                <text x={n.x - 73} y={n.y - 2} fill="#f8fafc" fontSize="11.5" fontWeight="600" fontFamily="system-ui, sans-serif">
                  {shortLabel}
                </text>
                <text x={n.x - 73} y={n.y + 13} fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                  {n.count} finding{n.count === 1 ? '' : 's'} · {n.severity.toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {selectedNode && (
        <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(148,163,184,0.18)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <strong style={{ fontSize: 12.5, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <Layers size={13} />
              {selectedNode.label} ({selectedNode.findings.length} linked finding{selectedNode.findings.length === 1 ? '' : 's'})
            </strong>
            <button type="button" className="filter-button" onClick={() => setSelectedNodeId(null)}>Clear selection</button>
          </div>
          <div style={{ display: 'grid', gap: 6, maxHeight: 170, overflowY: 'auto' }}>
            {selectedNode.findings.slice(0, 10).map((f, i) => (
              <div
                key={`${f.ruleId}-${f.file}-${f.line}-${i}`}
                onClick={() => onSelectFinding?.(f)}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 10px',
                  borderRadius: 6,
                  background: 'rgba(15,23,42,0.65)',
                  border: '1px solid rgba(148,163,184,0.16)',
                  cursor: onSelectFinding ? 'pointer' : 'default',
                  fontSize: 12,
                }}
              >
                <span>
                  <span className={`severity severity-${f.severity}`} style={{ marginRight: 8 }}>{f.severity}</span>
                  <strong>{f.title}</strong>
                </span>
                <code style={{ fontSize: 11, opacity: 0.78 }}>{f.file}:{f.line}</code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
