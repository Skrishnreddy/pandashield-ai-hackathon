import { useEffect, useMemo, useState } from 'react';
import { api, download } from '../api.js';
import { SeverityBadge, ScoreRing, Markdown, SEVERITIES, timeAgo } from './ui.jsx';
import FindingDetail from './FindingDetail.jsx';

const CATEGORY_LABEL = { code: 'Code', secret: 'Secret', dependency: 'Dependency' };
const STATUS_LABEL = { open: 'Open', fixed: 'Fixed', accepted_risk: 'Accepted risk', false_positive: 'False positive' };

export default function ScanView({ scanId }) {
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [sevFilter, setSevFilter] = useState('all');
  const [catFilter, setCatFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('open');
  const [retrying, setRetrying] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    api(`/scans/${scanId}`).then((s) => {
      setScan(s);
      const first = s.ai?.fixFirst?.[0] || s.findings?.[0]?.id;
      if (first && window.innerWidth > 1100) setSelected(first);
    }).catch((e) => setError(e.message));
  }, [scanId]);

  const findings = useMemo(() => {
    if (!scan) return [];
    const prio = { P1: 0, P2: 1, P3: 2, P4: 3 };
    return scan.findings
      .filter((f) => (sevFilter === 'all' || f.severity === sevFilter)
        && (catFilter === 'all' || f.category === catFilter)
        && (statusFilter === 'all' || f.status === statusFilter))
      .sort((a, b) => (prio[a.ai?.priority] ?? 9) - (prio[b.ai?.priority] ?? 9) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [scan, sevFilter, catFilter, statusFilter]);

  if (error) return <div className="page"><div className="alert error">{error}</div><a href="#/" className="ghost-btn">Back</a></div>;
  if (!scan) return <div className="page"><div className="skeleton tall" /><div className="skeleton" /><div className="skeleton" /></div>;

  const current = scan.findings.find((f) => f.id === selected);
  const sev = scan.stats.bySeverity;
  const statusCounts = scan.findings.reduce((a, f) => ({ ...a, [f.status]: (a[f.status] || 0) + 1 }), {});

  const updateFinding = (id, patch) => setScan((s) => ({ ...s, findings: s.findings.map((f) => (f.id === id ? { ...f, ...patch } : f)) }));

  const retryAi = async () => {
    setRetrying(true);
    try { setScan(await api(`/scans/${scanId}/triage`, { method: 'POST' })); } catch (e) { setError(e.message); } finally { setRetrying(false); }
  };

  const remove = async () => {
    if (!deleting) { setDeleting(true); setTimeout(() => setDeleting(false), 4000); return; }
    await api(`/scans/${scanId}`, { method: 'DELETE' });
    window.location.hash = '#/';
  };

  return (
    <div className="page scan-view">
      <div className="scan-head">
        <div>
          <div className="crumbs muted small">{sourceLabel(scan.source)} · {timeAgo(scan.createdAt)} · {scan.meta.filesScanned} files · {scan.meta.dependenciesChecked} dependencies · {(scan.meta.durationMs / 1000).toFixed(1)}s scan</div>
          <h1>{scan.name}</h1>
        </div>
        <div className="row gap wrap">
          <button className="ghost-btn" onClick={() => download(`/scans/${scanId}/report.md`, `pandashield-report-${scanId}.md`)}>Download report</button>
          <button className="ghost-btn" onClick={() => download(`/scans/${scanId}/report.sarif`, `pandashield-${scanId}.sarif`)}>Export SARIF</button>
          <button className="ghost-btn" onClick={() => window.print()}>Print / PDF</button>
          <button className="ghost-btn danger" onClick={remove}>{deleting ? 'Click again to delete' : 'Delete'}</button>
        </div>
      </div>

      <div className="overview">
        <div className="card score-card">
          <ScoreRing score={scan.stats.securityScore} />
          <div className="sev-grid">
            {['critical', 'high', 'medium', 'low'].map((k) => (
              <button key={k} className={`sev-count sev-${k} ${sevFilter === k ? 'on' : ''}`} onClick={() => setSevFilter(sevFilter === k ? 'all' : k)}>
                <b>{sev[k] || 0}</b><span>{k}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="card ai-card">
          <div className="row between">
            <span className="ai-tag">✦ Gemini analysis</span>
            {scan.ai?.model && <span className="muted small">{scan.ai.model} · {scan.ai.triaged} findings triaged{scan.ai.latencyMs ? ` · ${(scan.ai.latencyMs / 1000).toFixed(1)}s` : ''}</span>}
          </div>
          {scan.ai?.error ? (
            <div>
              <p className="muted">{scan.ai.error}</p>
              <button className="primary-btn" onClick={retryAi} disabled={retrying}>{retrying ? 'Asking Gemini…' : 'Retry Gemini analysis'}</button>
            </div>
          ) : (
            <>
              <Markdown text={scan.ai?.executiveSummary} />
              {scan.ai?.fixFirst?.length > 0 && (
                <div className="fix-first">
                  <b className="small">Fix first</b>
                  <ol>
                    {scan.ai.fixFirst.map((id) => {
                      const f = scan.findings.find((x) => x.id === id);
                      return f ? <li key={id}><button className="link" onClick={() => setSelected(id)}>{f.title}</button> <span className="muted mono small">{f.file}{f.line ? `:${f.line}` : ''}</span></li> : null;
                    })}
                  </ol>
                </div>
              )}
            </>
          )}
          {scan.appContext && <p className="muted small context-line"><b>Context:</b> {scan.appContext}</p>}
        </div>
      </div>

      {scan.meta.dependencyError && <div className="alert warn">Dependency check incomplete: {scan.meta.dependencyError}</div>}
      {scan.findingsTruncated && <div className="alert warn">Showing the first {scan.findings.length} of {scan.findingCount} findings.</div>}

      <div className="filters">
        <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)} aria-label="Category">
          <option value="all">All categories ({scan.stats.total})</option>
          {Object.entries(CATEGORY_LABEL).map(([k, v]) => <option key={k} value={k}>{v} ({scan.stats.byCategory[k] || 0})</option>)}
        </select>
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} aria-label="Severity">
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Status">
          <option value="all">Any status</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v} ({statusCounts[k] || 0})</option>)}
        </select>
        <span className="muted small">{findings.length} shown · sorted by Gemini priority</span>
      </div>

      <div className={`split ${current ? 'has-detail' : ''}`}>
        <ul className="finding-list">
          {findings.length === 0 && (
            <li className="empty">
              {scan.stats.total === 0 ? <><b>No issues found.</b><p className="muted small">The scanners found nothing in these files. Clean scans are saved too.</p></> : <p className="muted">No findings match these filters.</p>}
            </li>
          )}
          {findings.map((f) => (
            <li key={f.id}>
              <button className={`finding-row ${selected === f.id ? 'active' : ''}`} onClick={() => setSelected(f.id)}>
                <div className="fr-top">
                  <SeverityBadge severity={f.severity} />
                  {f.ai?.priority && <span className={`prio prio-${f.ai.priority}`}>{f.ai.priority}</span>}
                  <span className="cat">{CATEGORY_LABEL[f.category]}</span>
                  {f.status !== 'open' && <span className="status-pill">{STATUS_LABEL[f.status]}</span>}
                </div>
                <div className="fr-title">{f.title}</div>
                <div className="fr-loc mono">{f.file}{f.line ? `:${f.line}` : ''}</div>
              </button>
            </li>
          ))}
        </ul>
        {current && (
          <FindingDetail key={current.id} scanId={scanId} finding={current} onClose={() => setSelected(null)}
            onUpdate={(patch) => updateFinding(current.id, patch)} />
        )}
      </div>

      <section className="print-only">
        <h2>Findings</h2>
        {scan.findings.map((f) => (
          <div key={f.id} className="print-finding">
            <h3>[{f.severity}] {f.title}</h3>
            <p className="mono">{f.file}{f.line ? `:${f.line}` : ''} · {f.cwe || ''} · status: {STATUS_LABEL[f.status]}</p>
            <p>{f.ai?.explanation || f.description}</p>
            {f.ai?.remediation && <Markdown text={f.ai.remediation} />}
          </div>
        ))}
      </section>
    </div>
  );
}

function sourceLabel(src) {
  if (!src) return '';
  if (src.type === 'github') return `GitHub · ${src.owner}/${src.repo}`;
  if (src.type === 'sample') return 'Demo app';
  return 'Uploaded files';
}
