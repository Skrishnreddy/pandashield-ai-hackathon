import { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';

const SKIP = /(^|\/)(node_modules|\.git|dist|build|vendor|\.next|coverage|__pycache__|\.venv|venv|target)(\/|$)/;
const TEXT = /\.(js|jsx|mjs|cjs|ts|tsx|py|java|go|rb|php|cs|kt|swift|rs|c|cc|cpp|h|sh|bash|yml|yaml|json|toml|ini|cfg|conf|env|xml|html|htm|vue|svelte|tf|sql|properties|gradle|txt|md)$|(^|\/)(Dockerfile|\.env(\..+)?)$/i;

export default function NewScan({ model, hasHistory }) {
  const [mode, setMode] = useState('sample');
  const [samples, setSamples] = useState([]);
  const [sampleId, setSampleId] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [files, setFiles] = useState([]);
  const [pasteName, setPasteName] = useState('snippet.js');
  const [paste, setPaste] = useState('');
  const [appContext, setAppContext] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [drag, setDrag] = useState(false);
  const fileInput = useRef(null);
  const dirInput = useRef(null);

  useEffect(() => {
    api('/samples').then((d) => {
      setSamples(d.samples);
      if (d.samples[0]) setSampleId(d.samples[0].id);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!busy) return undefined;
    const t0 = Date.now();
    const iv = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500);
    return () => clearInterval(iv);
  }, [busy]);

  const addFiles = async (list) => {
    const picked = [];
    for (const f of list) {
      const p = f.webkitRelativePath || f.name;
      if (SKIP.test(p) || !TEXT.test(p) || f.size > 512 * 1024) continue;
      picked.push({ path: p, content: await f.text() });
      if (picked.length >= 400) break;
    }
    setFiles((prev) => {
      const map = new Map(prev.map((x) => [x.path, x]));
      picked.forEach((x) => map.set(x.path, x));
      return [...map.values()];
    });
  };

  const sample = samples.find((s) => s.id === sampleId);

  const canRun = !busy && (
    (mode === 'sample' && sampleId)
    || (mode === 'github' && /^https:\/\/github\.com\/[^/]+\/[^/]+/.test(repoUrl.trim()))
    || (mode === 'upload' && files.length > 0)
    || (mode === 'paste' && paste.trim().length > 0 && pasteName.trim()));

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      let body;
      if (mode === 'sample') body = { source: 'sample', sampleId, appContext };
      else if (mode === 'github') body = { source: 'github', repoUrl: repoUrl.trim(), appContext };
      else if (mode === 'upload') body = { source: 'files', files, appContext };
      else body = { source: 'files', files: [{ path: pasteName.trim(), content: paste }], appContext };
      const scan = await api('/scans', { method: 'POST', body });
      window.location.hash = `#/scan/${scan.id}`;
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    <div className="page new-scan">
      <div className="page-head">
        <h1>{hasHistory ? 'New security scan' : 'Run your first security scan'}</h1>
        <p className="muted">PandaShield runs real scanners on the code you choose, then Gemini triages every verified finding.</p>
      </div>

      <div className="card">
        <div className="tabs" role="tablist">
          {[['sample', 'Demo app'], ['github', 'GitHub repo'], ['upload', 'Upload files'], ['paste', 'Paste code']].map(([k, label]) => (
            <button key={k} role="tab" aria-selected={mode === k} className={`tab ${mode === k ? 'active' : ''}`} onClick={() => setMode(k)} disabled={busy}>{label}</button>
          ))}
        </div>

        {mode === 'sample' && (
          <div className="tab-body">
            {samples.length === 0 && <p className="muted">No built-in samples are available.</p>}
            {samples.map((s) => (
              <label key={s.id} className={`sample ${sampleId === s.id ? 'selected' : ''}`}>
                <input type="radio" name="sample" checked={sampleId === s.id} onChange={() => setSampleId(s.id)} />
                <div>
                  <b>{s.name}</b>
                  <p className="muted small">{s.description}</p>
                </div>
              </label>
            ))}
          </div>
        )}

        {mode === 'github' && (
          <div className="tab-body">
            <label className="field">
              <span>Public repository URL</span>
              <input type="url" placeholder="https://github.com/owner/repo" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} disabled={busy} />
            </label>
            <p className="muted small">Public repositories only. PandaShield downloads the source archive into memory, reads up to 400 text files, and never runs the code. Add <code>/tree/branch</code> to scan a branch.</p>
          </div>
        )}

        {mode === 'upload' && (
          <div className="tab-body">
            <div className={`dropzone ${drag ? 'drag' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); addFiles([...e.dataTransfer.files]); }}>
              <p><b>Drop source files here</b></p>
              <p className="muted small">JavaScript, TypeScript, Python, Dockerfiles, YAML, package.json, package-lock.json, requirements.txt …</p>
              <div className="row gap">
                <button className="ghost-btn" onClick={() => fileInput.current.click()} disabled={busy}>Choose files</button>
                <button className="ghost-btn" onClick={() => dirInput.current.click()} disabled={busy}>Choose a folder</button>
              </div>
              <input ref={fileInput} type="file" multiple hidden onChange={(e) => addFiles([...e.target.files])} />
              <input ref={dirInput} type="file" webkitdirectory="" directory="" multiple hidden onChange={(e) => addFiles([...e.target.files])} />
            </div>
            {files.length > 0 && (
              <div className="file-list">
                <div className="row between"><b>{files.length} file{files.length > 1 ? 's' : ''} ready</b><button className="mini-btn" onClick={() => setFiles([])}>Clear</button></div>
                <ul>{files.slice(0, 8).map((f) => <li key={f.path} className="mono small">{f.path}</li>)}</ul>
                {files.length > 8 && <p className="muted small">and {files.length - 8} more</p>}
              </div>
            )}
          </div>
        )}

        {mode === 'paste' && (
          <div className="tab-body">
            <label className="field">
              <span>File name (sets the language)</span>
              <input value={pasteName} onChange={(e) => setPasteName(e.target.value)} placeholder="app.py" disabled={busy} />
            </label>
            <label className="field">
              <span>Code</span>
              <textarea className="mono" rows={10} value={paste} onChange={(e) => setPaste(e.target.value)} placeholder="Paste code to analyse…" disabled={busy} />
            </label>
          </div>
        )}

        <label className="field context">
          <span>Application context <em className="muted">(optional, helps Gemini prioritise)</em></span>
          <textarea rows={3} value={appContext} onChange={(e) => setAppContext(e.target.value)} disabled={busy}
            placeholder={mode === 'sample' && sample?.appContext ? sample.appContext : 'e.g. Internet-facing payments API, handles customer PII, deployed on Cloud Run'} />
        </label>

        {error && <div className="alert error" role="alert">{error}</div>}

        <div className="run-row">
          <button className="primary-btn big" onClick={run} disabled={!canRun} data-testid="run-scan">
            {busy ? 'Analysing…' : 'Run security analysis'}
          </button>
          {busy && (
            <div className="progress" aria-live="polite">
              <div className="spinner small" />
              <span>Scanning, checking OSV.dev and asking Gemini ({model}) to triage the findings. This usually takes 10–40 seconds. {elapsed}s</span>
            </div>
          )}
        </div>
      </div>

      <div className="how-grid">
        <div className="mini-card"><b>Code analysis</b><p className="muted small">Injection, XSS, SSRF, path traversal, unsafe deserialisation, weak crypto and misconfigurations in JS/TS, Python and Docker.</p></div>
        <div className="mini-card"><b>Secret detection</b><p className="muted small">Cloud keys, tokens, private keys and credentials. Values are redacted before storage or AI analysis.</p></div>
        <div className="mini-card"><b>Dependency CVEs</b><p className="muted small">npm and PyPI packages checked against the OSV.dev vulnerability database with fixed versions.</p></div>
      </div>
    </div>
  );
}
