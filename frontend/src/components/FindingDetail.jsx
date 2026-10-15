import { useState } from 'react';
import { api } from '../api.js';
import { SeverityBadge, Markdown, CopyButton } from './ui.jsx';

const STATUSES = [
  ['open', 'Open'],
  ['fixed', 'Mark fixed'],
  ['accepted_risk', 'Accept risk'],
  ['false_positive', 'False positive'],
];

const SUGGESTED = [
  'How would I test that this is fixed?',
  'Is this exploitable if the endpoint needs authentication?',
  'Show the fix for the whole function.',
];

export default function FindingDetail({ scanId, finding: f, onClose, onUpdate }) {
  const [saving, setSaving] = useState(null);
  const [question, setQuestion] = useState('');
  const [asking, setAsking] = useState(false);
  const [askError, setAskError] = useState(null);
  const ai = f.ai;

  const setStatus = async (status) => {
    setSaving(status);
    try {
      await api(`/scans/${scanId}/findings/${f.id}`, { method: 'PATCH', body: { status } });
      onUpdate({ status });
    } catch (e) {
      setAskError(e.message);
    } finally {
      setSaving(null);
    }
  };

  const ask = async (q) => {
    const text = (q ?? question).trim();
    if (text.length < 3) return;
    setAsking(true);
    setAskError(null);
    try {
      const entry = await api(`/scans/${scanId}/findings/${f.id}/ask`, { method: 'POST', body: { question: text } });
      onUpdate({ conversation: [...(f.conversation || []), entry] });
      setQuestion('');
    } catch (e) {
      setAskError(e.message);
    } finally {
      setAsking(false);
    }
  };

  return (
    <article className="detail card" aria-label="Finding details">
      <div className="row between">
        <div className="row gap wrap">
          <SeverityBadge severity={f.severity}>{f.severity}</SeverityBadge>
          {ai?.contextualSeverity && ai.contextualSeverity !== f.severity && (
            <span className="muted small">Gemini: <SeverityBadge severity={ai.contextualSeverity} /> in your context</span>
          )}
          {ai?.priority && <span className={`prio prio-${ai.priority}`}>{ai.priority}</span>}
        </div>
        <button className="icon-btn" onClick={onClose} aria-label="Close details">✕</button>
      </div>
      <h2>{f.title}</h2>
      <div className="meta-row mono small">
        <span>{f.file}{f.line ? `:${f.line}` : ''}</span>
        {f.cwe && <a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer">{f.cwe}</a>}
        {f.owasp && <span>{f.owasp}</span>}
      </div>

      {f.snippet ? (
        <pre className="code-block numbered" aria-label="Code snippet">
          {f.snippet.lines.map((l, i) => {
            const n = f.snippet.startLine + i;
            return <div key={n} className={n === f.line ? 'hl' : ''}><span className="ln">{n}</span>{l || ' '}</div>;
          })}
        </pre>
      ) : (
        <pre className="code-block"><code>{f.evidence}</code></pre>
      )}

      {f.advisory && (
        <div className="advisory">
          <a href={f.advisory.url} target="_blank" rel="noreferrer">{f.advisory.id}</a>
          {f.advisory.cve && <span>{f.advisory.cve}</span>}
          {f.advisory.cvss != null && <span>CVSS {f.advisory.cvss}</span>}
          {f.advisory.fixedIn?.length > 0 && <span>Fixed in {f.advisory.fixedIn.join(', ')}</span>}
        </div>
      )}

      {ai ? (
        <div className="ai-block">
          <span className="ai-tag">✦ Gemini explanation</span>
          <Markdown text={ai.explanation} />
          {ai.priorityReason && <p className="muted small"><b>Why {ai.priority}:</b> {ai.priorityReason}</p>}
          {ai.falsePositiveLikelihood !== 'low' && <div className="alert warn small">Gemini rates the false-positive likelihood as <b>{ai.falsePositiveLikelihood}</b>. Review before acting.</div>}
          {ai.attackScenario && <><h4>Attack scenario</h4><Markdown text={ai.attackScenario} /></>}
          {ai.remediation && <><h4>How to fix</h4><Markdown text={ai.remediation} /></>}
          {ai.fixedCode && (
            <>
              <div className="row between"><h4>Suggested fix</h4><CopyButton text={ai.fixedCode} label="Copy fix" /></div>
              <pre className="code-block ok"><code>{ai.fixedCode}</code></pre>
            </>
          )}
        </div>
      ) : (
        <div className="ai-block">
          <h4>Scanner description</h4>
          <p>{f.description}</p>
          <p className="muted small">Gemini analysis covers the highest-severity findings first; this one was not included in the AI batch.</p>
        </div>
      )}

      <div className="status-row">
        {STATUSES.map(([k, label]) => (
          <button key={k} className={`chip ${f.status === k ? 'on' : ''}`} disabled={!!saving} onClick={() => setStatus(k)}>
            {saving === k ? 'Saving…' : label}
          </button>
        ))}
      </div>

      <div className="ask">
        <h4>Ask Gemini about this finding</h4>
        {(f.conversation || []).map((m, i) => (
          <div key={i} className="qa">
            <div className="q">{m.question}</div>
            <div className="a"><Markdown text={m.answer} /></div>
          </div>
        ))}
        {!(f.conversation || []).length && (
          <div className="row gap wrap">
            {SUGGESTED.map((s) => <button key={s} className="chip" onClick={() => ask(s)} disabled={asking}>{s}</button>)}
          </div>
        )}
        <form className="ask-form" onSubmit={(e) => { e.preventDefault(); ask(); }}>
          <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask a follow-up question…" maxLength={500} disabled={asking} aria-label="Question for Gemini" />
          <button className="primary-btn" disabled={asking || question.trim().length < 3}>{asking ? 'Thinking…' : 'Ask'}</button>
        </form>
        {askError && <p className="error-text" role="alert">{askError}</p>}
      </div>
    </article>
  );
}
