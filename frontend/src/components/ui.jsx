export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function SeverityBadge({ severity, children }) {
  return <span className={`sev sev-${severity}`}>{children || severity}</span>;
}

export function SeverityDots({ stats }) {
  const s = stats?.bySeverity || {};
  return (
    <span className="dots" aria-label={`${s.critical || 0} critical, ${s.high || 0} high, ${s.medium || 0} medium, ${s.low || 0} low`}>
      {['critical', 'high', 'medium', 'low'].map((k) => (s[k] ? <span key={k} className={`dot dot-${k}`}>{s[k]}</span> : null))}
      {!stats?.total && <span className="dot dot-clean">clean</span>}
    </span>
  );
}

export function ScoreRing({ score }) {
  const r = 42;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score ?? 0));
  const color = pct >= 80 ? 'var(--ok)' : pct >= 50 ? 'var(--medium)' : pct >= 25 ? 'var(--high)' : 'var(--critical)';
  return (
    <div className="score-ring" role="img" aria-label={`Security score ${pct} out of 100`}>
      <svg viewBox="0 0 100 100" width="112" height="112">
        <circle cx="50" cy="50" r={r} stroke="var(--line)" strokeWidth="9" fill="none" />
        <circle cx="50" cy="50" r={r} stroke={color} strokeWidth="9" fill="none" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - pct / 100)} transform="rotate(-90 50 50)" />
      </svg>
      <div className="score-val"><b>{pct}</b><span>/100</span></div>
    </div>
  );
}

export function timeAgo(iso) {
  if (!iso) return 'just now';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

// Minimal, safe Markdown renderer (no HTML injection): paragraphs, lists,
// bold, inline code and fenced code blocks.
export function Markdown({ text }) {
  if (!text) return null;
  const blocks = String(text).split(/```/);
  return (
    <div className="md">
      {blocks.map((b, i) => (i % 2 === 1
        ? <pre key={i} className="code-block"><code>{b.replace(/^[a-zA-Z0-9]*\n/, '')}</code></pre>
        : <MdText key={i} text={b} />))}
    </div>
  );
}

function MdText({ text }) {
  const lines = text.split('\n');
  const out = [];
  let list = null;
  const flush = () => { if (list) { out.push(list); list = null; } };
  lines.forEach((line, i) => {
    const li = line.match(/^\s*(?:[-*]|\d+[.)])\s+(.*)/);
    if (li) {
      if (!list) list = { type: /^\s*\d/.test(line) ? 'ol' : 'ul', items: [] };
      list.items.push(li[1]);
      return;
    }
    flush();
    if (line.trim()) out.push({ type: 'p', text: line.replace(/^#+\s*/, ''), key: i });
  });
  flush();
  return out.map((b, i) => {
    if (b.type === 'p') return <p key={i}>{inline(b.text)}</p>;
    const Tag = b.type;
    return <Tag key={i}>{b.items.map((t, j) => <li key={j}>{inline(t)}</li>)}</Tag>;
  });
}

function inline(text) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((p, i) => {
    if (p.startsWith('`') && p.endsWith('`')) return <code key={i}>{p.slice(1, -1)}</code>;
    if (p.startsWith('**') && p.endsWith('**')) return <strong key={i}>{p.slice(2, -2)}</strong>;
    return p;
  });
}

export function CopyButton({ text, label = 'Copy' }) {
  return (
    <button className="mini-btn" onClick={(e) => {
      navigator.clipboard?.writeText(text);
      const el = e.currentTarget;
      el.textContent = 'Copied ✓';
      setTimeout(() => { el.textContent = label; }, 1400);
    }}>{label}</button>
  );
}
