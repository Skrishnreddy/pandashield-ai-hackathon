import { useEffect, useState } from 'react';
import { api } from '../api.js';

const LABELS = {
  auth: ['Firebase Authentication', 'Your ID token was verified by the Cloud Run API with the Firebase Admin SDK.'],
  firestore: ['Cloud Firestore', 'The API wrote a document and read it back.'],
  gemini: ['Gemini', 'The API sent a live prompt to Gemini and received a response.'],
};

export default function Diagnostics() {
  const [data, setData] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, d] = await Promise.all([fetch('/health').then((r) => r.json()), api('/diagnostics')]);
      setHealth(h);
      setData(d);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { run(); }, []);

  return (
    <div className="page">
      <div className="page-head row between wrap">
        <div>
          <h1>System status</h1>
          <p className="muted">Live checks of every Google Cloud integration, run from this deployment.</p>
        </div>
        <button className="ghost-btn" onClick={run} disabled={loading}>{loading ? 'Checking…' : 'Run checks again'}</button>
      </div>
      {error && <div className="alert error">{error}</div>}
      <div className="status-grid">
        <div className="card status-card">
          <span className={`status-dot ${health ? 'ok' : loading ? 'wait' : 'bad'}`} />
          <div>
            <b>Cloud Run</b>
            <p className="muted small">{health ? `Healthy · revision ${health.revision}` : 'Checking /health…'}</p>
          </div>
        </div>
        {Object.entries(LABELS).map(([k, [title, desc]]) => {
          const c = data?.checks?.[k];
          return (
            <div className="card status-card" key={k}>
              <span className={`status-dot ${c ? (c.ok ? 'ok' : 'bad') : 'wait'}`} />
              <div>
                <b>{title}</b>
                <p className="muted small">{c ? `${c.ok ? '' : 'Failed: '}${c.detail} · ${c.ms} ms` : 'Checking…'}</p>
                <p className="muted small">{desc}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
