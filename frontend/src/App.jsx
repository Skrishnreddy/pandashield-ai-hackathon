import { useEffect, useState } from 'react';
import { initFirebase, watchAuth, logout, watchScanHistory } from './firebase.js';
import Landing from './components/Landing.jsx';
import NewScan from './components/NewScan.jsx';
import ScanView from './components/ScanView.jsx';
import Diagnostics from './components/Diagnostics.jsx';
import { SeverityDots, timeAgo } from './components/ui.jsx';

function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash || '#/');
  useEffect(() => {
    const on = () => setHash(window.location.hash || '#/');
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return hash.replace(/^#/, '') || '/';
}

export default function App() {
  const [boot, setBoot] = useState({ ready: false, error: null, cfg: null });
  const [user, setUser] = useState(undefined);
  const [history, setHistory] = useState(null);
  const [historyError, setHistoryError] = useState(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const route = useHashRoute();

  useEffect(() => {
    initFirebase()
      .then(({ cfg }) => {
        setBoot({ ready: true, error: null, cfg });
        return watchAuth((u) => setUser(u || null));
      })
      .catch((e) => setBoot({ ready: true, error: e.message, cfg: null }));
  }, []);

  useEffect(() => {
    if (!user) { setHistory(null); return undefined; }
    return watchScanHistory(user.uid, (items) => { setHistory(items); setHistoryError(null); }, (e) => setHistoryError(e.message));
  }, [user]);

  useEffect(() => { setMenuOpen(false); }, [route]);

  if (!boot.ready || user === undefined) {
    if (boot.error) return <FatalError message={boot.error} />;
    return <div className="boot"><img src="/logo.svg" alt="" width="56" height="56" /><div className="spinner" aria-label="Loading" /></div>;
  }
  if (!user) return <Landing emulator={!!boot.cfg?.emulators?.auth} model={boot.cfg?.gemini?.model} />;

  const scanMatch = route.match(/^\/scan\/([A-Za-z0-9]+)$/);
  let page;
  if (scanMatch) page = <ScanView key={scanMatch[1]} scanId={scanMatch[1]} />;
  else if (route === '/status') page = <Diagnostics />;
  else page = <NewScan model={boot.cfg?.gemini?.model} hasHistory={!!history?.length} />;

  return (
    <div className="shell">
      <header className="topbar">
        <button className="icon-btn only-mobile" aria-label="Open scan history" onClick={() => setMenuOpen((v) => !v)}>☰</button>
        <a href="#/" className="brand">
          <img src="/logo.svg" alt="" width="30" height="30" />
          <span>PandaShield <b>AI</b></span>
          <span className="edition">Hackathon Edition</span>
        </a>
        <nav className="top-actions">
          <a href="#/status" className={`ghost-btn ${route === '/status' ? 'active' : ''}`}>System status</a>
          <div className="user-chip" title={user.email || ''}>
            {user.photoURL ? <img src={user.photoURL} alt="" referrerPolicy="no-referrer" /> : <span className="avatar">{(user.displayName || user.email || '?')[0]}</span>}
            <span className="hide-mobile">{user.displayName || user.email}</span>
          </div>
          <button className="ghost-btn" onClick={logout}>Sign out</button>
        </nav>
      </header>
      <div className="body">
        <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
          <a href="#/" className="primary-btn wide">＋ New security scan</a>
          <div className="sidebar-title">
            <span>Scan history</span>
            <span className="badge-soft" title="Live from Firestore">● live</span>
          </div>
          {historyError && <p className="muted small">Could not load history: {historyError}</p>}
          {!history && !historyError && <div className="skeleton-list">{[0, 1, 2].map((i) => <div key={i} className="skeleton" />)}</div>}
          {history && history.length === 0 && <p className="muted small">No scans yet. Your saved analyses will appear here.</p>}
          <ul className="history">
            {history?.map((s) => (
              <li key={s.id}>
                <a href={`#/scan/${s.id}`} className={scanMatch?.[1] === s.id ? 'active' : ''}>
                  <span className="h-name">{s.name}</span>
                  <span className="h-meta">
                    <SeverityDots stats={s.stats} />
                    <span>{timeAgo(s.createdAt)}</span>
                  </span>
                </a>
              </li>
            ))}
          </ul>
          <a href="#/status" className="sidebar-link only-mobile">System status</a>
        </aside>
        {menuOpen && <div className="scrim only-mobile" onClick={() => setMenuOpen(false)} />}
        <main className="main">{page}</main>
      </div>
    </div>
  );
}

function FatalError({ message }) {
  return (
    <div className="boot">
      <img src="/logo.svg" alt="" width="56" height="56" />
      <h2>PandaShield could not start</h2>
      <p className="muted">{message}</p>
    </div>
  );
}
