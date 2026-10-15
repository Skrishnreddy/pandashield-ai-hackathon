import { useState } from 'react';
import { signInWithGoogle, emulatorSignIn } from '../firebase.js';

export default function Landing({ emulator, model }) {
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const go = async (fn) => {
    setBusy(true);
    setError(null);
    try { await fn(); } catch (e) { setError(e.code === 'auth/popup-closed-by-user' ? 'Sign-in was cancelled.' : e.message); } finally { setBusy(false); }
  };

  return (
    <div className="landing">
      <header className="landing-top">
        <div className="brand">
          <img src="/logo.svg" alt="" width="34" height="34" />
          <span>PandaShield <b>AI</b></span>
          <span className="edition">Hackathon Edition</span>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <span className="eyebrow">Powered by Gemini on Google Cloud</span>
          <h1>Your AI security analyst for every pull request.</h1>
          <p className="lead">
            PandaShield scans your code, secrets and dependencies with deterministic scanners, then Gemini explains each verified finding in plain language, ranks what to fix first for <em>your</em> application, and writes the fix.
          </p>
          <div className="hero-actions">
            <button className="primary-btn big" disabled={busy} onClick={() => go(signInWithGoogle)}>
              <GoogleIcon /> {busy ? 'Signing in…' : 'Sign in with Google to start'}
            </button>
            {emulator && (
              <button className="ghost-btn" data-testid="emulator-signin" disabled={busy}
                onClick={() => go(() => emulatorSignIn('demo.user@example.com', 'emulator-only-password'))}>
                Local emulator sign-in
              </button>
            )}
          </div>
          {error && <p className="error-text" role="alert">{error}</p>}
          <p className="muted small">Free to try. Your scans are private to your account.</p>
        </div>
        <div className="hero-card" aria-hidden="true">
          <div className="hc-label">Example of a triaged finding</div>
          <div className="hc-row"><span className="sev sev-critical">critical</span><span className="mono">src/server.js:37</span></div>
          <div className="hc-title">SQL query built with string concatenation</div>
          <pre className="hc-code">{"db.query(`SELECT * FROM orders\n  WHERE status = '${status}'`)"}</pre>
          <div className="hc-ai">
            <span className="ai-tag">✦ Gemini</span>
            <p>An attacker can send <code>status=' OR '1'='1</code> to read every customer&apos;s orders. Use a parameterised query:</p>
            <pre className="hc-code ok">{"db.query('SELECT * FROM orders WHERE status = $1', [status])"}</pre>
          </div>
        </div>
      </section>

      <section className="steps">
        {[
          ['1', 'Scan', 'Point PandaShield at a public GitHub repo, upload files, or try the built-in vulnerable demo app.'],
          ['2', 'Verify', '30+ code rules, secret detection with automatic redaction, and live CVE lookups from OSV.dev.'],
          ['3', 'Understand', `Gemini (${model || 'Gemini'}) explains each finding, the attack scenario, and its real priority in your app's context.`],
          ['4', 'Fix & track', 'Copy the fix, ask follow-up questions, mark findings fixed, and export Markdown or SARIF reports.'],
        ].map(([n, t, d]) => (
          <div className="step" key={n}><span className="step-n">{n}</span><h3>{t}</h3><p>{d}</p></div>
        ))}
      </section>

      <section className="trust">
        <div><h4>No hallucinated findings</h4><p>Gemini only reasons about evidence the scanners verified. Anything it returns for unknown findings is discarded.</p></div>
        <div><h4>Secrets stay secret</h4><p>Detected credentials are redacted before they are stored in Firestore or sent to Gemini.</p></div>
        <div><h4>Your code is never executed</h4><p>Repositories are read as text in memory with strict size limits. Nothing is run.</p></div>
      </section>

      <footer className="landing-foot">
        PandaShield AI — Hackathon Edition. Built with Gemini, Firebase Authentication, Cloud Firestore and Cloud Run.
      </footer>
    </div>
  );
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
    </svg>
  );
}
