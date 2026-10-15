# QA report — PandaShield AI Hackathon Edition

Results below were produced by actually running the test suites. Anything not yet executed is marked **NOT RUN** with the reason.

## Run 1 — local, 15 Oct 2026 (before deployment)

Environment: Linux, Node.js 22.22, Firebase CLI 15.34 with Auth + Firestore emulators (Firestore emulator 1.22.0), Chromium via Playwright 1.56.

| Suite | Command | Result |
|---|---|---|
| Unit + API | `cd backend && npm test` | **35 / 35 passed** |
| Firebase emulator integration | `cd backend && npm run test:emulator` | **7 / 7 passed** |
| Browser end-to-end (desktop + mobile) | `tests/e2e/run.sh` | **5 / 5 passed** |
| Dependency audit | `npm audit` (backend, frontend) | **0 vulnerabilities** |

### Coverage of the requested test areas

| Area | Covered by | Status |
|---|---|---|
| Main user workflow | e2e "main workflow" (sign in → scan demo app → review → mark fixed → ask → download report → reload) and API "full workflow" | Passed |
| Security analysis | 33 SAST rules each with a positive case, 8 negative (safe-code) cases, secret detection, manifest parsing, CVSS scoring, OSV lookups (mocked), demo-app scan finds all 18 planted vulnerability classes | Passed |
| Gemini request/response | Structured-output config, prompt fencing of untrusted input, invented-finding rejection, malformed output handling, error fallback and retry (mocked Gemini client) | Passed (mocked). **Live Gemini: NOT RUN** — needs the deployed project's Vertex AI access |
| Firestore persistence | Emulator: write scan + findings, reopen, list, status update, Q&A append, re-triage, recursive delete | Passed (emulator). **Production Firestore: NOT RUN** — pending deployment |
| Firebase functionality | Emulator: real ID token verified by Admin SDK, tampered token rejected; browser history read live via Firestore Web SDK | Passed (emulator) |
| Authorization / data access | API: other users get 404 on read, update, ask, delete; emulator: Firestore rules block cross-user reads and all browser writes | Passed |
| Input validation | Path traversal in file names, empty input, bad JSON, oversized body (413), invalid ids, unknown samples, unsafe GitHub URLs (non-https, other hosts, credentials, ports, `..`, metadata IP) | Passed |
| Error handling | Gemini outage saves scanner results with a retry; OSV outage reported without failing the scan; missing GitHub repo → 404 message | Passed |
| Secrets never leak | Raw demo secrets absent from scan JSON, Markdown report and UI | Passed |
| Report generation | Markdown and SARIF 2.1.0 via API; Markdown download from the browser | Passed |
| Mobile layout | 390×844 viewport: no horizontal overflow on landing, new scan, scan view; history drawer works | Passed |
| Browser console | No console errors or HTTP 5xx during the e2e run (expected 400s from the deliberate invalid-input test and emulator sign-in probe are excluded) | Passed |
| Cloud Run health | Production-mode server started from a clean `npm ci --omit=dev`: `/healthz` 200, SPA served, `/api/scans` 401 without token | Passed locally. **On Cloud Run: NOT RUN** — pending approval |
| Docker image build | — | **NOT RUN** — no Docker daemon in the build sandbox; Cloud Build will build it on deploy |
| Live OSV.dev and GitHub download | — | **NOT RUN** — blocked by the build sandbox network; verify after deploy |

### Notes

- Gemini and OSV were replaced with stubs only inside tests; stubbed text in e2e screenshots is prefixed `[TEST STUB]`. Those screenshots are test evidence, not product screenshots for the pitch deck.
- Bugs found and fixed during this run: SQL-concatenation and NoSQL `$where` rules missed strings containing the other quote type; four negative-lookahead rules could be bypassed by a space; `..` segments in GitHub URLs were normalised instead of rejected.

## Run 2 — deployed service, 15 Oct 2026

Service: `https://pandashield-hackathon-618305969514.asia-south1.run.app` (Cloud Run, asia-south1, project `pandashield-hackathon-rmjgau`, revision `pandashield-hackathon-00004-98g`).

| Check | Evidence | Result |
|---|---|---|
| Docker image build | Built by Cloud Build on deploy (`gcloud run deploy --source .`) | Passed |
| Cloud Run health and edge checks | `deployment/verify.sh`: `/health` ok, SPA served, public Firebase config present, `/api/scans` 401 anonymous and with a forged token, CSP header present | **6 / 6 passed** |
| Firebase Auth (Google sign-in) | Signed in on the deployed site; API accepted the Firebase ID token | Passed |
| Production Firestore + live Gemini | A scan run from the deployed UI: `POST /api/scans` 201, 59 findings saved, 30 triaged by Gemini 3.8 Flash on Vertex AI, scan reopened (200), Markdown report downloaded (200) | Passed |
| Live OSV.dev and GitHub download | Deployed scanner code run against real public repos (below): tarballs from codeload.github.com and live OSV.dev lookups | Passed |
| Unit + API (after scanner fixes below) | `cd backend && npm test` | **37 / 37 passed** |

### Real-repository scans

| Repository | Input path | Files | Findings | Notes |
|---|---|---|---|---|
| OWASP/NodeGoat (intentionally vulnerable) | GitHub URL | 84 | 42 | eval() injection, MongoDB `$where` injection, open redirect, hard-coded secrets (redacted), 17 dependency advisories (1 critical) |
| appsecco/dvna (intentionally vulnerable) | Folder upload (same filter as the browser's folder picker) | 39 | 40 | All 6 known code flaws: SQL injection, command injection, unsafe deserialisation, XXE, mathjs eval, open redirect; plus 36 dependency advisories |
| expressjs/express (well maintained) | GitHub URL | 172 | 4 | 0 vulnerable dependencies out of 44; the 4 code hits are XSS payload strings in a test file |

### Bugs found and fixed during this run

- Container failed to start (`EACCES` on `server.js`): source files were mode 600 and the image runs as the non-root `node` user. Fixed with `COPY --chown=node:node` in the final stage.
- `/healthz` is reserved by Cloud Run's front end and returned Google's 404. Added the `/health` alias and switched the System status page, Vite proxy and `verify.sh` to it.
- SQL injection was missed when the query is built in a variable before being executed (DVNA). The `js.sql-concat` rule now also matches SQL-shaped literals concatenated with input anywhere.
- Added `js.xxe` (libxmljs `noent: true`) and `js.expression-eval` (`mathjs.eval(req.body…)`), so there are now 35 SAST rules.
- `js.eval` fired on prose such as `<code>eval()</code>` in HTML. Empty calls are now ignored (NodeGoat: 14 → 6 hits).

### Known limits

- SAST is line-based: taint that flows through several variables (e.g. NodeGoat's SSRF in `research.js`) is not detected.
- `.ejs` templates are not scanned.
- JavaScript rules also run over HTML, so code samples in documentation pages can appear. Gemini's false-positive likelihood flags these.
