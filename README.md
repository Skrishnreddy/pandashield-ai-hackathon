# PandaShield AI — Hackathon Edition

> Scanner-verified security findings, explained, prioritised and fixed with Gemini.

**Live prototype:** https://pandashield-hackathon-618305969514.asia-south1.run.app
**Demo video:** _added after recording_
**Built for:** Google Cloud AI Builder Cup 2026 · Theme: Future of Work & Enterprise Productivity

This repository is an **independent hackathon build**. It shares the PandaShield name with an existing product, but every line of code, configuration, data store and cloud resource here was created from scratch for this hackathon and is separate from that product.

---

## The problem

Developers ship code faster than security teams can review it. Traditional scanners produce long lists of findings with CWE numbers and little context, so developers either ignore them or spend hours working out which ones matter and how to fix them. AI assistants can explain code, but on their own they can also invent vulnerabilities that do not exist.

## The solution

PandaShield AI combines **deterministic scanners** with **Gemini reasoning**:

1. **Scan** a public GitHub repository, uploaded files, pasted code, or the built-in vulnerable demo app.
2. **Verify** with real scanners: 35 code rules (injection, XSS, SSRF, path traversal, unsafe deserialisation, weak crypto, JWT and TLS misconfiguration, Docker hardening), secret detection with redaction, and dependency CVEs from [OSV.dev](https://osv.dev).
3. **Understand** with Gemini: plain-language explanation, a realistic attack scenario, and a contextual priority (P1–P4) based on what the app does.
4. **Fix** with Gemini-written remediation steps and corrected code; ask follow-up questions per finding.
5. **Track** status (fixed / accepted risk / false positive) in Firestore, reopen any past scan, and export Markdown or SARIF reports.

**Gemini never invents findings.** It only receives evidence the scanners verified; any finding id it returns that the scanners did not produce is discarded (`backend/src/ai/gemini.js`, `parseTriage`). Secrets are redacted before anything is stored or sent to Gemini, and scanned code is only ever read as text, never executed.

## Google technology

| Technology | How PandaShield uses it | Where |
|---|---|---|
| **Gemini** (`gemini-3.8-flash` via Vertex AI) | Structured JSON triage of every verified finding (explanation, attack scenario, contextual priority, remediation, fixed code, false-positive likelihood), an executive summary with a "fix first" list, and per-finding follow-up Q&A | `backend/src/ai/gemini.js` |
| **Firebase Authentication** | Google sign-in in the browser; the Cloud Run API verifies the Firebase ID token on every request with the Admin SDK | `frontend/src/firebase.js`, `backend/src/auth.js` |
| **Cloud Firestore** | Per-user data model `users/{uid}/scans/{scanId}/findings/{findingId}`; the API writes, the browser reads its own history live with `onSnapshot`; security rules block cross-user reads and all browser writes | `backend/src/store/scans.js`, `firebase/firestore.rules` |
| **Cloud Run** | One container serving the React app and the Node.js API, using its own least-privilege service account for Vertex AI and Firestore (no API keys) | `Dockerfile`, `deployment/` |

## Architecture

```
Browser (React + Firebase Web SDK)
  │  Google sign-in (Firebase Auth) ──────────────► Firebase Authentication
  │  live history (read-only, security rules) ────► Cloud Firestore
  │  HTTPS + Firebase ID token
  ▼
Cloud Run: pandashield-hackathon (Node.js / Express)
  ├─ verifies ID token (Firebase Admin SDK)
  ├─ input validation, size limits, per-user rate limits
  ├─ scanners: PandaShield SAST · secret detection + redaction · OSV.dev dependency lookup
  ├─ Gemini triage + Q&A (Vertex AI, service account) ──► Gemini 3.8 Flash
  └─ persistence (Admin SDK) ─────────────────────────► Cloud Firestore
```

A diagram is in [`docs/architecture.svg`](docs/architecture.svg).

## Repository layout

```
backend/      Express API, scanners, Gemini, Firestore store, unit/API/emulator tests
frontend/     React + Vite single-page app
firebase/     Firestore security rules, indexes, emulator config
samples/      Intentionally vulnerable demo app (scan target only, never executed)
tests/e2e/    Playwright browser tests against the Firebase emulators
deployment/   Cloud Run deployment plan and scripts
docs/         Architecture, solution description, QA report
presentation/ Pitch deck source and exports
video/        Demo video script and capture plan
submission/   Final submission package
```

## Run locally

Requirements: Node.js 20+, Java 11+ (for the Firebase emulators), Firebase CLI (`npm i -g firebase-tools`).

```bash
cd backend && npm ci && cd ../frontend && npm ci && npm run build && cd ..
cp .env.example backend/.env   # fill in values, or use the emulator setup below

# Local run against the Firebase emulators (no cloud resources needed)
cd backend
GOOGLE_CLOUD_PROJECT=demo-pandashield FIREBASE_PROJECT_ID=demo-pandashield FIREBASE_WEB_API_KEY=demo-key \
GEMINI_USE_VERTEX=false GEMINI_API_KEY=<your Gemini API key> \
firebase emulators:exec --config ../firebase/firebase.json --project demo-pandashield --only auth,firestore "node src/server.js"
# open http://localhost:8080 and use "Local emulator sign-in"
```

### Environment variables

See [`.env.example`](.env.example). Key ones: `GOOGLE_CLOUD_PROJECT`, `FIREBASE_WEB_API_KEY`, `FIREBASE_APP_ID`, `FIREBASE_AUTH_DOMAIN`, `GEMINI_MODEL` (default `gemini-3.8-flash`), `GEMINI_USE_VERTEX` (default `true`), `GEMINI_THINKING_LEVEL` (default `LOW`), `SCANS_PER_HOUR`, `ASKS_PER_HOUR`.

## Tests

```bash
cd backend
npm test                 # unit + API tests (scanners, Gemini parsing, auth, validation, workflow)
npm run test:emulator    # Firestore persistence, ID-token verification, security rules (Firebase emulators)
cd .. && tests/e2e/run.sh   # browser tests: full workflow, persistence after reload, mobile layout, console errors
```

Latest recorded results are in [`docs/QA_REPORT.md`](docs/QA_REPORT.md).

## Deploy

See [`deployment/DEPLOYMENT_PLAN.md`](deployment/DEPLOYMENT_PLAN.md). In short: `deployment/setup-project.sh` creates an isolated project, then `deployment/deploy.sh` deploys to Cloud Run from source and `deployment/verify.sh` checks the live service.

## Security notes

- Every `/api` route except `/api/config` requires a valid Firebase ID token; users can only access their own scans (enforced in the API and in Firestore rules).
- GitHub downloads are limited to `https://codeload.github.com/<owner>/<repo>` with strict name validation (no SSRF), a 30 MB archive cap, 400 files and 512 KB per file.
- Detected secrets are redacted before storage, AI analysis, reports and UI.
- Prompts fence untrusted code and context and instruct Gemini to ignore instructions inside them; structured output is validated server-side.
- Helmet security headers with a strict Content Security Policy; non-root container user.

## Licence

MIT
