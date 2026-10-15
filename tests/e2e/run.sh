#!/usr/bin/env bash
# Runs the browser end-to-end tests against the Firebase emulators.
# Requires: Node 20+, Java 11+, Firebase CLI, Playwright with Chromium.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$ROOT/frontend" && npx vite build >/dev/null)
export GOOGLE_CLOUD_PROJECT=demo-pandashield FIREBASE_PROJECT_ID=demo-pandashield FIREBASE_WEB_API_KEY=demo-key \
       FIREBASE_AUTH_DOMAIN=demo-pandashield.firebaseapp.com FIREBASE_APP_ID=demo-app PORT=8090
cd "$ROOT/backend"
firebase emulators:exec --config ../firebase/firebase.json --project demo-pandashield --only auth,firestore \
  "node ../tests/e2e/harness.js & HP=\$!; for i in \$(seq 1 40); do curl -sf http://127.0.0.1:8090/healthz >/dev/null && break; sleep 0.5; done; node --test ../tests/e2e/ui.e2e.js; RC=\$?; kill \$HP; exit \$RC"
