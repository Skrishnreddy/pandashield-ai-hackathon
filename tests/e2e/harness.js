// TEST-ONLY server for browser end-to-end tests. Uses the real API code,
// the real Firebase Auth + Firestore emulators, the real scanners, and the
// built frontend. Only Gemini and OSV are replaced with deterministic stubs
// so tests run offline; stubbed AI text is prefixed "[TEST STUB]" so it can
// never be mistaken for a real Gemini response.

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../../backend/src/app.js';
import { adminAuth, firestore } from '../../backend/src/store/firebase.js';
import { ScanStore } from '../../backend/src/store/scans.js';
import { runScan } from '../../backend/src/scan/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const osvStub = async () => ({ ok: true, json: async () => ({ results: [] }) });

const app = createApp({
  store: new ScanStore(firestore()),
  verifyIdToken: (t) => adminAuth().verifyIdToken(t),
  scan: (files) => runScan(files, { fetchImpl: osvStub }),
  triage: async (findings) => ({
    executiveSummary: `[TEST STUB] ${findings.length} findings reviewed. Fix the critical injection issues first.`,
    overallRisk: 'critical',
    fixFirst: findings.slice(0, 3).map((f) => f.id),
    byId: Object.fromEntries(findings.map((f, i) => [f.id, {
      priority: i < 3 ? 'P1' : 'P2',
      contextualSeverity: f.severity,
      priorityReason: '[TEST STUB] reason',
      explanation: `[TEST STUB] explanation for ${f.ruleId}`,
      attackScenario: '[TEST STUB] scenario',
      remediation: '1. [TEST STUB] step one\n2. step two',
      fixedCode: '// [TEST STUB] fixed code',
      falsePositiveLikelihood: 'low',
    }])),
    model: 'test-stub',
    triaged: findings.length,
  }),
  ask: async (f, q) => `[TEST STUB] answer to: ${q}`,
  staticDir: path.resolve(here, '../../frontend/dist'),
  samplesDir: path.resolve(here, '../../samples'),
  healthChecks: { auth: async (u) => `uid ${u.uid}` },
});

const port = Number(process.env.PORT || 8090);
app.listen(port, () => console.log(`e2e harness on ${port}`));
