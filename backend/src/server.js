import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { createApp } from './app.js';
import { adminAuth, firestore } from './store/firebase.js';
import { ScanStore } from './store/scans.js';
import { triageFindings, askAboutFinding, geminiClient, thinking } from './ai/gemini.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const staticDir = process.env.STATIC_DIR || path.resolve(here, '../../frontend/dist');
const samplesDir = process.env.SAMPLES_DIR || path.resolve(here, '../../samples');

const db = firestore();
const store = new ScanStore(db);

const app = createApp({
  store,
  verifyIdToken: (token) => adminAuth().verifyIdToken(token),
  triage: triageFindings,
  ask: askAboutFinding,
  staticDir,
  samplesDir,
  healthChecks: {
    firestore: async (user) => {
      const ref = db.collection('users').doc(user.uid).collection('diagnostics').doc('ping');
      const at = new Date().toISOString();
      await ref.set({ at });
      const back = await ref.get();
      if (back.data()?.at !== at) throw new Error('Read-after-write mismatch');
      return 'write + read ok';
    },
    gemini: async () => {
      const r = await geminiClient().models.generateContent({ model: config.gemini.model, contents: 'Reply with the single word: ready', config: { thinkingConfig: thinking() } });
      return `${config.gemini.model}: ${(r.text || '').trim().slice(0, 40)}`;
    },
    auth: async (user) => `verified uid ${user.uid.slice(0, 6)}…`,
  },
});

app.listen(config.port, () => {
  console.log(JSON.stringify({ severity: 'INFO', message: 'server_started', port: config.port, project: config.projectId || '(default)', model: config.gemini.model, vertex: config.gemini.useVertex }));
});
