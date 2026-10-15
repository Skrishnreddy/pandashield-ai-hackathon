// Express application. Dependencies are injected so the same app can run
// against real Google services (Cloud Run), the Firebase emulators, or
// in-memory fakes in unit tests.

import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import fs from 'node:fs';
import { config } from './config.js';
import { requireAuth, rateLimit } from './auth.js';
import { normaliseFiles, InputError, isScannablePath } from './scan/files.js';
import { runScan } from './scan/index.js';
import { fetchGithubFiles } from './scan/github.js';
import { markdownReport, sarifReport } from './report.js';

const ID = /^[A-Za-z0-9]{1,64}$/;

export function createApp(deps) {
  const {
    store, // ScanStore
    verifyIdToken, // (token) => decoded
    triage, // (findings, appContext) => ai result
    ask, // (finding, question, history) => answer
    fetchGithub = fetchGithubFiles,
    scan = runScan,
    staticDir = null,
    samplesDir = null,
    healthChecks = {},
  } = deps;

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'script-src': ["'self'", 'https://apis.google.com', 'https://www.gstatic.com'],
        'connect-src': ["'self'", 'https://*.googleapis.com', 'https://*.firebaseio.com', 'https://firestore.googleapis.com', 'wss://*.firebaseio.com', ...(config.emulators.auth || config.emulators.firestore ? ['http://localhost:*', 'http://127.0.0.1:*', 'ws://localhost:*', 'ws://127.0.0.1:*'] : [])],
        'frame-src': ["'self'", 'https://*.firebaseapp.com', 'https://accounts.google.com', 'https://apis.google.com'],
        'img-src': ["'self'", 'data:', 'https://*.googleusercontent.com'],
        'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        'font-src': ["'self'", 'https://fonts.gstatic.com'],
      },
    },
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  }));
  app.use(express.json({ limit: config.limits.maxRequestBytes }));

  // ---------- public endpoints ----------

  // '/healthz' is reserved by Cloud Run's front end, so '/health' is the public alias.
  app.get(['/healthz', '/health'], (req, res) => {
    res.json({ status: 'ok', service: 'pandashield-hackathon', revision: process.env.K_REVISION || 'local', time: new Date().toISOString() });
  });

  app.get('/api/config', (req, res) => {
    res.json({
      firebase: config.firebaseWeb,
      emulators: { auth: config.emulators.auth ? `http://${config.emulators.auth}` : null, firestore: config.emulators.firestore || null },
      gemini: { model: config.gemini.model },
      limits: { maxFiles: config.limits.maxFiles, maxFileBytes: config.limits.maxFileBytes, maxTotalBytes: config.limits.maxTotalBytes },
      edition: 'Hackathon Edition',
    });
  });

  // ---------- authenticated API ----------

  const api = express.Router();
  api.use(requireAuth(verifyIdToken));

  const scanLimiter = rateLimit({ windowMs: 3600_000, max: config.limits.scansPerHour, message: 'Scan limit reached for this hour. Please try again later.' });
  const askLimiter = rateLimit({ windowMs: 3600_000, max: config.limits.asksPerHour, message: 'Question limit reached for this hour. Please try again later.' });

  api.get('/diagnostics', async (req, res) => {
    const result = { revision: process.env.K_REVISION || 'local', checks: {} };
    for (const [name, fn] of Object.entries(healthChecks)) {
      const t = Date.now();
      try {
        result.checks[name] = { ok: true, detail: await fn(req.user), ms: Date.now() - t };
      } catch (e) {
        result.checks[name] = { ok: false, detail: e.message, ms: Date.now() - t };
      }
    }
    res.json(result);
  });

  api.get('/samples', (req, res) => {
    res.json({ samples: samplesDir ? listSamples(samplesDir) : [] });
  });

  api.post('/scans', scanLimiter, wrap(async (req, res) => {
    const body = req.body || {};
    let appContext = typeof body.appContext === 'string' ? body.appContext.slice(0, 1500) : '';
    let files;
    let source;
    let name = typeof body.name === 'string' ? body.name.trim().slice(0, 120) : '';

    if (body.source === 'github') {
      const gh = await fetchGithub(body.repoUrl);
      files = normaliseFiles(gh.files.map((f) => ({ path: f.path, content: f.content })));
      source = { type: 'github', owner: gh.owner, repo: gh.repo, ref: gh.ref, url: `https://github.com/${gh.owner}/${gh.repo}` };
      name ||= `${gh.owner}/${gh.repo}`;
    } else if (body.source === 'sample') {
      const sample = samplesDir && listSamples(samplesDir).find((s) => s.id === body.sampleId);
      if (!sample) throw new InputError('Unknown sample.');
      files = loadSample(samplesDir, sample.id);
      source = { type: 'sample', sampleId: sample.id };
      name ||= sample.name;
      if (!appContext) appContext = sample.appContext;
    } else if (body.source === 'files') {
      files = normaliseFiles(body.files);
      source = { type: 'files', fileCount: files.length };
      name ||= files.length === 1 ? files[0].path : `${files.length} uploaded files`;
    } else {
      throw new InputError('source must be "files", "github" or "sample".');
    }

    const result = await scan(files);
    let ai;
    try {
      ai = await triage(result.findings, appContext);
    } catch (e) {
      console.error(JSON.stringify({ severity: 'ERROR', message: 'gemini_triage_failed', error: e.message }));
      ai = { error: 'Gemini analysis is temporarily unavailable. Scanner findings were saved; you can retry the AI analysis.' };
    }
    const id = await store.saveScan(req.user, { ...result, name, source, appContext, ai });
    console.log(JSON.stringify({ severity: 'INFO', message: 'scan_saved', scanId: id, findings: result.findings.length, files: result.meta.filesScanned, triaged: ai?.triaged ?? 0 }));
    const saved = await store.getScan(req.user.uid, id);
    res.status(201).json(saved);
  }));

  api.get('/scans', wrap(async (req, res) => {
    res.json({ scans: await store.listScans(req.user.uid) });
  }));

  api.get('/scans/:scanId', wrap(async (req, res) => {
    const scan = await loadScan(req);
    res.json(scan);
  }));

  api.delete('/scans/:scanId', wrap(async (req, res) => {
    checkId(req.params.scanId);
    const ok = await store.deleteScan(req.user.uid, req.params.scanId);
    if (!ok) return res.status(404).json({ error: 'Scan not found.' });
    res.status(204).end();
  }));

  api.post('/scans/:scanId/triage', scanLimiter, wrap(async (req, res) => {
    const scan = await loadScan(req);
    const ai = await triage(scan.findings, scan.appContext);
    await store.saveTriage(req.user.uid, scan.id, ai);
    res.json(await store.getScan(req.user.uid, scan.id));
  }));

  api.patch('/scans/:scanId/findings/:findingId', wrap(async (req, res) => {
    checkId(req.params.scanId);
    checkId(req.params.findingId);
    const ok = await store.setFindingStatus(req.user.uid, req.params.scanId, req.params.findingId, req.body?.status);
    if (!ok) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ ok: true, status: req.body.status });
  }));

  api.post('/scans/:scanId/findings/:findingId/ask', askLimiter, wrap(async (req, res) => {
    checkId(req.params.scanId);
    checkId(req.params.findingId);
    const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
    if (question.length < 3 || question.length > 500) throw new InputError('Questions must be between 3 and 500 characters.');
    const finding = await store.getFinding(req.user.uid, req.params.scanId, req.params.findingId);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    const answer = await ask(finding, question, finding.conversation || []);
    const entry = { question, answer, at: new Date().toISOString() };
    await store.appendConversation(req.user.uid, req.params.scanId, req.params.findingId, entry);
    res.json(entry);
  }));

  api.get('/scans/:scanId/report.md', wrap(async (req, res) => {
    const scan = await loadScan(req);
    res.type('text/markdown').set('content-disposition', `attachment; filename="pandashield-report-${scan.id}.md"`).send(markdownReport(scan));
  }));

  api.get('/scans/:scanId/report.sarif', wrap(async (req, res) => {
    const scan = await loadScan(req);
    res.type('application/sarif+json').set('content-disposition', `attachment; filename="pandashield-${scan.id}.sarif"`).send(JSON.stringify(sarifReport(scan), null, 2));
  }));

  async function loadScan(req) {
    checkId(req.params.scanId);
    const scan = await store.getScan(req.user.uid, req.params.scanId);
    if (!scan) throw new InputError('Scan not found.', 404);
    return scan;
  }

  app.use('/api', api);
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

  // ---------- frontend ----------
  if (staticDir && fs.existsSync(staticDir)) {
    app.use(express.static(staticDir, { index: false, maxAge: '1h', setHeaders: (res, p) => { if (p.endsWith('.html')) res.set('cache-control', 'no-cache'); } }));
    app.get('*', (req, res) => res.set('cache-control', 'no-cache').sendFile(path.join(staticDir, 'index.html')));
  }

  // ---------- errors ----------
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'The upload is too large.' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'The request body is not valid JSON.' });
    const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
    if (status >= 500) console.error(JSON.stringify({ severity: 'ERROR', message: 'request_failed', path: req.path, error: err.message, stack: err.stack }));
    res.status(status).json({ error: err.expose ? err.message : 'Something went wrong. Please try again.' });
  });

  return app;
}

function wrap(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

function checkId(id) {
  if (!ID.test(id)) throw new InputError('Invalid id.');
}

// ---------- built-in samples ----------

export function listSamples(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => {
        let meta = {};
        try { meta = JSON.parse(fs.readFileSync(path.join(dir, d.name, 'pandashield-sample.json'), 'utf8')); } catch { /* optional */ }
        return { id: d.name, name: meta.name || d.name, description: meta.description || '', appContext: meta.appContext || '' };
      });
  } catch {
    return [];
  }
}

export function loadSample(dir, id) {
  if (!/^[a-z0-9-]+$/.test(id)) throw new InputError('Unknown sample.');
  const root = path.join(dir, id);
  const files = [];
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(r);
      else if (e.isFile() && e.name !== 'pandashield-sample.json' && isScannablePath(r)) files.push({ path: r, content: fs.readFileSync(path.join(root, r), 'utf8') });
    }
  };
  walk('');
  return normaliseFiles(files);
}
