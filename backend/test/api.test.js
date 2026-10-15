import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { markdownReport, sarifReport } from '../src/report.js';

// In-memory stand-in for ScanStore with the same interface.
class MemoryStore {
  constructor() { this.data = new Map(); this.n = 0; }
  async saveScan(user, scan) {
    const id = `scan${++this.n}`;
    this.data.set(`${user.uid}/${id}`, {
      id, name: scan.name, source: scan.source, appContext: scan.appContext, stats: scan.stats, meta: scan.meta,
      ai: scan.ai ? { executiveSummary: scan.ai.executiveSummary, fixFirst: scan.ai.fixFirst || [], model: scan.ai.model, triaged: scan.ai.triaged || 0, error: scan.ai.error || null } : null,
      findings: scan.findings.map((f) => ({ ...f, ai: scan.ai?.byId?.[f.id] || null, conversation: [] })),
      createdAt: new Date().toISOString(),
    });
    return id;
  }
  async listScans(uid) { return [...this.data.entries()].filter(([k]) => k.startsWith(`${uid}/`)).map(([, v]) => ({ id: v.id, name: v.name })); }
  async getScan(uid, id) { const s = this.data.get(`${uid}/${id}`); return s ? structuredClone(s) : null; }
  async getFinding(uid, id, fid) { return this.data.get(`${uid}/${id}`)?.findings.find((f) => f.id === fid) || null; }
  async setFindingStatus(uid, id, fid, status) {
    if (!['open', 'fixed', 'accepted_risk', 'false_positive'].includes(status)) throw Object.assign(new Error('Invalid status.'), { status: 400, expose: true });
    const f = await this.getFinding(uid, id, fid);
    if (!f) return false;
    f.status = status;
    return true;
  }
  async appendConversation(uid, id, fid, entry) { (await this.getFinding(uid, id, fid)).conversation.push(entry); }
  async saveTriage(uid, id, ai) {
    const s = this.data.get(`${uid}/${id}`);
    s.ai = { executiveSummary: ai.executiveSummary, fixFirst: ai.fixFirst, model: ai.model, triaged: ai.triaged, error: null };
    for (const f of s.findings) f.ai = ai.byId[f.id] || null;
  }
  async deleteScan(uid, id) { return this.data.delete(`${uid}/${id}`); }
}

const store = new MemoryStore();
let triageMode = 'ok';
const triage = async (findings) => {
  if (triageMode === 'fail') throw new Error('Gemini down');
  return {
    executiveSummary: `Gemini reviewed ${findings.length} findings.`,
    overallRisk: 'critical',
    fixFirst: findings.slice(0, 1).map((f) => f.id),
    byId: Object.fromEntries(findings.map((f) => [f.id, { priority: 'P1', explanation: `Explains ${f.ruleId}`, remediation: 'Fix it', fixedCode: 'safe()', contextualSeverity: f.severity, falsePositiveLikelihood: 'low' }])),
    model: 'gemini-test',
    triaged: findings.length,
  };
};
const app = createApp({
  store,
  verifyIdToken: async (t) => {
    if (t === 'alice-token') return { uid: 'alice', email: 'alice@example.com' };
    if (t === 'bob-token') return { uid: 'bob', email: 'bob@example.com' };
    throw new Error('bad token');
  },
  triage,
  ask: async (f, q) => `Answer about ${f.ruleId}: ${q}`,
  scan: undefined,
  fetchGithub: async (url) => {
    if (url.includes('missing')) throw Object.assign(new Error('Repository not found.'), { status: 404, expose: true });
    return { owner: 'acme', repo: 'demo', ref: 'HEAD', files: [{ path: 'app.py', content: 'import pickle\npickle.loads(data)\n' }] };
  },
  samplesDir: new URL('../../samples', import.meta.url).pathname,
  healthChecks: { auth: async (u) => `uid ${u.uid}`, broken: async () => { throw new Error('nope'); } },
});

let server;
let base;
before(async () => {
  // Keep dependency lookups offline and deterministic.
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes('osv.dev')) {
      if (String(url).endsWith('querybatch')) {
        const body = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ results: body.queries.map(() => ({ vulns: [] })) }) };
      }
    }
    return realFetch(url, opts);
  };
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const call = (path, { token = 'alice-token', method = 'GET', body } = {}) => fetch(base + path, {
  method,
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
  body: body !== undefined ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
});

test('health and config endpoints are public; security headers are set', async () => {
  const h = await fetch(`${base}/healthz`);
  assert.equal(h.status, 200);
  assert.equal((await h.json()).status, 'ok');
  assert.ok(h.headers.get('content-security-policy'));
  assert.equal(h.headers.get('x-powered-by'), null);
  const c = await (await fetch(`${base}/api/config`)).json();
  assert.equal(c.edition, 'Hackathon Edition');
  assert.ok('firebase' in c);
});

test('API rejects missing or invalid Firebase tokens', async () => {
  assert.equal((await call('/api/scans', { token: null })).status, 401);
  assert.equal((await call('/api/scans', { token: 'forged' })).status, 401);
  const r = await fetch(`${base}/api/scans`, { headers: { authorization: 'Basic abc' } });
  assert.equal(r.status, 401);
});

test('input validation returns clear 4xx errors', async () => {
  assert.equal((await call('/api/scans', { method: 'POST', body: {} })).status, 400);
  assert.equal((await call('/api/scans', { method: 'POST', body: { source: 'files', files: [] } })).status, 400);
  assert.equal((await call('/api/scans', { method: 'POST', body: { source: 'files', files: [{ path: '../../etc/passwd', content: 'x' }] } })).status, 400);
  assert.equal((await call('/api/scans', { method: 'POST', body: { source: 'sample', sampleId: '../../etc' } })).status, 400);
  assert.equal((await call('/api/scans', { method: 'POST', body: '{broken' })).status, 400);
  const nf = await call('/api/scans', { method: 'POST', body: { source: 'github', repoUrl: 'https://github.com/acme/missing' } });
  assert.equal(nf.status, 404);
  assert.match((await nf.json()).error, /not found/);
  assert.equal((await call('/api/scans/bad$id')).status, 400);
  assert.equal((await call('/api/nope')).status, 404);
});

test('full workflow: scan sample, triage, persist, reopen, update status, ask, report, delete', async () => {
  const samples = await (await call('/api/samples')).json();
  assert.equal(samples.samples[0].id, 'acme-orders-api');

  const res = await call('/api/scans', { method: 'POST', body: { source: 'sample', sampleId: 'acme-orders-api' } });
  assert.equal(res.status, 201);
  const scan = await res.json();
  assert.ok(scan.findings.length >= 20);
  assert.match(scan.ai.executiveSummary, /Gemini reviewed/);
  assert.ok(scan.findings.every((f) => f.ai && f.ai.priority === 'P1'));
  assert.match(scan.appContext, /Internet-facing/, 'sample context is used by default');

  const reopened = await (await call(`/api/scans/${scan.id}`)).json();
  assert.equal(reopened.findings.length, scan.findings.length);
  const list = await (await call('/api/scans')).json();
  assert.ok(list.scans.some((s) => s.id === scan.id));

  const fid = scan.findings[0].id;
  assert.equal((await call(`/api/scans/${scan.id}/findings/${fid}`, { method: 'PATCH', body: { status: 'hacked' } })).status, 400);
  assert.equal((await call(`/api/scans/${scan.id}/findings/${fid}`, { method: 'PATCH', body: { status: 'fixed' } })).status, 200);
  assert.equal((await (await call(`/api/scans/${scan.id}`)).json()).findings.find((f) => f.id === fid).status, 'fixed');

  assert.equal((await call(`/api/scans/${scan.id}/findings/${fid}/ask`, { method: 'POST', body: { question: 'x' } })).status, 400);
  const ask = await (await call(`/api/scans/${scan.id}/findings/${fid}/ask`, { method: 'POST', body: { question: 'How do I test the fix?' } })).json();
  assert.match(ask.answer, /How do I test the fix/);
  assert.equal((await (await call(`/api/scans/${scan.id}`)).json()).findings.find((f) => f.id === fid).conversation.length, 1);

  const md = await call(`/api/scans/${scan.id}/report.md`);
  assert.equal(md.status, 200);
  const mdText = await md.text();
  assert.match(mdText, /# PandaShield AI Security Report/);
  assert.ok(!mdText.includes('IOSFODNN7EXAMPLE'));
  const sarif = await (await call(`/api/scans/${scan.id}/report.sarif`)).json();
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, scan.findings.length);

  assert.equal((await call(`/api/scans/${scan.id}`, { method: 'DELETE' })).status, 204);
  assert.equal((await call(`/api/scans/${scan.id}`)).status, 404);
});

test('users cannot read or modify each other\'s scans', async () => {
  const scan = await (await call('/api/scans', { method: 'POST', body: { source: 'files', files: [{ path: 'a.py', content: 'yaml.load(x)' }] } })).json();
  const fid = scan.findings[0].id;
  assert.equal((await call(`/api/scans/${scan.id}`, { token: 'bob-token' })).status, 404);
  assert.equal((await call(`/api/scans/${scan.id}/findings/${fid}`, { token: 'bob-token', method: 'PATCH', body: { status: 'fixed' } })).status, 404);
  assert.equal((await call(`/api/scans/${scan.id}/findings/${fid}/ask`, { token: 'bob-token', method: 'POST', body: { question: 'leak it?' } })).status, 404);
  assert.equal((await call(`/api/scans/${scan.id}`, { token: 'bob-token', method: 'DELETE' })).status, 404);
  assert.ok(!(await (await call('/api/scans', { token: 'bob-token' })).json()).scans.some((s) => s.id === scan.id));
});

test('GitHub source is scanned and labelled', async () => {
  const scan = await (await call('/api/scans', { method: 'POST', body: { source: 'github', repoUrl: 'https://github.com/acme/demo' } })).json();
  assert.equal(scan.source.type, 'github');
  assert.equal(scan.name, 'acme/demo');
  assert.ok(scan.findings.some((f) => f.ruleId === 'py.pickle-load'));
});

test('Gemini failure still saves scanner results, and triage can be retried', async () => {
  triageMode = 'fail';
  const scan = await (await call('/api/scans', { method: 'POST', body: { source: 'files', files: [{ path: 'a.js', content: 'eval(req.query.x)' }] } })).json();
  assert.match(scan.ai.error, /temporarily unavailable/);
  assert.equal(scan.findings.length, 1);
  triageMode = 'ok';
  const retried = await (await call(`/api/scans/${scan.id}/triage`, { method: 'POST' })).json();
  assert.equal(retried.ai.error, null);
  assert.equal(retried.findings[0].ai.priority, 'P1');
});

test('clean code produces an empty, saved scan', async () => {
  const scan = await (await call('/api/scans', { method: 'POST', body: { source: 'files', files: [{ path: 'ok.js', content: 'const a = 1;\n' }] } })).json();
  assert.equal(scan.findings.length, 0);
  assert.equal(scan.stats.securityScore, 100);
});

test('diagnostics reports each check independently', async () => {
  const d = await (await call('/api/diagnostics')).json();
  assert.equal(d.checks.auth.ok, true);
  assert.equal(d.checks.broken.ok, false);
});

test('oversized request bodies are rejected with 413', async () => {
  const big = 'x'.repeat(4 * 1024 * 1024);
  const r = await call('/api/scans', { method: 'POST', body: { source: 'files', files: [{ path: 'a.js', content: big }] } });
  assert.equal(r.status, 413);
});

test('report helpers render without AI data', () => {
  const scan = { name: 'n', source: { type: 'files', fileCount: 1 }, stats: { bySeverity: {}, securityScore: 90 }, meta: {}, findings: [{ id: '1', ruleId: 'r', title: 't', severity: 'low', file: 'f', line: 2, description: 'd', category: 'code' }] };
  assert.match(markdownReport(scan), /### .* t/);
  assert.equal(sarifReport(scan).runs[0].results[0].locations[0].physicalLocation.region.startLine, 2);
});
