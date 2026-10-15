// Dependency vulnerability scanning using the public OSV.dev database
// (https://osv.dev). Manifests are parsed locally; only package names and
// versions are sent to OSV.

import { config } from '../config.js';

// ---------- manifest parsing ----------

const SEMVERISH = /^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?$/;

function cleanNpmVersion(spec) {
  if (typeof spec !== 'string') return null;
  const s = spec.trim();
  // Only exact versions or simple ^/~/>= lower bounds are resolvable without a lockfile.
  const m = s.match(/^(?:[\^~]|>=|=)?\s*v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)$/);
  if (!m) return null;
  const parts = m[1].split('-')[0].split('.');
  while (parts.length < 3) parts.push('0');
  return parts.join('.') + (m[1].includes('-') ? '-' + m[1].split('-').slice(1).join('-') : '');
}

export function parseManifests(files) {
  const deps = [];
  const lockDirs = new Set(files.filter((f) => /(^|\/)package-lock\.json$/.test(f.path)).map((f) => f.path.replace(/package-lock\.json$/, '')));

  for (const f of files) {
    const base = f.path.split('/').pop();
    try {
      if (base === 'package-lock.json') {
        const lock = JSON.parse(f.content);
        if (lock.packages) {
          for (const [key, meta] of Object.entries(lock.packages)) {
            if (!key || !meta || !meta.version || meta.link) continue;
            const name = meta.name || key.split('node_modules/').pop();
            if (SEMVERISH.test(meta.version)) deps.push({ ecosystem: 'npm', name, version: meta.version, file: f.path, exact: true, dev: !!meta.dev });
          }
        } else if (lock.dependencies) {
          const walk = (obj) => {
            for (const [name, meta] of Object.entries(obj)) {
              if (meta && meta.version && SEMVERISH.test(meta.version)) deps.push({ ecosystem: 'npm', name, version: meta.version, file: f.path, exact: true, dev: !!meta.dev });
              if (meta && meta.dependencies) walk(meta.dependencies);
            }
          };
          walk(lock.dependencies);
        }
      } else if (base === 'package.json') {
        if (lockDirs.has(f.path.replace(/package\.json$/, ''))) continue; // lockfile is more precise
        const pkg = JSON.parse(f.content);
        for (const [section, dev] of [['dependencies', false], ['devDependencies', true]]) {
          for (const [name, spec] of Object.entries(pkg[section] || {})) {
            const version = cleanNpmVersion(spec);
            if (version) deps.push({ ecosystem: 'npm', name, version, file: f.path, exact: /^\d/.test(String(spec).trim()), declared: spec, dev });
          }
        }
      } else if (/^requirements([-_.][\w.-]+)?\.txt$/i.test(base)) {
        for (const raw of f.content.split('\n')) {
          const line = raw.replace(/#.*/, '').trim();
          const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==|>=|~=)\s*([0-9][0-9A-Za-z.!+-]*)/);
          if (m) deps.push({ ecosystem: 'PyPI', name: m[1], version: m[3], file: f.path, exact: m[2] === '==', declared: `${m[2]}${m[3]}`, dev: false });
        }
      }
    } catch {
      // Malformed manifest: skip it rather than failing the whole scan.
    }
  }

  // De-duplicate by ecosystem/name/version.
  const map = new Map();
  for (const d of deps) {
    const k = `${d.ecosystem}|${d.name}|${d.version}`;
    if (!map.has(k)) map.set(k, d);
  }
  return [...map.values()];
}

// ---------- CVSS v3 base score ----------

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
};

export function cvss3Score(vector) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3')) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.C[m.C]) * (1 - W.C[m.I]) * (1 - W.C[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  if (impact <= 0) return 0;
  const roundUp = (x) => Math.ceil(x * 10 - 1e-9) / 10;
  return changed ? roundUp(Math.min(1.08 * (impact + expl), 10)) : roundUp(Math.min(impact + expl, 10));
}

export function severityFromScore(score) {
  if (score == null) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function osvSeverity(vuln) {
  const ds = vuln?.database_specific?.severity;
  const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
  let score = null;
  for (const s of vuln?.severity || []) {
    if (s.type === 'CVSS_V3') score = cvss3Score(s.score);
  }
  if (ds && map[String(ds).toUpperCase()]) return { severity: map[String(ds).toUpperCase()], cvss: score };
  return { severity: severityFromScore(score) || 'medium', cvss: score };
}

export function fixedVersions(vuln, name) {
  const out = new Set();
  for (const a of vuln?.affected || []) {
    if (a.package && a.package.name && a.package.name.toLowerCase() !== name.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) out.add(e.fixed);
  }
  return [...out];
}

// ---------- OSV client ----------

async function postJson(url, body, fetchImpl, timeoutMs = 20000) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`OSV responded with HTTP ${res.status}`);
  return res.json();
}

async function getJson(url, fetchImpl, timeoutMs = 20000) {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`OSV responded with HTTP ${res.status}`);
  return res.json();
}

export async function scanDependencies(files, { fetchImpl = globalThis.fetch, baseUrl = config.osvBaseUrl, maxDetails = 60 } = {}) {
  const deps = parseManifests(files);
  const result = { dependencies: deps.length, findings: [], error: null };
  if (!deps.length) return result;

  try {
    const hits = [];
    for (let i = 0; i < deps.length; i += 500) {
      const chunk = deps.slice(i, i + 500);
      const data = await postJson(`${baseUrl}/v1/querybatch`, {
        queries: chunk.map((d) => ({ package: { ecosystem: d.ecosystem, name: d.name }, version: d.version })),
      }, fetchImpl);
      (data.results || []).forEach((r, j) => {
        for (const v of r.vulns || []) hits.push({ dep: chunk[j], id: v.id });
      });
    }

    const details = new Map();
    const ids = [...new Set(hits.map((h) => h.id))].slice(0, maxDetails);
    await Promise.all(ids.map(async (id) => {
      try { details.set(id, await getJson(`${baseUrl}/v1/vulns/${encodeURIComponent(id)}`, fetchImpl)); } catch { /* keep id only */ }
    }));

    // Collapse aliases so one CVE reported as GHSA + PYSEC shows once per package.
    const seen = new Set();
    for (const { dep, id } of hits) {
      const v = details.get(id) || { id };
      const aliasKey = [id, ...(v.aliases || [])].sort()[0];
      const key = `${dep.ecosystem}|${dep.name}|${dep.version}|${aliasKey}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const { severity, cvss } = osvSeverity(v);
      const fixes = fixedVersions(v, dep.name);
      const cve = [id, ...(v.aliases || [])].find((a) => a.startsWith('CVE-'));
      result.findings.push({
        ruleId: `dep.${id}`,
        category: 'dependency',
        title: `${dep.name}@${dep.version}: ${v.summary || id}`,
        severity: dep.dev && severity !== 'critical' ? downgrade(severity) : severity,
        file: dep.file,
        line: null,
        evidence: `${dep.name} ${dep.declared || dep.version}`,
        cwe: (v.database_specific?.cwe_ids || [])[0] || null,
        owasp: 'A06:2021 Vulnerable and Outdated Components',
        description: (v.details || v.summary || `Known vulnerability ${id} affects this version.`).slice(0, 1200),
        package: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, dev: dep.dev, exact: dep.exact },
        advisory: { id, cve: cve || null, aliases: v.aliases || [], cvss, fixedIn: fixes, url: `https://osv.dev/vulnerability/${id}` },
      });
    }
  } catch (err) {
    result.error = `Dependency lookup failed: ${err.message}`;
  }
  return result;
}

function downgrade(sev) {
  return { high: 'medium', medium: 'low', low: 'low', info: 'info' }[sev] || sev;
}
