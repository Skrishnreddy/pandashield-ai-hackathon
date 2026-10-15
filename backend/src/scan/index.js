// Runs all scanners over an in-memory file set and returns normalised,
// de-duplicated, redacted findings plus summary statistics.

import { createHash } from 'node:crypto';
import { scanSecrets, redactContent } from './secrets.js';
import { scanCode } from './sast.js';
import { scanDependencies } from './deps.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

export function findingId(f) {
  return createHash('sha256').update(`${f.ruleId}|${f.file}|${f.line ?? ''}|${f.evidence}`).digest('hex').slice(0, 16);
}

export function snippet(content, line, radius = 3) {
  if (!line) return null;
  const lines = content.split('\n');
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  return {
    startLine: start,
    lines: lines.slice(start - 1, end).map((t) => (t.length > 300 ? t.slice(0, 300) + ' …' : t)),
  };
}

export function computeStats(findings) {
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  const byCategory = { code: 0, secret: 0, dependency: 0 };
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  const penalty = findings.reduce((acc, f) => acc + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  // 100 = nothing found; decays smoothly so large repos do not go negative.
  const securityScore = Math.round(100 * Math.exp(-penalty / 80));
  return { total: findings.length, bySeverity, byCategory, securityScore };
}

export async function runScan(files, { fetchImpl } = {}) {
  const started = Date.now();
  const secretFindings = scanSecrets(files);
  const codeFindings = scanCode(files);
  const dep = await scanDependencies(files, fetchImpl ? { fetchImpl } : undefined);

  // Redact secret values in file contents before building snippets.
  const rangesByFile = new Map();
  for (const f of secretFindings) {
    if (!rangesByFile.has(f.file)) rangesByFile.set(f.file, []);
    rangesByFile.get(f.file).push(f.secretRange);
  }
  const safeContent = new Map(files.map((f) => [f.path, redactContent(f.content, rangesByFile.get(f.path) || [])]));

  const all = [...secretFindings, ...codeFindings, ...dep.findings];
  const byId = new Map();
  for (const f of all) {
    delete f.secretRange;
    if (f.category === 'code') f.evidence = redactEvidence(f, safeContent);
    const id = findingId(f);
    if (byId.has(id)) continue;
    byId.set(id, {
      id,
      ...f,
      snippet: f.line ? snippet(safeContent.get(f.file) || '', f.line) : null,
      status: 'open',
    });
  }
  const findings = [...byId.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0),
  );

  const languages = {};
  for (const f of files) {
    const ext = (f.path.match(/\.([A-Za-z0-9]+)$/) || [, f.path.split('/').pop()])[1].toLowerCase();
    languages[ext] = (languages[ext] || 0) + 1;
  }

  return {
    findings,
    stats: computeStats(findings),
    meta: {
      filesScanned: files.length,
      dependenciesChecked: dep.dependencies,
      dependencyError: dep.error,
      languages,
      durationMs: Date.now() - started,
      scanners: ['pandashield-sast', 'pandashield-secrets', 'osv.dev'],
    },
  };
}

// Code findings report the raw line; use the redacted copy so a secret on the
// same line is never echoed back.
function redactEvidence(f, safeContent) {
  const content = safeContent.get(f.file);
  if (!content || !f.line) return f.evidence;
  return (content.split('\n')[f.line - 1] || '').trim().slice(0, 240);
}
