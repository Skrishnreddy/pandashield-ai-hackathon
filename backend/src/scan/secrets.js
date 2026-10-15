// Hard-coded secret detection. Matched values are always redacted before
// they leave this module, so raw secrets are never stored or sent to Gemini.

const RULES = [
  { id: 'secret.aws-access-key', title: 'AWS access key ID', re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, severity: 'critical' },
  { id: 'secret.github-token', title: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g, severity: 'critical' },
  { id: 'secret.google-api-key', title: 'Google API key', re: /\b(AIza[0-9A-Za-z_\-]{35})\b/g, severity: 'high' },
  { id: 'secret.slack-token', title: 'Slack token', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g, severity: 'high' },
  { id: 'secret.stripe-live-key', title: 'Stripe live secret key', re: /\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b/g, severity: 'critical' },
  { id: 'secret.private-key', title: 'Private key block', re: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g, severity: 'critical' },
  { id: 'secret.jwt', title: 'JSON Web Token', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, severity: 'medium' },
  { id: 'secret.db-url-password', title: 'Database URL with password', re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/'"]+:[^@\s'"]{3,}@[^\s'"]+)/g, severity: 'high' },
];

// key = "value" style assignments of sensitive names with a literal value.
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token|client_?secret|private_?key)[A-Za-z0-9_]*)\s*[:=]\s*(['"`])([^'"`\s]{8,})\2/gi;
const PLACEHOLDER = /^(?:x+|\*+|changeme|change_me|your[_-].*|example.*|placeholder|dummy|test|sample|<.*>|\$\{.*\}|process\.env.*|os\.environ.*|null|none|undefined|todo|redacted)$/i;

export function shannonEntropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function redact(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 6, 24))}${value.slice(-2)}`;
}

function lineOf(content, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export function scanSecrets(files) {
  const findings = [];
  for (const { path, content } of files) {
    const isExample = /(\.example|\.sample|\.template)$|(^|\/)(test|tests|__tests__|fixtures?)\//i.test(path);
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(content))) {
        findings.push({
          ruleId: rule.id,
          category: 'secret',
          title: `Hard-coded ${rule.title}`,
          severity: isExample ? 'low' : rule.severity,
          file: path,
          line: lineOf(content, m.index),
          evidence: redact(m[1]),
          cwe: 'CWE-798',
          owasp: 'A07:2021 Identification and Authentication Failures',
          description: `A value matching the format of a ${rule.title} is committed in source code. Anyone with read access to the code can use it.`,
          secretRange: [m.index, m.index + m[1].length],
        });
      }
    }
    ASSIGNMENT.lastIndex = 0;
    let m;
    while ((m = ASSIGNMENT.exec(content))) {
      const value = m[3];
      if (PLACEHOLDER.test(value)) continue;
      if (shannonEntropy(value) < 3.0) continue;
      const start = m.index + m[0].indexOf(value);
      // Skip when one of the specific rules already covered this location.
      if (findings.some((f) => f.file === path && f.secretRange && f.secretRange[0] <= start && start < f.secretRange[1])) continue;
      findings.push({
        ruleId: 'secret.generic-assignment',
        category: 'secret',
        title: `Hard-coded credential in "${m[1]}"`,
        severity: isExample ? 'low' : 'high',
        file: path,
        line: lineOf(content, m.index),
        evidence: `${m[1]} = "${redact(value)}"`,
        cwe: 'CWE-798',
        owasp: 'A07:2021 Identification and Authentication Failures',
        description: 'A credential-like variable is assigned a literal, high-entropy value instead of being loaded from a secret manager or environment variable.',
        secretRange: [start, start + value.length],
      });
    }
  }
  return findings;
}

// Replaces every detected secret in the content with its redacted form so
// snippets shown to users or sent to Gemini never contain the raw value.
export function redactContent(content, ranges) {
  if (!ranges.length) return content;
  const sorted = [...ranges].sort((a, b) => b[0] - a[0]);
  let out = content;
  for (const [s, e] of sorted) out = out.slice(0, s) + redact(out.slice(s, e)) + out.slice(e);
  return out;
}
