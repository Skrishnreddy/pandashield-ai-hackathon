// Normalises user-supplied files into a safe, bounded in-memory list.
// Nothing is ever written to disk and nothing is executed.

import { config } from '../config.js';

export class InputError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
    this.expose = true;
  }
}

const SKIP_DIRS = /(^|\/)(node_modules|\.git|dist|build|vendor|\.next|coverage|__pycache__|\.venv|venv|target)(\/|$)/;
const TEXT_EXT = /\.(js|jsx|mjs|cjs|ts|tsx|py|java|go|rb|php|cs|kt|swift|rs|c|cc|cpp|h|sh|bash|yml|yaml|json|toml|ini|cfg|conf|env|xml|html|htm|vue|svelte|tf|sql|properties|gradle|dockerfile|txt|md)$/i;
const SPECIAL_NAMES = /(^|\/)(Dockerfile|\.env(\..+)?|requirements(-[\w]+)?\.txt|package\.json|package-lock\.json|Pipfile|Gemfile|go\.mod)$/i;

export function isScannablePath(path) {
  if (SKIP_DIRS.test(path)) return false;
  return TEXT_EXT.test(path) || SPECIAL_NAMES.test(path);
}

export function normalisePath(raw) {
  if (typeof raw !== 'string') throw new InputError('Each file needs a string path.');
  let p = raw.replace(/\\/g, '/').replace(/^\.?\/+/, '').trim();
  if (!p || p.length > 300) throw new InputError('File paths must be 1-300 characters.');
  if (p.split('/').some((seg) => seg === '..')) throw new InputError('File paths may not contain "..".');
  if (/[\u0000-\u001f]/.test(p)) throw new InputError('File paths may not contain control characters.');
  return p;
}

export function looksBinary(content) {
  return content.includes('\u0000');
}

// Accepts [{path, content}] from the API and returns a bounded, validated list.
export function normaliseFiles(files, limits = config.limits) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new InputError('Provide at least one file to scan.');
  }
  if (files.length > limits.maxFiles) {
    throw new InputError(`Too many files: the limit is ${limits.maxFiles}.`);
  }
  const out = [];
  const seen = new Set();
  let total = 0;
  for (const f of files) {
    if (!f || typeof f !== 'object') throw new InputError('Each file must be an object with path and content.');
    const path = normalisePath(f.path);
    if (typeof f.content !== 'string') throw new InputError(`File ${path} has no text content.`);
    const bytes = Buffer.byteLength(f.content, 'utf8');
    if (bytes > limits.maxFileBytes) throw new InputError(`File ${path} is larger than ${Math.round(limits.maxFileBytes / 1024)} KB.`);
    total += bytes;
    if (total > limits.maxTotalBytes) throw new InputError('The files are larger than the total upload limit.');
    if (seen.has(path)) continue;
    seen.add(path);
    if (looksBinary(f.content)) continue;
    out.push({ path, content: f.content });
  }
  if (out.length === 0) throw new InputError('None of the files contained scannable text.');
  return out;
}

export function languageOf(path) {
  const lower = path.toLowerCase();
  if (/\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte)$/.test(lower)) return 'javascript';
  if (/\.py$/.test(lower)) return 'python';
  if (/\.(html|htm)$/.test(lower)) return 'html';
  if (/(^|\/)dockerfile$/.test(lower)) return 'docker';
  if (/\.(yml|yaml)$/.test(lower)) return 'yaml';
  if (/\.(tf)$/.test(lower)) return 'terraform';
  return 'other';
}
