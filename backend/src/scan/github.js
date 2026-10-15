// Downloads a PUBLIC GitHub repository as a tarball and extracts scannable
// text files into memory. The host is fixed (codeload.github.com) and the
// owner/repo/ref are strictly validated, so this cannot be used for SSRF.
// Repository code is only read as text; it is never executed.

import { createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';
import tar from 'tar-stream';
import { config } from '../config.js';
import { InputError, isScannablePath, looksBinary } from './files.js';

const NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$/;
const REF = /^[A-Za-z0-9._\/-]{1,100}$/;

export function parseGithubUrl(input) {
  if (typeof input !== 'string') throw new InputError('Enter a GitHub repository URL.');
  if (/(^|\/)\.\.(\/|$)|%2e%2e/i.test(input)) throw new InputError('The URL may not contain "..".');
  let url;
  try {
    url = new URL(input.trim());
  } catch {
    throw new InputError('That is not a valid URL.');
  }
  if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.username || url.password) {
    throw new InputError('Only public https://github.com repository URLs are supported.');
  }
  const parts = url.pathname.replace(/\/+$/, '').replace(/\.git$/, '').split('/').filter(Boolean);
  if (parts.length < 2) throw new InputError('Use the form https://github.com/owner/repo.');
  const [owner, repo] = parts;
  if (!NAME.test(owner) || !NAME.test(repo) || repo === '.' || repo === '..') throw new InputError('The owner or repository name is invalid.');
  let ref = 'HEAD';
  if (parts[2] === 'tree' && parts.length >= 4) ref = parts.slice(3).join('/');
  if (!REF.test(ref) || ref.split('/').includes('..')) throw new InputError('The branch or tag name is invalid.');
  return { owner, repo, ref };
}

export async function fetchGithubFiles(repoUrl, { fetchImpl = globalThis.fetch, limits = config.limits } = {}) {
  const { owner, repo, ref } = parseGithubUrl(repoUrl);
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/${ref.split('/').map(encodeURIComponent).join('/')}`;
  const res = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (res.status === 404) throw new InputError('Repository not found. Check the URL and make sure the repository is public.', 404);
  if (!res.ok) throw new InputError(`GitHub returned HTTP ${res.status} while downloading the repository.`, 502);
  const declared = Number(res.headers.get('content-length') || 0);
  if (declared && declared > limits.maxTarballBytes) throw new InputError('The repository is too large for the hackathon edition (30 MB archive limit).', 413);

  const files = await extractTarball(Readable.fromWeb(res.body), limits);
  return { owner, repo, ref, files };
}

export function extractTarball(stream, limits = config.limits) {
  return new Promise((resolve, reject) => {
    const files = [];
    let received = 0;
    let total = 0;
    let skipped = 0;
    let done = false;
    const extract = tar.extract();
    const gunzip = createGunzip();

    const fail = (err) => {
      if (done) return;
      done = true;
      stream.destroy?.();
      extract.destroy();
      reject(err);
    };

    stream.on('data', (chunk) => {
      received += chunk.length;
      if (received > limits.maxTarballBytes) fail(new InputError('The repository archive exceeds the 30 MB limit.', 413));
    });

    extract.on('entry', (header, entryStream, next) => {
      // Strip the "<repo>-<sha>/" prefix GitHub adds.
      const path = header.name.split('/').slice(1).join('/');
      const want = header.type === 'file' && path && !path.split('/').includes('..') && isScannablePath(path)
        && header.size <= limits.maxFileBytes && files.length < limits.maxFiles && total + header.size <= limits.maxTotalBytes;
      if (!want) {
        if (header.type === 'file') skipped++;
        entryStream.on('end', next);
        entryStream.resume();
        return;
      }
      const chunks = [];
      entryStream.on('data', (c) => chunks.push(c));
      entryStream.on('end', () => {
        const content = Buffer.concat(chunks).toString('utf8');
        if (!looksBinary(content)) {
          files.push({ path, content });
          total += header.size;
        }
        next();
      });
    });
    extract.on('finish', () => {
      if (done) return;
      done = true;
      if (!files.length) return reject(new InputError('No supported source files were found in the repository.'));
      resolve(Object.assign(files, { skipped }));
    });
    extract.on('error', (e) => fail(new InputError(`Could not read the repository archive: ${e.message}`, 502)));
    gunzip.on('error', (e) => fail(new InputError(`Could not decompress the repository archive: ${e.message}`, 502)));
    stream.on('error', fail);
    stream.pipe(gunzip).pipe(extract);
  });
}
