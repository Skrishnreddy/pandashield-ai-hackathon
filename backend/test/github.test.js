import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGzip } from 'node:zlib';
import { Readable } from 'node:stream';
import tar from 'tar-stream';
import { parseGithubUrl, fetchGithubFiles } from '../src/scan/github.js';

test('parseGithubUrl accepts only public github.com repository URLs', () => {
  assert.deepEqual(parseGithubUrl('https://github.com/owner/repo'), { owner: 'owner', repo: 'repo', ref: 'HEAD' });
  assert.deepEqual(parseGithubUrl('https://github.com/owner/repo.git/'), { owner: 'owner', repo: 'repo', ref: 'HEAD' });
  assert.deepEqual(parseGithubUrl('https://github.com/o/r/tree/feature/x'), { owner: 'o', repo: 'r', ref: 'feature/x' });
  for (const bad of [
    'http://github.com/o/r',
    'https://evil.com/o/r',
    'https://github.com.evil.com/o/r',
    'https://user:pw@github.com/o/r',
    'https://github.com:8443/o/r',
    'https://github.com/o',
    'https://github.com/o/r/tree/../../x',
    'https://169.254.169.254/latest/meta-data',
    'file:///etc/passwd',
    'not a url',
    42,
  ]) {
    assert.throws(() => parseGithubUrl(bad), undefined, `should reject ${bad}`);
  }
});

async function makeTarball(entries) {
  const pack = tar.pack();
  for (const [name, content] of entries) pack.entry({ name: `repo-abc123/${name}` }, content);
  pack.finalize();
  const chunks = [];
  for await (const c of pack.pipe(createGzip())) chunks.push(c);
  return Buffer.concat(chunks);
}

function responseFrom(buf, status = 200) {
  return {
    ok: status === 200,
    status,
    headers: new Map([['content-length', String(buf.length)]]),
    body: Readable.toWeb(Readable.from([buf])),
  };
}

test('fetchGithubFiles extracts only scannable text files from the archive', async () => {
  const buf = await makeTarball([
    ['src/app.js', 'eval(x)'],
    ['node_modules/lib/index.js', 'ignored'],
    ['image.png', 'binary'],
    ['requirements.txt', 'flask==0.12.2'],
    ['big.js', 'x'.repeat(2000)],
  ]);
  let requested;
  const res = await fetchGithubFiles('https://github.com/acme/demo', {
    fetchImpl: async (url, opts) => { requested = { url, opts }; return { ...responseFrom(buf), headers: { get: () => String(buf.length) } }; },
    limits: { maxFiles: 50, maxFileBytes: 1000, maxTotalBytes: 100000, maxTarballBytes: 1_000_000 },
  });
  assert.equal(requested.url, 'https://codeload.github.com/acme/demo/tar.gz/HEAD');
  assert.equal(requested.opts.redirect, 'error');
  assert.deepEqual(res.files.map((f) => f.path).sort(), ['requirements.txt', 'src/app.js']);
});

test('fetchGithubFiles reports missing repositories and oversized archives', async () => {
  await assert.rejects(
    fetchGithubFiles('https://github.com/acme/missing', { fetchImpl: async () => ({ ok: false, status: 404, headers: { get: () => null } }) }),
    /Repository not found/,
  );
  await assert.rejects(
    fetchGithubFiles('https://github.com/acme/huge', {
      fetchImpl: async () => ({ ok: true, status: 200, headers: { get: () => String(50 * 1024 * 1024) } }),
      limits: { maxTarballBytes: 1024, maxFiles: 10, maxFileBytes: 10, maxTotalBytes: 10 },
    }),
    /too large/,
  );
});
