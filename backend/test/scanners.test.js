import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normaliseFiles, InputError, isScannablePath } from '../src/scan/files.js';
import { scanSecrets, redact, redactContent } from '../src/scan/secrets.js';
import { scanCode, RULES } from '../src/scan/sast.js';
import { parseManifests, cvss3Score, osvSeverity, fixedVersions, scanDependencies } from '../src/scan/deps.js';
import { runScan, computeStats } from '../src/scan/index.js';
import { loadSample } from '../src/app.js';

const limits = { maxFiles: 5, maxFileBytes: 100, maxTotalBytes: 250 };

test('normaliseFiles validates paths, sizes and counts', () => {
  assert.throws(() => normaliseFiles([], limits), InputError);
  assert.throws(() => normaliseFiles([{ path: '../etc/passwd', content: 'x' }], limits), /may not contain/);
  assert.throws(() => normaliseFiles([{ path: 'a.js', content: 'x'.repeat(101) }], limits), /larger than/);
  assert.throws(() => normaliseFiles(Array.from({ length: 6 }, (_, i) => ({ path: `${i}.js`, content: 'x' })), limits), /Too many files/);
  assert.throws(() => normaliseFiles([{ path: 'a.js', content: 5 }], limits), /no text content/);
  const out = normaliseFiles([{ path: './src\\a.js', content: 'ok' }, { path: 'src/a.js', content: 'dup' }, { path: 'b.bin', content: 'a\u0000b' }, { path: 'c.js', content: 'ok' }], limits);
  assert.deepEqual(out.map((f) => f.path), ['src/a.js', 'c.js']);
});

test('isScannablePath skips vendored and binary paths', () => {
  assert.equal(isScannablePath('src/app.js'), true);
  assert.equal(isScannablePath('requirements.txt'), true);
  assert.equal(isScannablePath('Dockerfile'), true);
  assert.equal(isScannablePath('node_modules/x/index.js'), false);
  assert.equal(isScannablePath('logo.png'), false);
});

test('secret scanner finds and redacts credentials', () => {
  const content = [
    "const key = 'AKIAIOSFODNN7EXAMPLE';",
    'token = "ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"',
    "const dbPassword = 'Xk9#mQ2$vL7pR4tZ';",
    "const password = 'changeme';",
    "const apiKey = process.env.API_KEY;",
    'DATABASE_URL=postgres://admin:S3cretPw@db:5432/app',
  ].join('\n');
  const findings = scanSecrets([{ path: 'src/config.js', content }]);
  const ids = findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ['secret.aws-access-key', 'secret.db-url-password', 'secret.generic-assignment', 'secret.github-token']);
  for (const f of findings) {
    assert.ok(!f.evidence.includes('IOSFODNN7EXAMPLE'), 'raw AWS key must not appear');
    assert.ok(!f.evidence.includes('Xk9#mQ2$vL7pR4tZ'), 'raw password must not appear');
  }
  const redacted = redactContent(content, findings.map((f) => f.secretRange));
  assert.ok(!redacted.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!redacted.includes('S3cretPw'));
  assert.ok(redacted.includes("process.env.API_KEY"));
});

test('secret scanner downgrades findings in example and test files', () => {
  const f = scanSecrets([{ path: 'tests/fixtures/keys.js', content: "k='AKIAIOSFODNN7EXAMPLE'" }]);
  assert.equal(f[0].severity, 'low');
  assert.equal(redact('abcdefghijkl').startsWith('abcd'), true);
});

const positives = {
  'js.eval': ['a.js', 'const r = eval(req.query.x);'],
  'js.expression-eval': ['a.js', 'res.send({ output: mathjs.eval(req.body.eqn) });'],
  'js.new-function': ['a.js', 'const f = new Function(body);'],
  'js.child-process-exec': ['a.js', 'exec(`ls ${dir}`, cb);'],
  'js.sql-concat': ['a.js', 'db.query("SELECT * FROM u WHERE id = " + id);'],
  'js.nosql-where': ['a.js', 'User.find({ $where: "this.name == \'" + name + "\'" });'],
  'js.inner-html': ['a.js', 'el.innerHTML = userInput;'],
  'js.dangerously-set-inner-html': ['a.jsx', '<div dangerouslySetInnerHTML={{ __html: post.body }} />'],
  'js.document-write': ['a.js', 'document.write(location.hash);'],
  'js.path-traversal': ['a.js', 'res.sendFile(path.join(root, req.query.f));'],
  'js.ssrf': ['a.js', 'const r = await fetch(req.body.url);'],
  'js.open-redirect': ['a.js', 'res.redirect(req.query.next);'],
  'js.weak-hash': ['a.js', "crypto.createHash('md5')"],
  'js.insecure-random': ['a.js', 'const sessionToken = Math.random().toString(36);'],
  'js.jwt-none': ['a.js', "jwt.verify(t, k, { algorithms: ['HS256', 'none'] });"],
  'js.jwt-decode-no-verify': ['a.js', 'const u = jwt.decode(token);'],
  'js.tls-reject-unauthorized': ['a.js', 'https.request({ rejectUnauthorized: false });'],
  'js.cors-wildcard-credentials': ['a.js', "app.use(cors({ origin: '*' }));"],
  'js.unsafe-deserialize': ['a.js', 'serialize.unserialize(req.cookies.profile);'],
  'js.prototype-pollution-merge': ['a.js', '_.merge(config, req.body);'],
  'js.xxe': ['a.js', "const doc = libxmljs.parseXmlString(buf.toString('utf8'), { noent: true });"],
  'py.eval-exec': ['a.py', 'result = eval(request.args["x"])'],
  'py.subprocess-shell': ['a.py', 'subprocess.run(cmd, shell=True)'],
  'py.os-system': ['a.py', 'os.system("ping " + host)'],
  'py.sql-format': ['a.py', 'cur.execute(f"SELECT * FROM t WHERE id = {i}")'],
  'py.pickle-load': ['a.py', 'obj = pickle.loads(data)'],
  'py.yaml-load': ['a.py', 'cfg = yaml.load(stream)'],
  'py.requests-verify-false': ['a.py', 'requests.get(url, verify=False)'],
  'py.flask-debug': ['a.py', 'app.run(debug=True)'],
  'py.weak-hash': ['a.py', 'h = hashlib.md5(b)'],
  'py.ssti': ['a.py', 'return render_template_string("<p>" + name)'],
  'py.ssrf': ['a.py', 'requests.get(request.args["url"])'],
  'docker.root-user': ['Dockerfile', 'FROM node:20\nCMD ["node","a.js"]'],
  'docker.curl-pipe-shell': ['Dockerfile', 'RUN curl -s https://x.sh | bash'],
  'yaml.privileged': ['k8s.yaml', 'securityContext:\n  privileged: true'],
};

const negatives = {
  'js.eval': ['a.js', "const v = evaluate(x); obj.eval(x); eval('1+1');"],
  'js.sql-concat': ['a.js', "db.query('SELECT * FROM u WHERE id = $1', [id]);"],
  'js.inner-html': ['a.js', "el.innerHTML = '';"],
  'js.child-process-exec': ['a.js', "execFile('ls', ['-la']);"],
  'py.yaml-load': ['a.py', 'cfg = yaml.load(stream, Loader=yaml.SafeLoader)'],
  'py.sql-format': ['a.py', 'cur.execute("SELECT * FROM t WHERE id = %s", (i,))'],
  'py.subprocess-shell': ['a.py', 'subprocess.run(["ls", path])'],
  'docker.root-user': ['Dockerfile', 'FROM node:20\nUSER node\nCMD ["node","a.js"]'],
};

test('every SAST rule has a passing positive test case', () => {
  for (const rule of RULES) assert.ok(positives[rule.id], `missing positive case for ${rule.id}`);
  for (const [id, [path, content]] of Object.entries(positives)) {
    const hits = scanCode([{ path, content }]).map((f) => f.ruleId);
    assert.ok(hits.includes(id), `${id} should match: ${content}`);
  }
});

test('SAST rules do not fire on safe equivalents', () => {
  for (const [id, [path, content]] of Object.entries(negatives)) {
    const hits = scanCode([{ path, content }]).map((f) => f.ruleId);
    assert.ok(!hits.includes(id), `${id} should NOT match: ${content}`);
  }
});

test('SQL concatenation is found when the query is built in a variable first', () => {
  const hits = (content) => scanCode([{ path: 'a.js', content }]).map((f) => f.ruleId);
  assert.ok(hits(`var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";`).includes('js.sql-concat'));
  assert.ok(hits('const q = `DELETE FROM sessions WHERE user = ${id}`;').includes('js.sql-concat'));
  assert.ok(!hits('const msg = "Select a file from the list: " + name;').includes('js.sql-concat'));
  assert.ok(!hits('const q = "SELECT * FROM users WHERE id = ?";').includes('js.sql-concat'));
});

test('eval() mentioned in prose or called with no argument is not reported', () => {
  assert.equal(scanCode([{ path: 'a.html', content: 'Avoid <code>eval()</code> on user input.' }]).length, 0);
});

test('SAST ignores comments and pandashield-ignore lines', () => {
  assert.equal(scanCode([{ path: 'a.js', content: '// eval(req.query.x)\neval(x); // pandashield-ignore' }]).length, 0);
  assert.equal(scanCode([{ path: 'a.py', content: '# pickle.loads(x)' }]).length, 0);
});

test('manifest parsing handles package-lock, package.json and requirements', () => {
  const deps = parseManifests([
    { path: 'package.json', content: JSON.stringify({ dependencies: { lodash: '^4.17.15', left: 'git+https://x', react: '18' }, devDependencies: { minimist: '1.2.5' } }) },
    { path: 'api/package.json', content: '{"dependencies":{"express":"4.17.1"}}' },
    { path: 'api/package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'api' }, 'node_modules/express': { version: '4.17.1' }, 'node_modules/qs': { version: '6.7.0', dev: true } } }) },
    { path: 'requirements.txt', content: 'flask==0.12.2  # old\nrequests>=2.19.0\n-e git+https://x\nDjango[argon2]==3.2.0\nbroken' },
    { path: 'bad/package.json', content: '{not json' },
  ]);
  const key = (d) => `${d.ecosystem}:${d.name}@${d.version}`;
  const got = deps.map(key).sort();
  assert.deepEqual(got, ['PyPI:Django@3.2.0', 'PyPI:flask@0.12.2', 'PyPI:requests@2.19.0', 'npm:express@4.17.1', 'npm:lodash@4.17.15', 'npm:minimist@1.2.5', 'npm:qs@6.7.0', 'npm:react@18.0.0']);
  assert.equal(deps.find((d) => d.name === 'minimist').dev, true);
});

test('CVSS v3 base score calculation matches the specification', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('nonsense'), null);
  assert.deepEqual(osvSeverity({ database_specific: { severity: 'MODERATE' } }), { severity: 'medium', cvss: null });
  assert.equal(osvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }).severity, 'critical');
  assert.deepEqual(fixedVersions({ affected: [{ package: { name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.19' }] }] }] }, 'lodash'), ['4.17.19']);
});

function fakeOsv(map) {
  const calls = [];
  const impl = async (url, opts) => {
    calls.push(url);
    if (url.endsWith('/v1/querybatch')) {
      const body = JSON.parse(opts.body);
      return { ok: true, json: async () => ({ results: body.queries.map((q) => ({ vulns: (map[`${q.package.name}@${q.version}`] || []).map((id) => ({ id })) })) }) };
    }
    const id = decodeURIComponent(url.split('/').pop());
    return {
      ok: true,
      json: async () => ({
        id,
        summary: `Summary of ${id}`,
        aliases: id === 'GHSA-1' ? ['CVE-2020-8203'] : [],
        database_specific: { severity: 'HIGH', cwe_ids: ['CWE-1321'] },
        affected: [{ package: { name: 'lodash' }, ranges: [{ events: [{ fixed: '4.17.19' }] }] }],
      }),
    };
  };
  return { impl, calls };
}

test('dependency scan queries OSV and builds findings with fixes and CVEs', async () => {
  const { impl, calls } = fakeOsv({ 'lodash@4.17.15': ['GHSA-1'], 'minimist@1.2.5': ['GHSA-2'] });
  const res = await scanDependencies([{ path: 'package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.15' }, devDependencies: { minimist: '1.2.5' } }) }], { fetchImpl: impl, baseUrl: 'https://osv.test' });
  assert.equal(res.error, null);
  assert.equal(res.dependencies, 2);
  assert.equal(res.findings.length, 2);
  const lodash = res.findings.find((f) => f.package.name === 'lodash');
  assert.equal(lodash.severity, 'high');
  assert.equal(lodash.advisory.cve, 'CVE-2020-8203');
  assert.deepEqual(lodash.advisory.fixedIn, ['4.17.19']);
  assert.equal(res.findings.find((f) => f.package.name === 'minimist').severity, 'medium', 'dev dependency is downgraded');
  assert.ok(calls[0].startsWith('https://osv.test/v1/querybatch'));
});

test('dependency scan reports OSV outages instead of failing the scan', async () => {
  const res = await scanDependencies([{ path: 'requirements.txt', content: 'flask==0.12.2' }], { fetchImpl: async () => ({ ok: false, status: 503 }) });
  assert.match(res.error, /HTTP 503/);
  assert.equal(res.findings.length, 0);
});

test('runScan on the built-in demo app finds every planted vulnerability class and never leaks secrets', async () => {
  const files = loadSample(new URL('../../samples', import.meta.url).pathname, 'acme-orders-api');
  const { impl } = fakeOsv({ 'lodash@4.17.15': ['GHSA-1'] });
  const r = await runScan(files, { fetchImpl: impl });
  const rules = new Set(r.findings.map((f) => f.ruleId));
  for (const id of ['secret.aws-access-key', 'secret.db-url-password', 'secret.generic-assignment', 'js.sql-concat', 'js.child-process-exec',
    'js.path-traversal', 'js.ssrf', 'js.eval', 'js.jwt-decode-no-verify', 'js.inner-html', 'py.pickle-load', 'py.subprocess-shell',
    'py.yaml-load', 'py.ssti', 'py.sql-format', 'docker.curl-pipe-shell', 'docker.root-user', 'dep.GHSA-1']) {
    assert.ok(rules.has(id), `expected ${id}`);
  }
  const json = JSON.stringify(r);
  for (const raw of ['IOSFODNN7EXAMPLE', 'Pr0d-0rders-2024!', 'q8Zr2LwT9vXe4NbK7pYc1HdM']) assert.ok(!json.includes(raw), `raw secret ${raw} leaked`);
  assert.equal(new Set(r.findings.map((f) => f.id)).size, r.findings.length, 'ids are unique');
  assert.ok(r.stats.securityScore < 20);
  assert.equal(r.meta.filesScanned, files.length);
});

test('computeStats scores a clean project at 100', () => {
  assert.equal(computeStats([]).securityScore, 100);
  assert.equal(computeStats([{ severity: 'low', category: 'code' }]).bySeverity.low, 1);
});
