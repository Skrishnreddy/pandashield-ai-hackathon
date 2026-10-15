// Integration tests against the real Firebase Auth + Firestore emulators.
// Run with: npm run test:emulator   (needs the Firebase CLI and Java)
//
// Verifies: ScanStore persistence (write, reopen, update, delete), Firebase
// ID token verification by the Admin SDK, and Firestore security rules
// (owners can read their own data, nobody can read others' data, browsers
// cannot write).

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initializeApp as initClient, deleteApp } from 'firebase/app';
import { getAuth, connectAuthEmulator, createUserWithEmailAndPassword } from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator, doc, getDoc, setDoc, collection, getDocs, updateDoc } from 'firebase/firestore';
import { adminAuth, firestore } from '../src/store/firebase.js';
import { ScanStore } from '../src/store/scans.js';
import { runScan } from '../src/scan/index.js';
import { loadSample } from '../src/app.js';

const PROJECT = process.env.GCLOUD_PROJECT || 'demo-pandashield';
assert.ok(process.env.FIRESTORE_EMULATOR_HOST, 'FIRESTORE_EMULATOR_HOST must be set (run via firebase emulators:exec)');
assert.ok(process.env.FIREBASE_AUTH_EMULATOR_HOST, 'FIREBASE_AUTH_EMULATOR_HOST must be set');

const clients = [];
async function clientFor(email) {
  const app = initClient({ apiKey: 'demo-key', projectId: PROJECT, authDomain: `${PROJECT}.firebaseapp.com` }, email);
  clients.push(app);
  const auth = getAuth(app);
  connectAuthEmulator(auth, `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`, { disableWarnings: true });
  const db = getFirestore(app);
  const [h, p] = process.env.FIRESTORE_EMULATOR_HOST.split(':');
  connectFirestoreEmulator(db, h, Number(p));
  const cred = await createUserWithEmailAndPassword(auth, email, 'test-password-123');
  return { auth, db, user: cred.user };
}

let alice;
let bob;
let store;
let scanId;
let findingId;

before(async () => {
  alice = await clientFor(`alice-${Date.now()}@example.com`);
  bob = await clientFor(`bob-${Date.now()}@example.com`);
  store = new ScanStore(firestore());
});

after(async () => {
  for (const a of clients) await deleteApp(a);
  await firestore().terminate();
});

test('Admin SDK verifies a real Firebase ID token and rejects a tampered one', async () => {
  const token = await alice.user.getIdToken();
  const decoded = await adminAuth().verifyIdToken(token);
  assert.equal(decoded.uid, alice.user.uid);
  await assert.rejects(adminAuth().verifyIdToken(token.slice(0, -4) + 'AAAA'));
});

test('ScanStore persists a scan with findings and Gemini triage, and reopens it', async () => {
  const files = loadSample(new URL('../../samples', import.meta.url).pathname, 'acme-orders-api');
  const result = await runScan(files, { fetchImpl: async () => ({ ok: true, json: async () => ({ results: [] }) }) });
  const first = result.findings[0];
  scanId = await store.saveScan({ uid: alice.user.uid, email: alice.user.email }, {
    ...result,
    name: 'Emulator test',
    source: { type: 'sample', sampleId: 'acme-orders-api' },
    appContext: 'test',
    ai: { executiveSummary: 'summary', overallRisk: 'critical', fixFirst: [first.id], model: 'gemini-test', triaged: 1, byId: { [first.id]: { priority: 'P1', explanation: 'why' } } },
  });
  findingId = first.id;
  const reopened = await store.getScan(alice.user.uid, scanId);
  assert.equal(reopened.name, 'Emulator test');
  assert.equal(reopened.findings.length, result.findings.length);
  assert.equal(reopened.findings.find((f) => f.id === first.id).ai.priority, 'P1');
  assert.match(reopened.createdAt, /^\d{4}-\d\d-\d\dT/);
  const list = await store.listScans(alice.user.uid);
  assert.equal(list[0].id, scanId);
});

test('ScanStore updates status, appends Q&A, and saves re-triage', async () => {
  assert.equal(await store.setFindingStatus(alice.user.uid, scanId, findingId, 'fixed'), true);
  await assert.rejects(store.setFindingStatus(alice.user.uid, scanId, findingId, 'bogus'));
  assert.equal(await store.setFindingStatus(alice.user.uid, scanId, 'nope', 'fixed'), false);
  await store.appendConversation(alice.user.uid, scanId, findingId, { question: 'q', answer: 'a', at: 'now' });
  await store.saveTriage(alice.user.uid, scanId, { executiveSummary: 'v2', fixFirst: [], model: 'gemini-test', triaged: 1, byId: { [findingId]: { priority: 'P2' } } });
  const f = await store.getFinding(alice.user.uid, scanId, findingId);
  assert.equal(f.status, 'fixed');
  assert.equal(f.conversation.length, 1);
  assert.equal(f.ai.priority, 'P2');
  assert.equal((await store.getScan(alice.user.uid, scanId)).ai.executiveSummary, 'v2');
});

test('security rules: owner can read their scans and findings from the browser SDK', async () => {
  const snap = await getDoc(doc(alice.db, 'users', alice.user.uid, 'scans', scanId));
  assert.equal(snap.exists(), true);
  const findings = await getDocs(collection(alice.db, 'users', alice.user.uid, 'scans', scanId, 'findings'));
  assert.ok(findings.size > 10);
});

test('security rules: another user cannot read the owner\'s data', async () => {
  await assert.rejects(getDoc(doc(bob.db, 'users', alice.user.uid, 'scans', scanId)), /permission/i);
  await assert.rejects(getDocs(collection(bob.db, 'users', alice.user.uid, 'scans')), /permission/i);
});

test('security rules: browsers cannot write, even to their own documents', async () => {
  await assert.rejects(setDoc(doc(alice.db, 'users', alice.user.uid, 'scans', 'forged'), { name: 'x' }), /permission/i);
  await assert.rejects(updateDoc(doc(alice.db, 'users', alice.user.uid, 'scans', scanId), { stats: {} }), /permission/i);
  await assert.rejects(setDoc(doc(alice.db, 'other', 'x'), { a: 1 }), /permission/i);
});

test('ScanStore deletes a scan and its findings recursively', async () => {
  assert.equal(await store.deleteScan(alice.user.uid, scanId), true);
  assert.equal(await store.getScan(alice.user.uid, scanId), null);
  assert.equal(await store.getFinding(alice.user.uid, scanId, findingId), null);
});
