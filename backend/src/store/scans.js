// Firestore data model (hackathon project only):
//
//   users/{uid}                                  profile + counters
//   users/{uid}/scans/{scanId}                   scan summary, stats, Gemini summary
//   users/{uid}/scans/{scanId}/findings/{id}     one finding + Gemini triage + Q&A
//
// All writes go through this server (Admin SDK). Browsers can only READ
// their own documents, enforced by firebase/firestore.rules.

import { FieldValue } from 'firebase-admin/firestore';

export const MAX_STORED_FINDINGS = 300;
const ALLOWED_STATUS = ['open', 'fixed', 'accepted_risk', 'false_positive'];

export class ScanStore {
  constructor(db) {
    this.db = db;
  }

  userRef(uid) {
    return this.db.collection('users').doc(uid);
  }

  scanRef(uid, scanId) {
    return this.userRef(uid).collection('scans').doc(scanId);
  }

  async saveScan(user, scan) {
    const ref = this.userRef(user.uid).collection('scans').doc();
    const findings = scan.findings.slice(0, MAX_STORED_FINDINGS);
    const now = FieldValue.serverTimestamp();
    const summary = {
      name: scan.name,
      source: scan.source,
      appContext: scan.appContext || '',
      status: scan.ai?.error ? 'scanned' : 'triaged',
      stats: scan.stats,
      meta: scan.meta,
      ai: scan.ai
        ? {
            executiveSummary: scan.ai.executiveSummary || '',
            overallRisk: scan.ai.overallRisk || null,
            fixFirst: scan.ai.fixFirst || [],
            model: scan.ai.model || null,
            triaged: scan.ai.triaged || 0,
            latencyMs: scan.ai.latencyMs || null,
            error: scan.ai.error || null,
          }
        : null,
      findingCount: scan.findings.length,
      findingsTruncated: scan.findings.length > findings.length,
      createdAt: now,
      updatedAt: now,
      ownerUid: user.uid,
    };

    // Firestore batches are limited to 500 operations.
    let batch = this.db.batch();
    let ops = 0;
    batch.set(ref, summary);
    ops++;
    for (const f of findings) {
      batch.set(ref.collection('findings').doc(f.id), { ...f, ai: scan.ai?.byId?.[f.id] || null, conversation: [] });
      if (++ops >= 450) {
        await batch.commit();
        batch = this.db.batch();
        ops = 0;
      }
    }
    batch.set(this.userRef(user.uid), {
      email: user.email || null,
      displayName: user.name || null,
      lastScanAt: now,
      scanCount: FieldValue.increment(1),
    }, { merge: true });
    await batch.commit();
    return ref.id;
  }

  async listScans(uid, limit = 20) {
    const snap = await this.userRef(uid).collection('scans').orderBy('createdAt', 'desc').limit(limit).get();
    return snap.docs.map((d) => serialise({ id: d.id, ...d.data() }));
  }

  async getScan(uid, scanId) {
    const doc = await this.scanRef(uid, scanId).get();
    if (!doc.exists) return null;
    const findings = await this.scanRef(uid, scanId).collection('findings').get();
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return serialise({
      id: doc.id,
      ...doc.data(),
      findings: findings.docs.map((d) => d.data()).sort((a, b) => order[a.severity] - order[b.severity]),
    });
  }

  async getFinding(uid, scanId, findingId) {
    const doc = await this.scanRef(uid, scanId).collection('findings').doc(findingId).get();
    return doc.exists ? doc.data() : null;
  }

  async setFindingStatus(uid, scanId, findingId, status) {
    if (!ALLOWED_STATUS.includes(status)) throw Object.assign(new Error('Invalid status.'), { status: 400, expose: true });
    const ref = this.scanRef(uid, scanId).collection('findings').doc(findingId);
    const doc = await ref.get();
    if (!doc.exists) return false;
    await ref.update({ status, statusUpdatedAt: FieldValue.serverTimestamp() });
    await this.scanRef(uid, scanId).update({ updatedAt: FieldValue.serverTimestamp() });
    return true;
  }

  async appendConversation(uid, scanId, findingId, entry) {
    const ref = this.scanRef(uid, scanId).collection('findings').doc(findingId);
    await ref.update({ conversation: FieldValue.arrayUnion(entry) });
  }

  async saveTriage(uid, scanId, ai) {
    const ref = this.scanRef(uid, scanId);
    let batch = this.db.batch();
    let ops = 0;
    batch.update(ref, {
      status: 'triaged',
      ai: {
        executiveSummary: ai.executiveSummary || '',
        overallRisk: ai.overallRisk || null,
        fixFirst: ai.fixFirst || [],
        model: ai.model || null,
        triaged: ai.triaged || 0,
        latencyMs: ai.latencyMs || null,
        error: null,
      },
      updatedAt: FieldValue.serverTimestamp(),
    });
    for (const [id, triage] of Object.entries(ai.byId || {})) {
      batch.update(ref.collection('findings').doc(id), { ai: triage });
      if (++ops >= 450) {
        await batch.commit();
        batch = this.db.batch();
        ops = 0;
      }
    }
    await batch.commit();
  }

  async deleteScan(uid, scanId) {
    const ref = this.scanRef(uid, scanId);
    const doc = await ref.get();
    if (!doc.exists) return false;
    await this.db.recursiveDelete(ref);
    return true;
  }
}

// Converts Firestore Timestamps to ISO strings for JSON responses.
export function serialise(v) {
  if (v && typeof v.toDate === 'function') return v.toDate().toISOString();
  if (Array.isArray(v)) return v.map(serialise);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, serialise(x)]));
  return v;
}
