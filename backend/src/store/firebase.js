// Firebase Admin initialisation for the hackathon project only.
// On Cloud Run, credentials come from the service's own service account
// (Application Default Credentials). No key files are used.

import { initializeApp, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { config } from '../config.js';

let app;

export function firebaseApp() {
  if (!app) app = getApps()[0] || initializeApp(config.projectId ? { projectId: config.projectId } : undefined);
  return app;
}

export const adminAuth = () => getAuth(firebaseApp());

let db;
export function firestore() {
  if (!db) {
    db = getFirestore(firebaseApp());
    db.settings({ ignoreUndefinedProperties: true });
  }
  return db;
}
