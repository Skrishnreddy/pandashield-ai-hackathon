// Firebase Web SDK: Authentication (Google sign-in) and Firestore (live,
// read-only access to the signed-in user's own scan history).
import { initializeApp } from 'firebase/app';
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged,
  connectAuthEmulator, signInWithEmailAndPassword, createUserWithEmailAndPassword,
} from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator, collection, query, orderBy, limit, onSnapshot } from 'firebase/firestore';

let services = null;

export async function initFirebase() {
  if (services) return services;
  const res = await fetch('/api/config');
  if (!res.ok) throw new Error('Could not load app configuration.');
  const cfg = await res.json();
  if (!cfg.firebase?.apiKey) throw new Error('Firebase is not configured for this deployment.');
  const app = initializeApp(cfg.firebase);
  const auth = getAuth(app);
  const db = getFirestore(app);
  if (cfg.emulators?.auth) connectAuthEmulator(auth, cfg.emulators.auth, { disableWarnings: true });
  if (cfg.emulators?.firestore) {
    const [host, port] = cfg.emulators.firestore.split(':');
    connectFirestoreEmulator(db, host, Number(port));
  }
  services = { app, auth, db, cfg };
  return services;
}

export function watchAuth(cb) {
  return onAuthStateChanged(services.auth, cb);
}

export function signInWithGoogle() {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return signInWithPopup(services.auth, provider);
}

// Only offered when the app is wired to the local Firebase Auth emulator
// (development and automated tests). Never shown in production.
export async function emulatorSignIn(email, password) {
  try {
    return await signInWithEmailAndPassword(services.auth, email, password);
  } catch {
    return createUserWithEmailAndPassword(services.auth, email, password);
  }
}

export function logout() {
  return signOut(services.auth);
}

export function watchScanHistory(uid, cb, onError) {
  const q = query(collection(services.db, 'users', uid, 'scans'), orderBy('createdAt', 'desc'), limit(25));
  return onSnapshot(q, (snap) => {
    cb(snap.docs.map((d) => {
      const data = d.data({ serverTimestamps: 'estimate' });
      return { id: d.id, ...data, createdAt: data.createdAt?.toDate?.().toISOString() || null };
    }));
  }, onError);
}
