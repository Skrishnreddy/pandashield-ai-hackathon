// Firebase Authentication: every /api route except /api/config requires a
// valid Firebase ID token in the Authorization header.

export function requireAuth(verifyIdToken) {
  return async (req, res, next) => {
    const header = req.get('authorization') || '';
    const m = header.match(/^Bearer\s+([A-Za-z0-9._-]+)$/);
    if (!m) return res.status(401).json({ error: 'Sign in to continue.' });
    try {
      const decoded = await verifyIdToken(m[1]);
      req.user = { uid: decoded.uid, email: decoded.email || null, name: decoded.name || null };
      return next();
    } catch {
      return res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
    }
  };
}

// Simple fixed-window limiter per user. Cloud Run may run several instances,
// so this is a per-instance safety net, not a billing control.
export function rateLimit({ windowMs, max, key = (req) => req.user?.uid || req.ip, message }) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const k = key(req);
    let entry = hits.get(k);
    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 0 };
      hits.set(k, entry);
    }
    entry.count++;
    if (hits.size > 10000) for (const [hk, v] of hits) if (now - v.start > windowMs) hits.delete(hk);
    if (entry.count > max) {
      res.set('retry-after', String(Math.ceil((entry.start + windowMs - now) / 1000)));
      return res.status(429).json({ error: message || 'Too many requests. Please try again later.' });
    }
    return next();
  };
}
