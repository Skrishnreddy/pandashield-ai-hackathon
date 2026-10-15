// Central configuration. Every value comes from the environment so the
// hackathon deployment never shares settings with any other project.

const int = (v, d) => (Number.isFinite(Number(v)) && v !== '' ? Number(v) : d);

export const config = {
  port: int(process.env.PORT, 8080),
  env: process.env.NODE_ENV || 'development',

  // Google Cloud / Firebase project used ONLY by the hackathon edition.
  projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID || '',

  // Gemini. On Cloud Run we use Vertex AI with the service account (no key).
  // Locally a Gemini API key can be used instead.
  gemini: {
    useVertex: (process.env.GEMINI_USE_VERTEX || 'true') === 'true',
    location: process.env.GEMINI_LOCATION || 'global',
    apiKey: process.env.GEMINI_API_KEY || '',
    model: process.env.GEMINI_MODEL || 'gemini-3.8-flash',
    // LOW keeps triage fast and inexpensive; set MEDIUM/HIGH for deeper analysis.
    thinkingLevel: process.env.GEMINI_THINKING_LEVEL || 'LOW',
    maxFindings: int(process.env.GEMINI_MAX_FINDINGS, 30),
    timeoutMs: int(process.env.GEMINI_TIMEOUT_MS, 90000),
  },

  // Public Firebase web config, served to the browser at /api/config.
  // These values identify the project; they are not secrets.
  firebaseWeb: {
    apiKey: process.env.FIREBASE_WEB_API_KEY || '',
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || '',
    projectId: process.env.FIREBASE_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || '',
    appId: process.env.FIREBASE_APP_ID || '',
  },

  // Emulator support for local development and automated tests.
  emulators: {
    auth: process.env.FIREBASE_AUTH_EMULATOR_HOST || '',
    firestore: process.env.FIRESTORE_EMULATOR_HOST || '',
  },

  limits: {
    maxFiles: int(process.env.MAX_FILES, 400),
    maxFileBytes: int(process.env.MAX_FILE_BYTES, 512 * 1024),
    maxTotalBytes: int(process.env.MAX_TOTAL_BYTES, 8 * 1024 * 1024),
    maxTarballBytes: int(process.env.MAX_TARBALL_BYTES, 30 * 1024 * 1024),
    maxRequestBytes: int(process.env.MAX_REQUEST_BYTES, 3 * 1024 * 1024),
    scansPerHour: int(process.env.SCANS_PER_HOUR, 20),
    asksPerHour: int(process.env.ASKS_PER_HOUR, 60),
  },

  osvBaseUrl: process.env.OSV_BASE_URL || 'https://api.osv.dev',
};
