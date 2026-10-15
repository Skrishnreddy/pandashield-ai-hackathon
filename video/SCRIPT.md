# Demo video script — PandaShield AI Hackathon Edition

**Target length: 2:45** (the official rules require a video **under 3 minutes**).
Everything shown is the live, deployed Cloud Run app. Gemini output shown on screen is whatever the real model returns during recording; nothing is staged or edited into the UI.

| Time | Screen | Narration |
|---|---|---|
| 0:00–0:15 | Title card, then a long, unprioritised scanner output | "Developers ship code faster than anyone can review it for security. Scanners produce long lists of CWE numbers, and nobody knows which ones matter or how to fix them." |
| 0:15–0:30 | PandaShield landing page | "PandaShield AI is a security analyst for every developer. Real scanners find the problems, and Gemini explains them, ranks them for *your* app, and writes the fix." |
| 0:30–0:45 | Sign in with Google, then the New scan screen | "I sign in with Google through Firebase Authentication and pick a target. It can be a public GitHub repo, uploaded files, pasted code, or this intentionally vulnerable demo API." |
| 0:45–1:05 | Show the app context, click **Run security analysis**, show the progress line | "I tell PandaShield this is an internet-facing orders API that stores customer data. On Cloud Run, it runs 35 code rules, secret detection and live CVE lookups from OSV.dev. Then it sends only the verified findings to Gemini." |
| 1:05–1:30 | Results: score, severity counts, Gemini executive summary, Fix first list | "Here is the result. Gemini wrote an executive summary and a fix-first list for this particular app, not a generic severity sort." |
| 1:30–2:00 | Open the top finding: highlighted code, explanation, attack scenario, fixed code; click **Copy fix** | "For each finding, I see the exact line, a plain-language explanation, how an attacker would exploit it, and corrected code I can copy. Notice the AWS key is redacted. Secrets never reach Firestore or Gemini." |
| 2:00–2:15 | Ask a follow-up ("How would I test that this is fixed?"), then **Mark fixed** | "I can ask Gemini follow-up questions about this finding, then mark it fixed." |
| 2:15–2:25 | Reload the page, history sidebar shows the scan, reopen it, status still "Fixed" | "Everything is saved in Firestore per user, so after a refresh my history and triage decisions are still here." |
| 2:25–2:38 | Architecture diagram, then the System status page with all checks green | "Under the hood: Firebase Auth, Cloud Firestore with owner-only security rules, Gemini on Vertex AI with no API keys, and one Cloud Run service. This status page checks each one live." |
| 2:38–2:45 | Download report, then the closing card with the URL | "Real findings, real fixes, in minutes. PandaShield AI, Hackathon Edition." |

Word count of the narration is about 330 words. At a natural pace that fits within 2:45; trim the 0:45 line first if a take runs long.
