# PandaShield AI — Hackathon Edition: solution description

**Theme:** Future of Work & Enterprise Productivity

**One line:** PandaShield AI is a security analyst for developers. Real scanners find vulnerabilities in code, secrets and dependencies, and Gemini explains each verified finding, ranks it for the specific application, and writes the fix.

**Problem.** Security scanners give developers long lists of CWE ids with little context. Teams lose hours working out which findings matter and how to fix them, so real risks stay open. General-purpose AI chat can explain code, but it can also invent vulnerabilities.

**Solution.** A user signs in with Google and scans a public GitHub repository, uploaded files, pasted code, or a built-in vulnerable demo app. Deterministic scanners run first: 35 code rules for injection, XSS, SSRF, path traversal, unsafe deserialisation, weak crypto and misconfiguration; secret detection that redacts values; and dependency CVE lookups from OSV.dev. Gemini then triages only those verified findings. For each one it gives a plain-language explanation, a realistic attack scenario, a P1–P4 priority based on the application context the user describes, remediation steps and corrected code. It also writes a "fix first" summary. Developers can ask follow-up questions on any finding, mark findings fixed, accepted or false positive, reopen past scans, and export Markdown or SARIF reports.

**How the Google technologies are used**

- **Gemini (gemini-3.8-flash on Vertex AI):** the core of the product. The server uses structured output with a strict JSON schema, fences untrusted code and context in the prompt, and discards any finding Gemini returns that the scanners did not produce. Gemini also answers per-finding follow-up questions using the finding's evidence and the conversation so far.
- **Firebase Authentication:** Google sign-in in the browser. Every API request carries the Firebase ID token, and the Cloud Run service verifies it with the Firebase Admin SDK.
- **Cloud Firestore:** stores each user's scans, findings, Gemini analysis, finding status and Q&A under `users/{uid}/scans/{scanId}/findings/{findingId}`. The server writes through the Admin SDK. The browser reads its own scan history live with the Firestore Web SDK. Security rules allow owners to read only their own data and block all writes from the browser.
- **Cloud Run:** a single container serves the React app and the Node.js API. It scales to zero and uses a least-privilege service account for Vertex AI and Firestore, so no API keys exist in the deployment.

**Why it is different.** The scanners provide the facts and Gemini provides the judgement. Every AI explanation is tied to a real line of code or a real advisory. Secrets are never stored or sent to the model, and scanned code is never executed.
