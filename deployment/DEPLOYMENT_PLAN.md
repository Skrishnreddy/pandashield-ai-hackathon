# Deployment plan — PandaShield AI Hackathon Edition

**Status: waiting for approval. Nothing has been created or deployed.**

## Isolation from the existing PandaShield product

| Item | Hackathon Edition | Existing product |
|---|---|---|
| Google Cloud project | **New** project `pandashield-hackathon-<suffix>` | Not touched |
| Firebase project | Same new project | Not touched |
| Firestore database | New `(default)` database in the new project | Not touched |
| Cloud Run service | `pandashield-hackathon` in the new project | Not touched |
| Secrets / keys | None. Cloud Run uses its own service account (Vertex AI + Firestore via IAM) | Not reused |
| Cloudflare Pages / Tunnel | Not used | Not touched |

Both scripts refuse to run unless the project id starts with `pandashield-hackathon-`.

## What gets created (in the new project only)

1. Project `pandashield-hackathon-<suffix>`, labelled `app=pandashield-hackathon`, linked to the billing account you choose.
2. APIs: Cloud Run, Cloud Build, Artifact Registry, Firestore, Vertex AI, Firebase, Identity Toolkit, Logging.
3. Firestore Native database in `asia-south1` (Mumbai), with `firebase/firestore.rules` deployed (owner read-only; all writes via the API).
4. Service account `pandashield-run` with only `roles/datastore.user`, `roles/aiplatform.user`, `roles/logging.logWriter`.
5. Firebase web app + Google sign-in provider (one console click), Cloud Run URL added to authorised domains.
6. Cloud Run service `pandashield-hackathon` in `asia-south1`: public (`--allow-unauthenticated`, the app enforces Firebase Auth on every API route), min instances 0, max instances 3, 1 vCPU / 1 GiB, request timeout 180 s.

## Gemini model

`gemini-3.8-flash` (stable on the Gemini API model page, updated September 2026) via Vertex AI, location `global`, thinking level `LOW`.
`gemini-2.5-flash` was deliberately **not** used: Google's model lifecycle page lists its retirement as "not before October 16, 2026", which overlaps the judging window (Oct 19 – Nov 6).
The in-app **System status** page sends a live prompt to confirm the model works in the deployed project; if 3.8 Flash is not enabled for the project, `GEMINI_MODEL` can be changed without a code change.

## Estimated cost (USD)

| Service | Expected usage during the hackathon | Estimate |
|---|---|---|
| Cloud Run | A few thousand requests; scale to zero | **$0** (free tier: 2M requests, 180k vCPU-s, 360k GiB-s per month) |
| Firestore | ~30 document writes per scan, small reads | **$0** (within the free daily quota) |
| Gemini 3.8 Flash on Vertex AI | ~$0.06 per scan (≈15k input + 12k output/thinking tokens at the $0.75 / $3.75 per 1M introductory rate), ~$0.01 per follow-up question | **~$5–15** for 100–200 scans |
| Cloud Build + Artifact Registry | A handful of builds, one ~250 MB image | **~$0–1** |
| **Total** | | **≈ $5–20** |

Prices are from Google's Cloud Run pricing page and third-party listings of Vertex AI Gemini 3.8 Flash pricing; confirm on the Vertex AI pricing page before approving.
Cost controls: per-user limits of 20 scans and 60 questions per hour, at most 30 findings sent to Gemini per scan, max 3 Cloud Run instances, and a **$20 budget alert** on the new project (recommended).
No domains, subscriptions or paid third-party services are needed.

## Commands (run after approval)

```bash
# 1. One-time project setup (asks you to re-type the project id)
PROJECT_ID=pandashield-hackathon-<suffix> BILLING_ACCOUNT=<id> ./deployment/setup-project.sh
# 2. Enable Google sign-in in Firebase console, then get the web config
firebase apps:sdkconfig web --project pandashield-hackathon-<suffix>
# 3. Deploy
PROJECT_ID=... FIREBASE_WEB_API_KEY=... FIREBASE_APP_ID=... ./deployment/deploy.sh
# 4. Add the run.app domain to Firebase Auth authorised domains, then verify
PROJECT_ID=... ./deployment/verify.sh https://pandashield-hackathon-xxxx.asia-south1.run.app
```

Then sign in on the deployed site and open **System status** to confirm Firebase Auth, Firestore write/read and a live Gemini response.

## Rollback

`gcloud run services delete pandashield-hackathon --region asia-south1 --project <id>` removes the service; `gcloud projects delete <id>` removes everything created for the hackathon. Neither affects the existing product.
