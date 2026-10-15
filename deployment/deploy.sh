#!/usr/bin/env bash
# Builds and deploys the hackathon edition to Cloud Run from source
# (Cloud Build + Artifact Registry). Run only after approval.
#
# Usage: PROJECT_ID=pandashield-hackathon-xxxx FIREBASE_WEB_API_KEY=... FIREBASE_APP_ID=... ./deployment/deploy.sh
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${FIREBASE_WEB_API_KEY:?Set FIREBASE_WEB_API_KEY (public Firebase web API key)}"
: "${FIREBASE_APP_ID:?Set FIREBASE_APP_ID}"
REGION="${REGION:-asia-south1}"
SERVICE="${SERVICE:-pandashield-hackathon}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.8-flash}"
SA="pandashield-run@${PROJECT_ID}.iam.gserviceaccount.com"

if [[ "$PROJECT_ID" != pandashield-hackathon-* ]]; then
  echo "Refusing: PROJECT_ID must start with 'pandashield-hackathon-'." >&2
  exit 1
fi

cd "$(dirname "$0")/.."
gcloud run deploy "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --source . \
  --service-account "$SA" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 3 \
  --concurrency 40 \
  --cpu 1 \
  --memory 1Gi \
  --timeout 180 \
  --labels app=pandashield-hackathon \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},FIREBASE_PROJECT_ID=${PROJECT_ID},FIREBASE_AUTH_DOMAIN=${PROJECT_ID}.firebaseapp.com,FIREBASE_WEB_API_KEY=${FIREBASE_WEB_API_KEY},FIREBASE_APP_ID=${FIREBASE_APP_ID},GEMINI_USE_VERTEX=true,GEMINI_LOCATION=global,GEMINI_MODEL=${GEMINI_MODEL}"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
echo "Deployed: $URL"
echo "Next: add $(echo "$URL" | sed 's#https://##') to Firebase Authentication > Settings > Authorized domains, then run deployment/verify.sh"
