#!/usr/bin/env bash
# One-time setup of a NEW, ISOLATED Google Cloud + Firebase project for the
# PandaShield AI Hackathon Edition. Run only after the deployment plan has
# been approved. It never touches any existing PandaShield resources.
#
# Usage: PROJECT_ID=pandashield-hackathon-xxxx BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX ./deployment/setup-project.sh
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID (must start with pandashield-hackathon-)}"
: "${BILLING_ACCOUNT:?Set BILLING_ACCOUNT (the billing account ID to link)}"
REGION="${REGION:-asia-south1}"
FIRESTORE_LOCATION="${FIRESTORE_LOCATION:-asia-south1}"
SA_NAME="pandashield-run"
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if [[ "$PROJECT_ID" != pandashield-hackathon-* ]]; then
  echo "Refusing: PROJECT_ID must start with 'pandashield-hackathon-' so it can never be the existing product's project." >&2
  exit 1
fi

echo "About to create/configure project: $PROJECT_ID (region $REGION)"
read -r -p "Type the project id again to continue: " confirm
[[ "$confirm" == "$PROJECT_ID" ]] || { echo "Aborted."; exit 1; }

if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud projects create "$PROJECT_ID" --name="PandaShield Hackathon" --labels=app=pandashield-hackathon,purpose=hackathon
fi
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"

gcloud services enable --project "$PROJECT_ID" \
  run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  firestore.googleapis.com aiplatform.googleapis.com firebase.googleapis.com \
  identitytoolkit.googleapis.com logging.googleapis.com

# Firestore (Native mode), separate database for this project only.
if ! gcloud firestore databases describe --project "$PROJECT_ID" --database='(default)' >/dev/null 2>&1; then
  gcloud firestore databases create --project "$PROJECT_ID" --location="$FIRESTORE_LOCATION" --type=firestore-native
fi

# Least-privilege runtime service account for Cloud Run.
if ! gcloud iam service-accounts describe "$SA" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT_ID" --display-name="PandaShield Hackathon Cloud Run"
fi
for role in roles/datastore.user roles/aiplatform.user roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA" --role="$role" --condition=None >/dev/null
done

# Firebase: attach to the project, create the web app, deploy Firestore rules.
firebase projects:addfirebase "$PROJECT_ID" || true
firebase apps:create web "PandaShield Hackathon Web" --project "$PROJECT_ID" || true
(cd "$(dirname "$0")/../firebase" && firebase deploy --only firestore:rules,firestore:indexes --project "$PROJECT_ID")

cat <<MSG

Project ready. Remaining console steps (Firebase console > Authentication):
  1. Get started > Sign-in method > enable Google.
  2. Settings > Authorized domains: add the Cloud Run URL after the first deploy.
Then print the web config with:
  firebase apps:sdkconfig web --project $PROJECT_ID
and pass apiKey / appId to deployment/deploy.sh.
MSG
