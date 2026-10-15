#!/usr/bin/env bash
# Post-deployment checks that need no credentials. The authenticated checks
# (Auth, Firestore, Gemini) are on the in-app "System status" page.
set -euo pipefail
URL="${1:?Usage: verify.sh https://SERVICE-URL}"
PROJECT_ID="${PROJECT_ID:-}"
fail=0
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

check "health endpoint returns ok"            "curl -sf $URL/health | grep -q '\"status\":\"ok\"'"
check "frontend is served"                    "curl -sf $URL/ | grep -q 'PandaShield AI'"
check "public config has Firebase settings"   "curl -sf $URL/api/config | grep -q '\"apiKey\":\"[^\"]'"
check "API rejects anonymous requests (401)"  "[ \"\$(curl -s -o /dev/null -w '%{http_code}' $URL/api/scans)\" = 401 ]"
check "API rejects forged tokens (401)"       "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer forged' $URL/api/scans)\" = 401 ]"
check "security headers present"              "curl -sI $URL/ | grep -qi 'content-security-policy'"
if [ -n "$PROJECT_ID" ]; then
  echo "--- latest revision and recent logs ---"
  gcloud run services describe pandashield-hackathon --project "$PROJECT_ID" --region "${REGION:-asia-south1}" --format='value(status.latestReadyRevisionName)'
  gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=pandashield-hackathon" --project "$PROJECT_ID" --limit 10 --format='value(timestamp,jsonPayload.message,severity)'
fi
exit $fail
