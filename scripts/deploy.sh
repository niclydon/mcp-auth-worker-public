#!/usr/bin/env bash
# Deploy mcp-auth-worker — the single consolidated OAuth 2.1 Authorization Server
# for the MCP fleet (issuer https://mcp-auth.example.com).
#
# This Worker needs NO secrets of its own: login is the Cloudflare Access identity
# injected at the edge (Cf-Access-Authenticated-User-Email), and tokens are opaque
# entries in the shared OAUTH_KV namespace — there are no signing keys. The only
# binding is the shared KV (pinned in wrangler.toml).
#
# Edge prerequisites (one-time, done at first provision):
#   - Sentinel DNS A 192.0.2.1 (proxied) for mcp-auth.example.com
#   - CF Access IDENTITY app on path mcp-auth.example.com/authorize
#       policy: allow, email = operator@example.com
#   - CF Access BYPASS app on host mcp-auth.example.com (everyone) so /token,
#       /register, /callback, /.well-known/* are reachable programmatically
#     (Cloudflare matches the more-specific /authorize app first.)

set -euo pipefail
PROJ=$(cd "$(dirname "$0")/.." && pwd)
cd "$PROJ"

export CLOUDFLARE_API_TOKEN=$(aws --profile secrets --region us-east-1 \
  secretsmanager get-secret-value --secret-id shared/cloudflare-workers-edit \
  --query SecretString --output text \
  | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['api_token'])")

# OB-55555: stamp the deployed Worker with its source commit and deploy time so
# /health can report provenance. Passed as build-time vars rather than written
# into wrangler.toml as literals — a hardcoded sha would be a lie the moment
# anything else deployed, which is the failure this exists to fix.
#
# A dirty tree is marked. Reporting a clean sha for a build that included
# uncommitted work is the same lie in a smaller font, and this Worker is the
# fleet's authorization server: "which code is actually running" has to be
# answerable exactly.
GIT_COMMIT="$(git rev-parse HEAD)"
if ! git diff --quiet HEAD -- || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  GIT_COMMIT="${GIT_COMMIT}-dirty"
  echo "[deploy] WARNING: working tree is dirty — stamping ${GIT_COMMIT}"
fi
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[deploy] wrangler deploy (git_commit=${GIT_COMMIT} deployed_at=${DEPLOYED_AT})"
npx wrangler deploy --var "GIT_COMMIT:${GIT_COMMIT}" --var "DEPLOYED_AT:${DEPLOYED_AT}"

echo "[deploy] smoke /health"
sleep 4
curl -s -m 10 https://mcp-auth.example.com/health | python3 -m json.tool

echo "[deploy] smoke discovery"
curl -s -m 10 https://mcp-auth.example.com/.well-known/oauth-authorization-server | python3 -m json.tool
