# Changes

## 2026-09-08

- Added a manual-only GitHub Actions deployment workflow for the fleet OAuth
  authorization server. It runs tests and type checks, deploys with source
  provenance, and verifies both the authorization server and Nexus resource
  server health endpoints.
- Kept deployment behind `workflow_dispatch`; pushes to the default branch do
  not deploy this high-blast authentication surface.
- Reused the existing shared Cloudflare deploy credential for the
  repository secret. No Cloudflare token was minted, rotated, or committed.

Runner-Attribution: codex
