# Snapshot and provenance

This repository is the canonical **public edition** of a private production
Worker: the single consolidated OAuth 2.1 authorization server for a fleet
of MCP (Model Context Protocol) resource-server Workers fronted by
Cloudflare.

- Source: the private `mcp-auth-worker` repository, HEAD of October 2026.
- Form: a single-commit snapshot of that tree, scrubbed as described below.
  It is not a mirror and does not track the private repo; the private system
  has moved on since the snapshot date.
- Why one edition: the fleet runs nine near-identical resource-server
  Workers that all validate tokens against this one issuer. The
  authorization server is the shared, reusable piece, so it is the one
  published; the resource-server variants are configuration, not new code.

## Scrub standard

Applied to every file before publication, and verified by pattern scans
plus a gitleaks pass over the tree:

- Real hostnames replaced with example.com equivalents
  (`mcp-auth.example.com`, `resource.example.com`).
- The operator identity the code authorizes replaced with
  `operator@example.com`.
- Cloudflare account ID and KV namespace ID replaced with placeholders in
  `wrangler.toml` and the README.
- Personal secret-store wiring (vault paths, CLI profiles, secret IDs)
  generalized to "your secret store"; no token values ever appear.
- Internal ticket references removed from the narrative doc.

No secrets, tokens, or personal data were present in the source tree
(gitleaks clean before and after the scrub).

## Refresh policy

This edition is refreshed deliberately, not continuously: when the
pattern changes materially, a new snapshot is cut with the same scrub and
this page is updated with the new snapshot date.
