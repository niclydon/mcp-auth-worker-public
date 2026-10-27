# mcp-auth-worker

> **Public edition.** This is the canonical public edition of a production
> Cloudflare Worker: the single OAuth 2.1 authorization server for a fleet of
> MCP resource-server Workers. It is a snapshot of the private source (see
> SNAPSHOT.md for provenance and the scrub standard), published so the pattern
> can be read, forked, and adapted. Configuration values are placeholders:
> hostnames are example.com, account and KV identifiers are yours to supply,
> and the one operator identity the code checks for is operator@example.com.
> The nine production resource-server Workers that validate against this
> issuer are separate, near-identical variants; this authorization server is
> the shared piece worth publishing once.

The **single consolidated OAuth 2.1 Authorization Server** for the MCP fleet.
Issuer: `https://mcp-auth.example.com`.

## What it is

Before this, each of the 11 `*-mcp.example.com` Workers was its own OAuth issuer with
its own per-Worker `OAUTH_KV`. This Worker replaces all of them as the **sole issuer**.
Each Resource-Server (RS) Worker now:

1. advertises `mcp-auth` as its authorization server in
   `/.well-known/oauth-protected-resource` (`authorization_servers`), and
2. validates the opaque bearer credentials this issuer mints by **binding the same
   shared `OAUTH_KV` namespace** (`mcp-auth-shared-OAUTH_KV`,
   id `YOUR_OAUTH_KV_NAMESPACE_ID`).

The `@cloudflare/workers-oauth-provider` internal-validation path hashes the presented
credential (`SHA-256`) and reads the matching grant entry straight out of KV. The
per-credential encryption key is derived from the credential itself via a **library
constant** (`WRAPPING_KEY_HMAC_KEY`) — there is **no per-Worker signing key**. So an RS
that shares the KV validates this issuer's credentials with the stock provider; it does
**not** need `resolveExternalToken`.

## Login = Cloudflare Access identity or operator password

`/authorize` trusts the `Cf-Access-Authenticated-User-Email` header the Access edge
injects, locks it to `operator@example.com`, and auto-completes the grant. There is no
Cloudflare password in this path. A request that reaches `/authorize` without that
header falls back to the first-party operator password gate, backed by the
`LOGIN_PASSWORD` and `SESSION_SECRET` Worker secrets. The password recovery record lives in the
operator's own secret store, outside this repo. For headless/browser-only
connect flows, the same field accepts one-time operator codes stored in `OAUTH_KV`
under `operator_code:*` with a short TTL; successful use deletes the code.

`Cf-Access-Jwt-Assertion` (the signed application token) is recorded in grant metadata
for defense in depth, but the email header is what authenticates — it is unforgeable on
an Access-protected hostname because the edge strips any inbound copy.

## Edge topology

| Path | Access app | Effect |
|---|---|---|
| `mcp-auth.example.com/authorize` | **identity** (allow, email=operator@example.com) | browser CF Access challenge |
| `mcp-auth.example.com/*` (rest) | **bypass** (everyone) | `/token`, `/register`, `/.well-known/*` reachable by clients/Workers |

Cloudflare matches the more-specific `/authorize` app first.

## Deploy

```bash
./scripts/deploy.sh
```

No Worker secrets to push — the only binding is the shared KV.

### Manual GitHub Actions deploy

The `deploy` workflow is deliberately `workflow_dispatch` only. A push to the
default branch never deploys the fleet authorization server automatically.

Before the first manual run, copy your existing Workers Scripts edit token
from your secret store into the repository secret. Do not mint a second token
and do not print the value:

```bash
# $TOKEN holds your Cloudflare API token, read from your secret store
printf '%s' "$TOKEN" | gh secret set CLOUDFLARE_API_TOKEN --repo OWNER/mcp-auth-worker --body -
```

Confirm only the secret name and timestamp:

```bash
gh secret list --repo OWNER/mcp-auth-worker
```

The GitHub secret authenticates the deploy job; it is not a Worker runtime
secret. The workflow stamps the source commit and deployment time, then checks
`mcp-auth.example.com/health` and `resource.example.com/health` before it can
finish successfully. `./scripts/deploy.sh` remains the canonical
fallback deployment path.
