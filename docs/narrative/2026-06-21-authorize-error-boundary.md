# 2026-06-21 Authorize Error Boundary

A hardening pass reworked the consolidated MCP authorization server's `/authorize` path so stale or unknown OAuth client IDs return controlled OAuth errors instead of escaping as Cloudflare Worker exceptions.

The handler now translates parse/lookup/authorization failures into no-store JSON `400` responses unless a parsed request has a redirect URI already registered to the client, in which case it redirects back with OAuth error parameters and preserves `state`. Unknown clients are short-circuited before `completeAuthorization`, so the provider library never gets a chance to throw the 1101-producing path for stale DCR records.

The success path is still the same Cloudflare Access identity check, RFC 8707 resource requirement, shared `OAUTH_KV` client lookup, and `completeAuthorization` call. The test harness covers parse-time unknown clients, lookup-time unknown clients, missing resource indicators, provider completion failures, and the normal redirect flow.
