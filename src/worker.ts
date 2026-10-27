// mcp-auth.example.com — the SINGLE consolidated OAuth 2.1 Authorization Server
// for the MCP fleet.
//
// This Worker is the sole token issuer. Every Resource-Server (RS) Worker in the
// fleet (the fleet’s resource-server Workers) advertises THIS host in its
// /.well-known/oauth-protected-resource (authorization_servers) and validates the
// opaque tokens this issuer mints by binding the SAME shared OAUTH_KV namespace.
// The RS workers stop being issuers; they become validate-only proxies.
//
// Login is NOT a shared password. /authorize trusts the Cloudflare Access identity
// the edge injects (Cf-Access-Authenticated-User-Email) and auto-approves the grant
// for the single allowed operator. The edge CF Access *identity* app on the
// /authorize path is what authenticates the human in the browser; this Worker only
// reads the resulting header. Anyone reaching /authorize WITHOUT that header (i.e.
// not via the Access challenge) is rejected.
//
// There is no MCP API surface on this host. apiRoute is a dead path so the provider
// never proxies anything — it only issues and validates tokens.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { handleAuthorize, type Env } from "./authorize";
import { healthBody } from "./health";

// This issuer fronts no MCP API. apiRoute points at a path nothing ever calls so the
// provider's token-validation/proxy path is inert here. (The provider constructor
// REQUIRES an apiRoute + apiHandler, hence this stub.)
const apiHandler = {
  async fetch(): Promise<Response> {
    return new Response("mcp-auth is an authorization server only; no resource API here.", {
      status: 404,
    });
  },
};

const defaultHandler = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json(healthBody(env));
    }

    if (url.pathname === "/authorize") {
      return handleAuthorize(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

export default new OAuthProvider({
  // No real resource API on the issuer host; this path is never hit by clients.
  apiRoute: "/__noapi",
  apiHandler,
  defaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["mcp"],
  accessTokenTTL: 3600,
  refreshTokenTTL: 60 * 60 * 24 * 30,
});
