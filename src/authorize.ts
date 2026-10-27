import type { AuthRequest, ClientInfo, OAuthHelpers } from "@cloudflare/workers-oauth-provider";

// The only identity allowed to obtain tokens from this issuer.
export const ALLOWED_EMAIL = "operator@example.com";

// Cloudflare Access forwarded-identity headers (developers.cloudflare.com):
//   Cf-Access-Authenticated-User-Email — authenticated user's email
//   Cf-Access-Jwt-Assertion           — signed application token (defense in depth)
export const ACCESS_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email";
export const ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  LOGIN_PASSWORD?: string;
  SESSION_SECRET?: string;
  // Set to "1" only for `wrangler dev`, where the CF Access edge is absent and the
  // identity header must be supplied by the caller (the local-flow proof curls it).
  ALLOW_DEV_ACCESS_HEADER?: string;
  // OB-55555: build-time provenance, injected by scripts/deploy.sh via
  // `wrangler deploy --var`. Deliberately NOT literals in wrangler.toml — a
  // hardcoded sha would be a lie the moment anything else deployed, which is the
  // exact failure this exists to fix. Optional because `wrangler dev` sets
  // neither, and /health reports "unknown" rather than undefined so an
  // un-stamped deploy is visibly un-stamped.
  GIT_COMMIT?: string;
  DEPLOYED_AT?: string;
}

// /authorize: trust the CF Access identity injected by the edge, lock to the single
// allowed operator, and auto-complete the OAuth grant. If Cloudflare Access is bypassed,
// fall back to a first-party single-operator password session.
export async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const email = request.headers.get(ACCESS_EMAIL_HEADER);
  const jwt = request.headers.get(ACCESS_JWT_HEADER);

  // The email header is injected by Cloudflare Access ONLY on a request that passed
  // the Access challenge; a client cannot forge it on an Access-protected hostname
  // (the edge strips inbound copies). If it's absent we are NOT behind Access for
  // this request — reject, except under explicit local-dev override.
  const devOverride = env.ALLOW_DEV_ACCESS_HEADER === "1";
  if (!email) {
    if (!devOverride) {
      return handlePasswordAuthorize(request, env);
    }
    return new Response("Forbidden: dev override on but no Access email header supplied.", {
      status: 403,
    });
  }

  if (email.toLowerCase() !== ALLOWED_EMAIL.toLowerCase()) {
    return new Response(`Forbidden: ${escapeHtml(email)} is not authorized.`, { status: 403 });
  }

  return completeAuthorizedRequest(request, env, {
    email,
    via: "cf-access",
    jwtPresent: Boolean(jwt),
  });
}

async function handlePasswordAuthorize(request: Request, env: Env): Promise<Response> {
  if (!env.LOGIN_PASSWORD || !env.SESSION_SECRET) {
    return new Response("Forbidden: no Cloudflare Access identity present.", { status: 403 });
  }

  const sessionEmail = await readSessionEmail(request, env);
  if (sessionEmail === ALLOWED_EMAIL) {
    return completeAuthorizedRequest(request, env, {
      email: ALLOWED_EMAIL,
      via: "password-session",
      jwtPresent: false,
    });
  }

  if (request.method === "POST") {
    const form = await request.formData();
    const password = String(form.get("password") ?? "");
    if (
      (await secretsMatch(password, env.LOGIN_PASSWORD, env.SESSION_SECRET)) ||
      (await consumeOneTimeCode(password, env))
    ) {
      const response = await completeAuthorizedRequest(request, env, {
        email: ALLOWED_EMAIL,
        via: "password",
        jwtPresent: false,
      });
      return appendSetCookie(response, await buildSessionCookie(env));
    }
    return renderPasswordForm(request, "Invalid password.", 401);
  }

  return renderPasswordForm(request);
}

async function completeAuthorizedRequest(
  request: Request,
  env: Env,
  auth: { email: string; via: string; jwtPresent: boolean },
): Promise<Response> {
  // Parse the inbound OAuth authorization request and auto-approve it for this user.
  let oauthReq: AuthRequest;
  try {
    oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch (error) {
    return oauthErrorResponse(error);
  }

  // OB-27081 H1: every token MUST be audience-bound. The library only enforces audience
  // when the grant carries a resource (RFC 8707); an authorize request that omits one
  // would mint an UNBOUND token valid against every RS sharing the KV. Reject it so no
  // unbound token can ever exist. Verified safe: 14/14 live grants carry a resource —
  // all real MCP clients (Claude/Codex/Grok/Antigravity) send the indicator.
  if (!oauthReq.resource) {
    return oauthErrorJson(
      "invalid_target",
      "a resource indicator (RFC 8707) is required to obtain a token from this authorization server.",
    );
  }

  let client: ClientInfo | null;
  try {
    client = await env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId);
  } catch (error) {
    return oauthErrorResponse(error);
  }

  if (!client) {
    return oauthErrorJson(
      "invalid_client",
      "unknown or unregistered client_id; re-register (DCR) at /register",
    );
  }

  try {
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReq,
      userId: ALLOWED_EMAIL,
      metadata: {
        client: client.clientName ?? oauthReq.clientId,
        via: auth.via,
        jwtPresent: auth.jwtPresent,
      },
      scope: oauthReq.scope ?? [],
      props: { user: ALLOWED_EMAIL, email: auth.email },
    });

    return Response.redirect(redirectTo, 302);
  } catch (error) {
    const oauthError = classifyOAuthError(error);
    const registeredRedirectUri = isRegisteredRedirectUri(oauthReq.redirectUri, client);
    if (registeredRedirectUri) {
      return redirectWithOAuthError(oauthReq, oauthError);
    }
    return oauthErrorJson(oauthError.error, oauthError.description);
  }
}

const SESSION_COOKIE = "mcp_auth_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24;

function appendSetCookie(response: Response, cookie: string): Response {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function buildSessionCookie(env: Env): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payload = base64UrlEncode(JSON.stringify({ email: ALLOWED_EMAIL, exp }));
  const sig = await hmacHex(payload, env.SESSION_SECRET!);
  return `${SESSION_COOKIE}=${payload}.${sig}; Max-Age=${SESSION_TTL_SECONDS}; Path=/authorize; HttpOnly; Secure; SameSite=Lax`;
}

async function readSessionEmail(request: Request, env: Env): Promise<string | null> {
  const raw = parseCookie(request.headers.get("Cookie") ?? "")[SESSION_COOKIE];
  if (!raw) return null;
  const [payload, sig] = raw.split(".");
  if (!payload || !sig) return null;
  const expected = await hmacHex(payload, env.SESSION_SECRET!);
  if (!constantTimeEqual(sig, expected)) return null;

  try {
    const decoded = JSON.parse(base64UrlDecode(payload)) as { email?: string; exp?: number };
    if (decoded.exp === undefined || decoded.exp < Math.floor(Date.now() / 1000)) return null;
    return decoded.email ?? null;
  } catch {
    return null;
  }
}

function parseCookie(header: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of header.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (!name || valueParts.length === 0) continue;
    result[name] = valueParts.join("=");
  }
  return result;
}

async function secretsMatch(input: string, expected: string, secret: string): Promise<boolean> {
  const [a, b] = await Promise.all([hmacHex(input, secret), hmacHex(expected, secret)]);
  return constantTimeEqual(a, b);
}

async function consumeOneTimeCode(input: string, env: Env): Promise<boolean> {
  const code = input.trim();
  if (!code || !env.SESSION_SECRET || typeof env.OAUTH_KV.get !== "function") return false;
  const key = await operatorCodeKey(code, env.SESSION_SECRET);
  const record = await env.OAUTH_KV.get(key);
  if (!record) return false;
  await env.OAUTH_KV.delete(key);
  return true;
}

export async function operatorCodeKey(code: string, secret: string): Promise<string> {
  return `operator_code:${await hmacHex(`operator-code:${code.trim()}`, secret)}`;
}

async function hmacHex(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

function renderPasswordForm(request: Request, error = "", status = 200): Response {
  const url = new URL(request.url);
  const action = `${url.pathname}${url.search}`;
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect MCP</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b0d10; color: #f4f6f8; }
    main { width: min(420px, calc(100vw - 32px)); }
    label, input, button { display: block; width: 100%; box-sizing: border-box; }
    label { font-weight: 650; margin-bottom: 8px; }
    input { border: 1px solid #3b4654; border-radius: 8px; padding: 12px; background: #11161d; color: #f4f6f8; font-size: 16px; }
    button { margin-top: 12px; border: 0; border-radius: 8px; padding: 12px; background: #2d7ff9; color: white; font-weight: 700; font-size: 16px; }
    p { color: #aab4c0; line-height: 1.4; }
    .error { color: #ff9b9b; }
  </style>
</head>
<body>
  <main>
    <h1>Connect MCP</h1>
    <p>Enter the operator password or a one-time code to continue connecting this MCP server.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="post" action="${escapeHtml(action)}">
      <label for="password">Password or one-time code</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Continue</button>
    </form>
  </main>
</body>
</html>`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    },
  );
}

function oauthErrorResponse(error: unknown): Response {
  const oauthError = classifyOAuthError(error);
  return oauthErrorJson(oauthError.error, oauthError.description);
}

function oauthErrorJson(error: string, errorDescription: string): Response {
  return Response.json(
    {
      error,
      error_description: errorDescription,
    },
    {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    },
  );
}

function redirectWithOAuthError(
  oauthReq: Pick<AuthRequest, "redirectUri" | "state">,
  oauthError: { error: string; description: string },
): Response {
  const redirectUrl = new URL(oauthReq.redirectUri);
  redirectUrl.searchParams.set("error", oauthError.error);
  redirectUrl.searchParams.set("error_description", oauthError.description);
  if (oauthReq.state) redirectUrl.searchParams.set("state", oauthReq.state);
  return Response.redirect(redirectUrl.toString(), 302);
}

function classifyOAuthError(error: unknown): { error: string; description: string } {
  const message = error instanceof Error ? error.message : String(error);
  const lower = message.toLowerCase();
  if (lower.includes("invalid client") || lower.includes("clientid")) {
    return {
      error: "invalid_client",
      description: "unknown or unregistered client_id; re-register (DCR) at /register",
    };
  }
  if (lower.includes("resource parameter") || lower.includes("resource indicator")) {
    return {
      error: "invalid_target",
      description: "the resource parameter must be a valid absolute URI without a fragment",
    };
  }
  return {
    error: "invalid_request",
    description: "authorization request could not be completed; verify client registration and redirect_uri",
  };
}

function isRegisteredRedirectUri(redirectUri: string, client: ClientInfo): boolean {
  return Boolean(redirectUri && client.redirectUris?.includes(redirectUri));
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}
