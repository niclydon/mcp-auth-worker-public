import assert from "node:assert/strict";
import { handleAuthorize, ACCESS_EMAIL_HEADER, operatorCodeKey, type Env } from "../src/authorize.ts";

type MockOAuthProvider = Env["OAUTH_PROVIDER"];

const baseAuthRequest = {
  responseType: "code",
  clientId: "client-1",
  redirectUri: "https://client.example/callback",
  scope: ["mcp"],
  state: "state-123",
  codeChallenge: "challenge",
  codeChallengeMethod: "S256",
  resource: "https://resource.example.com",
};

function request(url = "https://mcp-auth.example.com/authorize") {
  return new Request(url, {
    headers: {
      [ACCESS_EMAIL_HEADER]: "operator@example.com",
    },
  });
}

function passwordRequest(
  url = "https://mcp-auth.example.com/authorize",
  init: RequestInit = {},
) {
  return new Request(url, init);
}

function env(overrides: Partial<MockOAuthProvider>, envOverrides: Partial<Env> = {}): Env {
  const oauthProvider = {
    parseAuthRequest: async () => baseAuthRequest,
    lookupClient: async () => ({
      clientId: "client-1",
      redirectUris: ["https://client.example/callback"],
      clientName: "Test Client",
    }),
    completeAuthorization: async () => ({
      redirectTo: "https://client.example/callback?code=abc&state=state-123",
    }),
    ...overrides,
  } as MockOAuthProvider;

  return {
    OAUTH_KV: {} as KVNamespace,
    OAUTH_PROVIDER: oauthProvider,
    ...envOverrides,
  };
}

async function json(response: Response) {
  return response.json() as Promise<{ error: string; error_description: string }>;
}

{
  let completeCalled = false;
  const response = await handleAuthorize(
    request(),
    env({
      parseAuthRequest: async () => {
        throw new Error("Invalid client. The clientId provided does not match to this client.");
      },
      completeAuthorization: async () => {
        completeCalled = true;
        return { redirectTo: "https://client.example/callback?code=abc" };
      },
    }),
  );

  assert.equal(response.status, 400);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(await json(response), {
    error: "invalid_client",
    error_description: "unknown or unregistered client_id; re-register (DCR) at /register",
  });
  assert.equal(completeCalled, false);
}

{
  let completeCalled = false;
  const response = await handleAuthorize(
    request(),
    env({
      lookupClient: async () => null,
      completeAuthorization: async () => {
        completeCalled = true;
        return { redirectTo: "https://client.example/callback?code=abc" };
      },
    }),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await json(response), {
    error: "invalid_client",
    error_description: "unknown or unregistered client_id; re-register (DCR) at /register",
  });
  assert.equal(completeCalled, false);
}

{
  let completeCalled = false;
  const response = await handleAuthorize(
    request(),
    env({
      lookupClient: async () => {
        throw new Error("KV lookup failed while loading the OAuth client");
      },
      completeAuthorization: async () => {
        completeCalled = true;
        return { redirectTo: "https://client.example/callback?code=abc" };
      },
    }),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await json(response), {
    error: "invalid_request",
    error_description: "authorization request could not be completed; verify client registration and redirect_uri",
  });
  assert.equal(completeCalled, false);
}

{
  const response = await handleAuthorize(
    request(),
    env({
      parseAuthRequest: async () => ({ ...baseAuthRequest, resource: undefined }),
    }),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await json(response), {
    error: "invalid_target",
    error_description:
      "a resource indicator (RFC 8707) is required to obtain a token from this authorization server.",
  });
}

{
  const response = await handleAuthorize(
    request(),
    env({
      completeAuthorization: async () => {
        throw new Error("Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.");
      },
    }),
  );

  assert.equal(response.status, 302);
  const location = new URL(response.headers.get("Location") ?? "");
  assert.equal(location.origin + location.pathname, "https://client.example/callback");
  assert.equal(location.searchParams.get("error"), "invalid_request");
  assert.equal(
    location.searchParams.get("error_description"),
    "authorization request could not be completed; verify client registration and redirect_uri",
  );
  assert.equal(location.searchParams.get("state"), "state-123");
}

{
  const response = await handleAuthorize(request(), env({}));
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://client.example/callback?code=abc&state=state-123");
}

{
  let completeCalled = false;
  const response = await handleAuthorize(
    passwordRequest(),
    env(
      {
        completeAuthorization: async () => {
          completeCalled = true;
          return { redirectTo: "https://client.example/callback?code=abc" };
        },
      },
      { LOGIN_PASSWORD: "correct horse", SESSION_SECRET: "session-secret" },
    ),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Type"), "text/html; charset=utf-8");
  assert.match(await response.text(), /Connect MCP/);
  assert.equal(completeCalled, false);
}

{
  let completeCalled = false;
  const response = await handleAuthorize(
    passwordRequest("https://mcp-auth.example.com/authorize?client_id=client-1", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: "wrong" }),
    }),
    env(
      {
        completeAuthorization: async () => {
          completeCalled = true;
          return { redirectTo: "https://client.example/callback?code=abc" };
        },
      },
      { LOGIN_PASSWORD: "correct horse", SESSION_SECRET: "session-secret" },
    ),
  );

  assert.equal(response.status, 401);
  assert.match(await response.text(), /Invalid password/);
  assert.equal(completeCalled, false);
}

{
  const response = await handleAuthorize(
    passwordRequest("https://mcp-auth.example.com/authorize?client_id=client-1", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: "correct horse" }),
    }),
    env({}, { LOGIN_PASSWORD: "correct horse", SESSION_SECRET: "session-secret" }),
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://client.example/callback?code=abc&state=state-123");
  assert.match(response.headers.get("Set-Cookie") ?? "", /mcp_auth_session=/);
}

{
  const first = await handleAuthorize(
    passwordRequest("https://mcp-auth.example.com/authorize?client_id=client-1", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: "correct horse" }),
    }),
    env({}, { LOGIN_PASSWORD: "correct horse", SESSION_SECRET: "session-secret" }),
  );
  const cookie = first.headers.get("Set-Cookie")?.split(";")[0] ?? "";
  let completedViaSession = false;
  const second = await handleAuthorize(
    passwordRequest("https://mcp-auth.example.com/authorize?client_id=client-1", {
      headers: { Cookie: cookie },
    }),
    env(
      {
        completeAuthorization: async () => {
          completedViaSession = true;
          return { redirectTo: "https://client.example/callback?code=session" };
        },
      },
      { LOGIN_PASSWORD: "correct horse", SESSION_SECRET: "session-secret" },
    ),
  );

  assert.equal(second.status, 302);
  assert.equal(second.headers.get("Location"), "https://client.example/callback?code=session");
  assert.equal(completedViaSession, true);
}

{
  const code = "ABC123";
  const key = await operatorCodeKey(code, "session-secret");
  let deletedKey = "";
  const response = await handleAuthorize(
    passwordRequest("https://mcp-auth.example.com/authorize?client_id=client-1", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: code }),
    }),
    env(
      {},
      {
        LOGIN_PASSWORD: "not-this",
        SESSION_SECRET: "session-secret",
        OAUTH_KV: {
          get: async (name: string) => (name === key ? "1" : null),
          delete: async (name: string) => {
            deletedKey = name;
          },
        } as unknown as KVNamespace,
      },
    ),
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://client.example/callback?code=abc&state=state-123");
  assert.equal(deletedKey, key);
}

console.log("authorize tests passed");
