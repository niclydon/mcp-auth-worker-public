import assert from "node:assert/strict";
import { healthBody } from "../src/health.ts";

// OB-55555: /health reported only { status, service, role } — no version, no sha —
// so a deployed Worker could not be distinguished from any other build of itself
// and drift was undefinable. mcp-auth-worker is the canonical authorization server
// whose /health literal every RS Worker copied, so this shape is the fleet
// template.

// The stamped case: what a real deploy produces.
{
  const body = healthBody({
    GIT_COMMIT: "5c575770f1e2a3b4c5d6e7f80912a3b4c5d6e7f8",
    DEPLOYED_AT: "2026-08-22T19:40:00Z",
  });
  assert.equal(body.git_commit, "5c575770f1e2a3b4c5d6e7f80912a3b4c5d6e7f8");
  assert.equal(body.deployed_at, "2026-08-22T19:40:00Z");
}

// The un-stamped case. This is the load-bearing one: an absent var must report
// the STRING "unknown", never undefined. `Response.json` drops undefined keys, so
// an un-stamped deploy would look identical to a Worker built before the field
// existed — silently indistinguishable, which is the bug.
{
  const body = healthBody({});
  assert.equal(body.git_commit, "unknown");
  assert.equal(body.deployed_at, "unknown");
  assert.ok(Object.hasOwn(body, "git_commit"), "git_commit key must be present even when unset");
  assert.ok(Object.hasOwn(body, "deployed_at"), "deployed_at key must be present even when unset");
  assert.equal(JSON.parse(JSON.stringify(body)).git_commit, "unknown", "must survive JSON serialisation");
}

// An empty-string var is as un-stamped as an absent one.
{
  const body = healthBody({ GIT_COMMIT: "", DEPLOYED_AT: "" });
  assert.equal(body.git_commit, "unknown");
  assert.equal(body.deployed_at, "unknown");
}

// Additive only: the three pre-existing keys keep their exact values, because RS
// workers and any monitor copied this literal.
{
  const body = healthBody({});
  assert.equal(body.status, "ok");
  assert.equal(body.service, "mcp-auth-worker");
  assert.equal(body.role, "authorization-server");
  assert.deepEqual(
    Object.keys(body).sort(),
    ["deployed_at", "git_commit", "role", "service", "status"],
    "unexpected /health shape change",
  );
}

console.log("health tests passed");
