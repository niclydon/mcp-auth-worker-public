import type { Env } from "./authorize";

/**
 * OB-55555: /health used to report only { status, service, role } — no version, no
 * sha — so a deployed Worker could not be told apart from any other build of
 * itself, and drift was undefinable. mcp-auth-worker is the canonical
 * authorization server whose /health literal every RS Worker copied, so this is
 * the template the fleet follows, not a one-off.
 *
 * Additive only: existing keys keep their exact values and old clients ignore the
 * new ones. An absent var reports the string "unknown" rather than being omitted
 * or undefined, so an un-stamped deploy is VISIBLY un-stamped instead of looking
 * like a field that was never added.
 */
export function healthBody(env: Pick<Env, "GIT_COMMIT" | "DEPLOYED_AT">): {
  status: string;
  service: string;
  role: string;
  git_commit: string;
  deployed_at: string;
} {
  return {
    status: "ok",
    service: "mcp-auth-worker",
    role: "authorization-server",
    git_commit: env.GIT_COMMIT || "unknown",
    deployed_at: env.DEPLOYED_AT || "unknown",
  };
}
