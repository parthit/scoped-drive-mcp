import { describe, expect, test } from "vitest";
import { createApp } from "../src/app.js";
import { Accounts } from "../src/accounts.js";
import { Bridge } from "../src/bridge.js";
import { MemoryStore } from "../src/store/memory.js";
import type { OAuthProfile } from "../src/oauth.js";

const BASE = "http://bridge.test";
const SECRET = "test-session-secret";

function profile(provider: OAuthProfile["provider"], id: string, label: string): OAuthProfile {
  return { provider, providerUserId: id, label };
}

describe("accounts", () => {
  test("register refuses to mint a user, and one account can own two bots", async () => {
    const store = new MemoryStore();
    const accounts = new Accounts(store);
    const bridge = new Bridge(store);
    const missing = await bridge.register({ displayName: "Alex" }, BASE);
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toBe("account_required");

    const first = await accounts.completeLogin(profile("google", "sub-a", "ada@example.com"), null);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const secondBotOwner = first.data.user_id;
    const alex = await bridge.register({ displayName: "Alex", userId: secondBotOwner }, BASE);
    const blair = await bridge.register({ displayName: "Blair", userId: secondBotOwner }, BASE);
    expect(alex.ok && blair.ok).toBe(true);
    if (!alex.ok || !blair.ok) return;
    expect(alex.data.bot_id).not.toBe(blair.data.bot_id);
    expect(alex.data.user_id).toBe(secondBotOwner);
    expect(blair.data.user_id).toBe(secondBotOwner);
    const bots = await store.listBotsForUser(secondBotOwner);
    expect(bots).toHaveLength(2);
  });

  test("a second login provider links only for the signed-in account", async () => {
    const accounts = new Accounts(new MemoryStore());
    const google = await accounts.completeLogin(profile("google", "sub-a", "ada@example.com"), null);
    expect(google.ok).toBe(true);
    if (!google.ok) return;
    const github = await accounts.completeLogin(profile("github", "99", "ada"), google.data.user_id);
    expect(github.ok).toBe(true);
    if (!github.ok) expect(github.ok).toBe(true);
    if (github.ok) expect(github.data.user_id).toBe(google.data.user_id);

    const other = await accounts.completeLogin(profile("x", "x-1", "ada@example.com"), null);
    expect(other.ok).toBe(true);
    if (!other.ok) return;
    expect(other.data.user_id).not.toBe(google.data.user_id);

    const stolen = await accounts.completeLogin(profile("google", "sub-a", "ada@example.com"), other.data.user_id);
    expect(stolen.ok).toBe(false);
    if (!stolen.ok) expect(stolen.error).toBe("identity_taken");
  });
});

describe("login http", () => {
  test("register requires a session created by a provider callback", async () => {
    const seen: string[] = [];
    const server = createApp({
      store: new MemoryStore(),
      baseUrl: BASE,
      sessionSecret: SECRET,
      oauth: {
        google: { clientId: "gid", clientSecret: "gsecret" },
        github: { clientId: "hid", clientSecret: "hsecret" },
        x: { clientId: "xid", clientSecret: "xsecret" },
      },
      fetch: (async (input: RequestInfo | URL) => {
        const url = String(input);
        seen.push(url);
        if (url.includes("googleapis.com/token") || url.includes("github.com/login/oauth/access_token") || url.includes("api.twitter.com/2/oauth2/token")) {
          return Response.json({ access_token: "access-once", token_type: "bearer" });
        }
        if (url.includes("userinfo")) return Response.json({ sub: "sub-a", email: "ada@example.com", name: "Ada" });
        if (url.includes("api.github.com/user")) return Response.json({ id: 99, login: "ada" });
        if (url.includes("api.twitter.com/2/users/me")) return Response.json({ data: { id: "x-1", name: "Ada", username: "ada" } });
        return new Response("missing", { status: 404 });
      }) as typeof fetch,
    });

    const page = await server.request(`${BASE}/register`);
    expect(page.status).toBe(303);
    expect(page.headers.get("location")).toBe("/login");

    const login = await server.request(`${BASE}/login`);
    const html = await login.text();
    expect(html).toContain("Continue with Google");
    expect(html).toContain("Continue with GitHub");
    expect(html).toContain("Continue with X");

    const start = await server.request(`${BASE}/auth/google`);
    expect(start.status).toBe(302);
    const location = new URL(start.headers.get("location") ?? "", "https://accounts.google.com");
    expect(location.searchParams.get("scope")).toContain("openid");
    expect(location.searchParams.get("scope")).not.toContain("drive");
    const state = location.searchParams.get("state");
    const cookie = start.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="));
    expect(state).toBeTruthy();
    expect(cookie).toBeTruthy();

    const callback = await server.request(`${BASE}/auth/google/callback?code=abc&state=${state}`, {
      headers: { cookie: cookie!.split(";")[0]! },
    });
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/");
    const session = callback.headers.getSetCookie().find((item) => item.startsWith("bb_session="));
    expect(session).toBeTruthy();
    expect(seen.join(" ")).not.toContain("access-once");

    const created = await server.request(`${BASE}/register`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", cookie: session!.split(";")[0]! },
      body: JSON.stringify({ display_name: "Alex" }),
    });
    expect(created.status).toBe(201);
    const body = (await created.json()) as { bot_id: string; user_id: string; token: string };
    expect(body.token.startsWith("bb_")).toBe(true);

    const again = await server.request(`${BASE}/register`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", cookie: session!.split(";")[0]! },
      body: JSON.stringify({ display_name: "Blair" }),
    });
    const second = (await again.json()) as { bot_id: string; user_id: string };
    expect(second.user_id).toBe(body.user_id);
    expect(second.bot_id).not.toBe(body.bot_id);

    const home = await server.request(`${BASE}/`, { headers: { cookie: session!.split(";")[0]! } });
    const homeHtml = await home.text();
    expect(homeHtml).toContain("Alex");
    expect(homeHtml).toContain("Blair");
    expect(homeHtml).toContain("Integrations");
  });
});
