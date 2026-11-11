import { createHmac } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import { createApp } from "../src/app.js";
import { Bridge } from "../src/bridge.js";
import type { WebhookFeature } from "../src/limits.js";
import type { WebhookPostInput } from "../src/notify/webhook.js";
import { signWake } from "../src/notify/webhook.js";
import type { Result } from "../src/result.js";
import { MemoryStore } from "../src/store/memory.js";
import { PgStore } from "../src/store/pg-store.js";
import { createPgliteDb, type PgliteDb } from "../src/store/pglite.js";
import type { Store } from "../src/store/types.js";
import type { BotRow } from "../src/types.js";

const BASE = "http://bridge.test";
const DAY = 24 * 60 * 60 * 1000;
const KEK = Buffer.alloc(32, 7);
const SECRET = "sk_live_test_key_99";
const URL = "https://api2.cursor.sh/automations/webhook/super-secret-path";

const feature: WebhookFeature = {
  enabled: true,
  kek: KEK,
  allowlist: ["api2.cursor.sh"],
  maxPerBotPerHour: 60,
  attemptTimeoutMs: 4000,
  maxAttempts: 5,
};

function must<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(`${result.error}: ${result.message}`);
  return result.data;
}

function tokenOf(url: string | undefined): string {
  if (!url) throw new Error("missing url");
  return url.slice(url.lastIndexOf("/") + 1);
}

type Posted = { input: WebhookPostInput; statusCode: number };

function registerWebhookTests(label: string, openStore: () => Promise<Store>): void {
  describe(label, () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    let store: Store;
    let posts: Posted[];
    let queued: Array<Promise<void>>;
    let statusCode = 200;
    let postImpl: (input: WebhookPostInput) => Promise<{ statusCode: number }> = async (input) => {
      posts.push({ input, statusCode });
      return { statusCode };
    };

    beforeEach(async () => {
      now = new Date("2026-01-01T00:00:00.000Z");
      store = await openStore();
      await store.clearAll();
      posts = [];
      queued = [];
      statusCode = 200;
      postImpl = async (input) => {
        posts.push({ input, statusCode });
        return { statusCode };
      };
    });

    function bridge(overrides: Partial<WebhookFeature> = {}): Bridge {
      return new Bridge(store, {
        now: () => now,
        webhooks: { ...feature, ...overrides },
        lookup: async (host) => (host === "api2.cursor.sh" ? ["8.8.8.8"] : Promise.reject(new Error("dns"))),
        postWebhook: (input) => postImpl(input),
        jitter: () => 0,
        schedule: (work) => {
          queued.push(work());
        },
      });
    }

    function advance(ms: number): void {
      now = new Date(now.getTime() + ms);
    }

    async function flush(): Promise<void> {
      const batch = queued.splice(0, queued.length);
      await Promise.all(batch);
    }

    async function active(app: Bridge) {
      const a = must(await app.register({ displayName: "Alex" }, BASE));
      const b = must(await app.register({ displayName: "Blair" }, BASE));
      const alex = (await app.authenticate(a.token)) as BotRow;
      const blair = (await app.authenticate(b.token)) as BotRow;
      const invite = must(await app.requestLink(alex, {}, BASE));
      const peer = must(await app.requestLink(blair, { inviteCode: invite.invite_code }, BASE));
      must(await app.decideApproval(tokenOf(peer.approval_url), "approve", BASE));
      must(await app.decideApproval(tokenOf(invite.approval_url), "approve", BASE));
      return { alex, blair, invite };
    }

    test("bearer ping omits the message and is not awaited by send", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET, authScheme: "bearer" }));
      let release: (value: { statusCode: number }) => void = () => undefined;
      const gate = new Promise<{ statusCode: number }>((resolve) => {
        release = resolve;
      });
      postImpl = (input) => {
        posts.push({ input, statusCode: 200 });
        return gate;
      };
      const sent = await app.sendMessage(alex, { linkId: invite.link_id, body: "Dinner is at 7." });
      expect(sent.ok).toBe(true);
      expect(posts).toHaveLength(0);
      release({ statusCode: 200 });
      await flush();
      const body = posts[0]?.input.body ?? "";
      expect(body).not.toContain("Dinner is at 7.");
      expect(JSON.parse(body)).toMatchObject({
        v: 1,
        type: "bot_bridge.message_available",
        link_id: invite.link_id,
      });
      expect(posts[0]?.input.headers.authorization).toBe(`Bearer ${SECRET}`);
      expect(posts[0]?.input.headers["x-automation-key"]).toBeUndefined();
      const view = must(await app.getWebhook(blair, BASE));
      expect(view.secret_hint).toBe(SECRET.slice(-4));
      expect(JSON.stringify(view)).not.toContain(SECRET);
      const mailbox = must(await app.checkMessages(blair, {}));
      expect(mailbox.unread_count).toBe(1);
    });

    test("extra scheme and hmac headers are explicit", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(
        await app.setWebhook(blair, BASE, {
          url: URL,
          senderKey: SECRET,
          authScheme: "bearer_and_x_automation_key",
        }),
      );
      await app.sendMessage(alex, { linkId: invite.link_id, body: "one" });
      await flush();
      expect(posts[0]?.input.headers["x-automation-key"]).toBe(SECRET);

      const second = bridge();
      const people = await active(second);
      must(await second.setWebhook(people.blair, BASE, { url: URL, senderKey: SECRET, authScheme: "hmac_sha256" }));
      advance(1000);
      await second.sendMessage(people.alex, { linkId: people.invite.link_id, body: "two" });
      await flush();
      const hmacPost = posts[posts.length - 1]!;
      const signature = hmacPost.input.headers["x-bot-bridge-signature"];
      const stamp = Math.floor(now.getTime() / 1000);
      expect(signature).toBe(signWake(SECRET, hmacPost.input.body, stamp));
      expect(signature).toBe(`t=${stamp},v1=${createHmac("sha256", SECRET).update(`${stamp}.${hmacPost.input.body}`).digest("hex")}`);
    });

    test("idempotent replay does not ping twice, and revoke cancels a pending ping", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      const held: Array<() => Promise<void>> = [];
      const holding = new Bridge(store, {
        now: () => now,
        webhooks: feature,
        lookup: async () => ["8.8.8.8"],
        postWebhook: (input) => {
          posts.push({ input, statusCode: 200 });
          return Promise.resolve({ statusCode: 200 });
        },
        jitter: () => 0,
        schedule: (work) => held.push(work),
      });
      const sent = must(await holding.sendMessage(alex, { linkId: invite.link_id, body: "Dinner is at 7.", idempotencyKey: "k1" }));
      const replay = must(await holding.sendMessage(alex, { linkId: invite.link_id, body: "Dinner is at 7.", idempotencyKey: "k1" }));
      expect(replay.idempotent_replay).toBe(true);
      expect(replay.msg_id).toBe(sent.msg_id);
      expect(held).toHaveLength(1);
      must(await holding.revokeLink(alex, { linkId: invite.link_id, purge: false }, alex.bot_id));
      await held[0]!();
      expect(posts).toHaveLength(0);
    });

    test("retries a 500 and stops after three auth failures", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      statusCode = 500;
      await app.sendMessage(alex, { linkId: invite.link_id, body: "first" });
      await flush();
      expect(posts).toHaveLength(1);
      const pending = must(await app.getWebhook(blair, BASE));
      expect(pending.last_delivery?.status).toBe("pending");
      advance(30_000);
      statusCode = 200;
      const drained = await app.drain();
      expect(drained.succeeded).toBe(1);
      expect(posts).toHaveLength(2);

      statusCode = 401;
      for (let i = 0; i < 3; i++) {
        advance(1000);
        await app.sendMessage(alex, { linkId: invite.link_id, body: `nope ${i}` });
        await flush();
      }
      const rejected = must(await app.getWebhook(blair, BASE));
      expect(rejected.enabled).toBe(false);
      expect(rejected.last_error).toBe("auth_rejected");
      const before = posts.length;
      advance(1000);
      await app.sendMessage(alex, { linkId: invite.link_id, body: "after disable" });
      await flush();
      expect(posts).toHaveLength(before);
    });

    test("a timeout is retryable and the hourly cap defers the next ping", async () => {
      const app = bridge({ maxPerBotPerHour: 1 });
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      postImpl = async () => {
        throw new Error("timeout");
      };
      await app.sendMessage(alex, { linkId: invite.link_id, body: "slow" });
      await flush();
      let view = must(await app.getWebhook(blair, BASE));
      expect(view.last_delivery?.status).toBe("pending");
      expect(view.last_delivery?.last_error).toBe("timeout");
      postImpl = async (input) => {
        posts.push({ input, statusCode: 200 });
        return { statusCode: 200 };
      };
      advance(30_000);
      expect((await app.drain()).succeeded).toBe(1);

      advance(1000);
      await app.sendMessage(alex, { linkId: invite.link_id, body: "capped" });
      await flush();
      view = must(await app.getWebhook(blair, BASE));
      expect(posts).toHaveLength(1);
      expect(view.last_delivery?.attempts).toBe(0);
      expect(view.last_delivery?.status).toBe("pending");
    });

    test("a redirect is not followed and a thrown error is logged without the key", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      statusCode = 302;
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
      await app.sendMessage(alex, { linkId: invite.link_id, body: "redir" });
      await flush();
      expect(posts).toHaveLength(1);
      expect(must(await app.getWebhook(blair, BASE)).last_delivery?.last_error).toBe("redirect_refused");
      errorSpy.mockRestore();

      postImpl = async () => {
        throw new Error(`Authorization: Bearer ${SECRET}`);
      };
      const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
      advance(1000);
      await app.sendMessage(alex, { linkId: invite.link_id, body: "boom" });
      await flush();
      const logged = spy.mock.calls.map((call) => call.join(" ")).join("\n");
      expect(logged).not.toContain(SECRET);
      expect(logged).toContain("network");
      spy.mockRestore();
    });

    test("audit stores the host and not the path or key", async () => {
      const app = bridge();
      const { blair } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      const blob = JSON.stringify(await store.listAudits());
      expect(blob).toContain("api2.cursor.sh");
      expect(blob).not.toContain("super-secret-path");
      expect(blob).not.toContain(SECRET);
    });

    test("two drains send one ping", async () => {
      const app = bridge();
      const { alex, blair, invite } = await active(app);
      must(await app.setWebhook(blair, BASE, { url: URL, senderKey: SECRET }));
      const quiet = new Bridge(store, {
        now: () => now,
        webhooks: feature,
        lookup: async () => ["8.8.8.8"],
        postWebhook: (input) => postImpl(input),
        jitter: () => 0,
        schedule: () => undefined,
      });
      await quiet.sendMessage(alex, { linkId: invite.link_id, body: "once" });
      await Promise.all([quiet.drain(), quiet.drain()]);
      expect(posts).toHaveLength(1);
    });
  });
}

registerWebhookTests("memory webhooks", async () => new MemoryStore());

let pglite: PgliteDb | null = null;
registerWebhookTests("postgres webhooks", async () => {
  if (!pglite) {
    pglite = await createPgliteDb();
    await new PgStore(pglite).ensureSchema();
  }
  return new PgStore(pglite);
});

afterAll(async () => {
  await pglite?.close();
});

describe("webhook http", () => {
  const lookup = async () => ["8.8.8.8"];

  test("settings page saves a hint and does not echo the key", async () => {
    const store = new MemoryStore();
    const app = new Bridge(store, {
      webhooks: feature,
      lookup,
      schedule: () => undefined,
    });
    const registered = must(await app.register({ displayName: "Blair" }, BASE));
    const blair = (await app.authenticate(registered.token))!;
    const settings = must(await app.getWebhook(blair, BASE));
    const http = createApp({
      store,
      baseUrl: BASE,
      webhooks: feature,
      lookup,
    });
    const saved = await http.request(settings.settings_url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        action: "save",
        url: URL,
        sender_key: SECRET,
        auth_scheme: "bearer",
        enabled: "true",
      }),
    });
    const html = await saved.text();
    expect(html).toContain(SECRET.slice(-4));
    expect(html).not.toContain(SECRET);
    const view = must(await app.getWebhook(blair, BASE));
    expect(view.configured).toBe(true);

    const removed = await http.request(settings.settings_url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ action: "remove" }),
    });
    expect(removed.status).toBe(200);
    expect(must(await app.getWebhook(blair, BASE)).configured).toBe(false);
  });

  test("rotating the settings link kills the old url", async () => {
    const store = new MemoryStore();
    const app = new Bridge(store, { webhooks: feature, lookup, schedule: () => undefined });
    const registered = must(await app.register({ displayName: "Blair" }, BASE));
    const blair = (await app.authenticate(registered.token))!;
    const settings = must(await app.getWebhook(blair, BASE));
    const http = createApp({ store, baseUrl: BASE, webhooks: feature, lookup });
    const rotated = await http.request(settings.settings_url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ action: "rotate" }),
    });
    const body = (await rotated.json()) as { settings_url: string };
    expect(body.settings_url).not.toBe(settings.settings_url);
    const stale = await http.request(settings.settings_url);
    expect(await stale.text()).toContain("not valid");
  });

  test("drain auth matches the sweep shape, and a disabled flag refuses registration", async () => {
    const store = new MemoryStore();
    const closed = createApp({
      store,
      baseUrl: BASE,
      webhookDrainToken: null,
      cronSecret: null,
      webhooks: { ...feature, enabled: false },
    });
    expect((await closed.request(`${BASE}/internal/webhook-drain`)).status).toBe(404);
    const off = createApp({
      store,
      baseUrl: BASE,
      webhookDrainToken: "drain-secret",
      webhooks: { ...feature, enabled: false, kek: null },
    });
    const missing = await off.request(`${BASE}/internal/webhook-drain`, { method: "POST" });
    expect(missing.status).toBe(401);
    const wrong = await off.request(`${BASE}/internal/webhook-drain`, {
      method: "POST",
      headers: { authorization: "Bearer nope" },
    });
    expect(wrong.status).toBe(401);
    const alex = await off.request(`${BASE}/register`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ display_name: "Alex" }),
    });
    const token = ((await alex.json()) as { token: string }).token;
    const denied = await off.request(`${BASE}/mcp/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "set_webhook", arguments: { url: URL, sender_key: SECRET } },
      }),
    });
    const payload = (await denied.json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
    expect(payload.result.isError).toBe(true);
    expect(payload.result.content[0]?.text).toContain("webhook_disabled");
  });
});
