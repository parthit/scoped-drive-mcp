import { describe, expect, test } from "vitest";
import { Access } from "../src/access.js";
import { Bridge } from "../src/bridge.js";
import { createApp } from "../src/app.js";
import { newId } from "../src/ids.js";
import { MemoryStore } from "../src/store/memory.js";
import type { UserRow } from "../src/types.js";

const BASE = "http://bridge.test";
const FILES: Record<string, { name: string; mimeType: string; parents: string[]; trashed?: boolean; text?: string }> = {
  folder: { name: "Shared", mimeType: "application/vnd.google-apps.folder", parents: ["root"] },
  child: { name: "Notes", mimeType: "text/plain", parents: ["folder"], text: "hello from drive" },
  outside: { name: "Private", mimeType: "text/plain", parents: ["root"], text: "secret" },
  root: { name: "My Drive", mimeType: "application/vnd.google-apps.folder", parents: [] },
};

function driveFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  const params = new URLSearchParams(typeof init?.body === "string" ? init.body : "");
  if (url.includes("userinfo")) return Promise.resolve(Response.json({ sub: "ada", email: "ada@example.com" }));
  if (url.includes("oauth2.googleapis.com/token") && params.get("grant_type") === "refresh_token") {
    return Promise.resolve(Response.json({ access_token: "drive-access" }));
  }
  if (url.includes("oauth2.googleapis.com/token")) {
    return Promise.resolve(Response.json({ access_token: "once", refresh_token: "refresh-secret", scope: "https://www.googleapis.com/auth/drive.readonly" }));
  }
  if (url.includes("/drive/v3/about")) return Promise.resolve(Response.json({ user: { emailAddress: "ada@example.com" } }));
  const fileMatch = url.match(/\/drive\/v3\/files\/([^/?]+)/);
  if (fileMatch && !url.includes("alt=media")) {
    const file = FILES[decodeURIComponent(fileMatch[1]!)];
    if (!file) return Promise.resolve(new Response("missing", { status: 404 }));
    return Promise.resolve(Response.json({ id: decodeURIComponent(fileMatch[1]!), ...file }));
  }
  if (fileMatch && url.includes("alt=media")) {
    const file = FILES[decodeURIComponent(fileMatch[1]!)];
    return Promise.resolve(new Response(file?.text ?? "", { status: file ? 200 : 404 }));
  }
  if (url.includes("/drive/v3/files?")) {
    return Promise.resolve(Response.json({ files: [{ id: "child", name: "Notes", mimeType: "text/plain" }, { id: "outside", name: "Private", mimeType: "text/plain" }] }));
  }
  return Promise.resolve(new Response("missing", { status: 404 }));
}

describe("drive card", () => {
  test("a granted folder exposes its child and hides the rest", async () => {
    const store = new MemoryStore();
    const user: UserRow = { user_id: newId("usr"), email: null, created_at: new Date() };
    await store.insertUser(user);
    const bridge = new Bridge(store);
    const registered = await bridge.register({ displayName: "Alex", userId: user.user_id }, BASE);
    if (!registered.ok) throw new Error(registered.message);
    const bot = await bridge.authenticate(registered.data.token);
    if (!bot) throw new Error("bot missing");
    const access = new Access(store, {
      encryptionKey: "test-key",
      fetch: driveFetch,
      googleDrive: { clientId: "gid", clientSecret: "gsecret" },
    });
    const empty = await access.catalog(bot);
    expect(empty.ok && empty.data.integrations).toEqual([]);

    const connected = await access.finishDriveConnect({
      bot,
      code: "code",
      verifier: "verifier",
      redirectUri: `${BASE}/integrations/google-drive/callback`,
      capabilities: ["list", "read"],
    });
    expect(connected.ok).toBe(true);
    const stored = JSON.stringify(await store.listConnections(bot.bot_id));
    expect(stored).not.toContain("refresh-secret");

    await access.grant(bot, { kind: "folder", externalId: "folder", name: "Shared" });
    expect(await access.toolNames(bot)).toEqual(["drive_list_folder", "drive_search", "drive_get_metadata", "drive_read_file"]);
    const read = await access.call(bot, "drive_read_file", { file_id: "child" }, BASE);
    expect(read.ok).toBe(true);
    if (read.ok) expect(read.data).toMatchObject({ text: "hello from drive" });

    const denied = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.error).toBe("access_required");
      expect(String(denied.details?.approval_url)).toContain("/access/ar_");
      const token = String(denied.details?.approval_url).split("/").pop() ?? "";
      const approved = await access.decideAccess(token, user.user_id, "approve");
      expect(approved.ok && approved.data.status).toBe("approved");
    }
    const allowed = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
    expect(allowed.ok).toBe(true);

    const other = await bridge.register({ displayName: "Blair", userId: user.user_id }, BASE);
    if (!other.ok) throw new Error(other.message);
    const second = await bridge.authenticate(other.data.token);
    if (!second) throw new Error("second bot missing");
    const separate = await access.catalog(second);
    expect(separate.ok && separate.data.integrations).toEqual([]);
    const catalog = await access.catalog(bot);
    expect(catalog.ok && catalog.data.integrations[0]?.resources).toEqual([
      { kind: "folder", id: "folder", name: "Shared" },
      { kind: "file", id: "outside", name: "outside" },
    ]);
    expect(catalog.ok && JSON.stringify(catalog.data)).not.toContain("refresh");

    const write = await access.setCapabilities(bot, ["list", "read", "trash"]);
    expect(write.ok).toBe(false);
    if (!write.ok) expect(write.error).toBe("needs_reconnect");
    expect(await access.toolNames(bot)).not.toContain("drive_trash_file");
  });
});

describe("drive http", () => {
  test("the integrations page connects a drive card for one bot", async () => {
    const server = createApp({
      store: new MemoryStore(),
      baseUrl: BASE,
      sessionSecret: "test-session-secret",
      encryptionKey: "test-key",
      oauth: { google: { clientId: "gid", clientSecret: "gsecret" } },
      googleDrive: { clientId: "gid", clientSecret: "gsecret" },
      fetch: driveFetch,
    });
    const start = await server.request(`${BASE}/auth/google`);
    const location = new URL(start.headers.get("location") ?? "", "https://accounts.google.com");
    const state = location.searchParams.get("state") ?? "";
    const oauthCookie = start.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="))?.split(";")[0] ?? "";
    const callback = await server.request(`${BASE}/auth/google/callback?code=ada&state=${encodeURIComponent(state)}`, { headers: { cookie: oauthCookie } });
    const session = callback.headers.getSetCookie().find((item) => item.startsWith("bb_session="))?.split(";")[0] ?? "";
    const created = await server.request(`${BASE}/register`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ display_name: "Alex" }),
    });
    const bot = (await created.json()) as { bot_id: string };
    const page = await server.request(`${BASE}/bots/${bot.bot_id}`, { headers: { cookie: session } });
    const html = await page.text();
    expect(html).toContain("Google Drive");
    expect(html).toContain("Integrations");
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
    const connect = await server.request(`${BASE}/bots/${bot.bot_id}/drive/connect`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, capability: "list" }),
    });
    expect(connect.status).toBe(302);
    expect(connect.headers.get("location")).toContain("drive.readonly");
  });
});
