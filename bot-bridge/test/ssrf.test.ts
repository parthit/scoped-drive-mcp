import { describe, expect, test } from "vitest";
import { addressIsPublic, approveWebhookUrl, inspectWebhookUrl } from "../src/ssrf.js";

const ALLOW = ["api2.cursor.sh"];

describe("webhook url policy", () => {
  test("accepts an allowlisted https url when every address is public", async () => {
    const approved = await approveWebhookUrl(
      "https://api2.cursor.sh/automations/webhook/abc",
      ALLOW,
      async () => ["8.8.8.8"],
    );
    expect(approved).toEqual({
      ok: true,
      hostname: "api2.cursor.sh",
      path: "/automations/webhook/abc",
      address: "8.8.8.8",
    });
  });

  test("rejects non-https, userinfo, query, fragment, odd ports, and ip literals", () => {
    const samples = [
      "http://api2.cursor.sh/hook",
      "https://user:pass@api2.cursor.sh/hook",
      "https://api2.cursor.sh/hook?x=1",
      "https://api2.cursor.sh/hook#frag",
      "https://api2.cursor.sh:8443/hook",
      "https://8.8.8.8/hook",
      "not a url",
    ];
    for (const sample of samples) {
      expect(inspectWebhookUrl(sample, ALLOW).ok).toBe(false);
    }
  });

  test("rejects a host that is not on the allowlist", () => {
    expect(inspectWebhookUrl("https://example.com/hook", ALLOW)).toMatchObject({
      ok: false,
      code: "webhook_host_not_allowed",
    });
  });

  test("rejects private and mapped answers, including a mixed result", async () => {
    const bad = [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "::1",
      "fe80::1",
      "fd00::1",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
    ];
    for (const address of bad) {
      expect(addressIsPublic(address)).toBe(false);
      const approved = await approveWebhookUrl("https://api2.cursor.sh/hook", ALLOW, async () => [address]);
      expect(approved.ok).toBe(false);
    }
    const mixed = await approveWebhookUrl("https://api2.cursor.sh/hook", ALLOW, async () => ["8.8.8.8", "10.0.0.1"]);
    expect(mixed).toMatchObject({ ok: false, code: "invalid_webhook_url" });
  });
});
