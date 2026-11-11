import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

export type DnsLookup = (hostname: string) => Promise<string[]>;

export type WebhookUrl =
  | { ok: true; hostname: string; path: string; address: string }
  | { ok: false; code: "invalid_webhook_url" | "webhook_host_not_allowed" | "dns" };

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("10.0.0.0", 8, "ipv4");
blocked.addSubnet("100.64.0.0", 10, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("172.16.0.0", 12, "ipv4");
blocked.addSubnet("192.168.0.0", 16, "ipv4");
blocked.addSubnet("224.0.0.0", 4, "ipv4");
blocked.addSubnet("240.0.0.0", 4, "ipv4");
blocked.addAddress("255.255.255.255", "ipv4");
blocked.addAddress("::", "ipv6");
blocked.addAddress("::1", "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");
blocked.addSubnet("ff00::", 8, "ipv6");

export function addressIsPublic(address: string): boolean {
  const parsed = canonicalize(address);
  if (!parsed) return false;
  return !blocked.check(parsed.address, parsed.family);
}

export async function defaultLookup(hostname: string): Promise<string[]> {
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

export async function approveWebhookUrl(raw: string, allowlist: string[], resolve: DnsLookup): Promise<WebhookUrl> {
  const inspected = inspectWebhookUrl(raw, allowlist);
  if (!inspected.ok) return inspected;
  let addresses: string[];
  try {
    addresses = await resolve(inspected.hostname);
  } catch {
    return { ok: false, code: "dns" };
  }
  if (addresses.length === 0 || addresses.some((address) => !addressIsPublic(address))) {
    return { ok: false, code: "invalid_webhook_url" };
  }
  const chosen = canonicalize(addresses[0]!);
  if (!chosen) return { ok: false, code: "invalid_webhook_url" };
  return { ok: true, hostname: inspected.hostname, path: inspected.path, address: chosen.address };
}

export function inspectWebhookUrl(
  raw: string,
  allowlist: string[],
): { ok: true; hostname: string; path: string } | { ok: false; code: "invalid_webhook_url" | "webhook_host_not_allowed" } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, code: "invalid_webhook_url" };
  }
  if (url.protocol !== "https:") return { ok: false, code: "invalid_webhook_url" };
  if (url.username || url.password || url.search || url.hash) return { ok: false, code: "invalid_webhook_url" };
  if (url.port && url.port !== "443") return { ok: false, code: "invalid_webhook_url" };
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname.includes(" ") || isIP(hostname) !== 0) return { ok: false, code: "invalid_webhook_url" };
  if (!allowlist.map((host) => host.toLowerCase()).includes(hostname)) {
    return { ok: false, code: "webhook_host_not_allowed" };
  }
  return { ok: true, hostname, path: url.pathname || "/" };
}

function canonicalize(address: string): { family: "ipv4" | "ipv6"; address: string } | null {
  if (isIP(address) === 4) return { family: "ipv4", address };
  if (isIP(address) !== 6) return null;
  const lower = address.toLowerCase();
  const dotted = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted && isIP(dotted[1]!) === 4) return { family: "ipv4", address: dotted[1]! };
  const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = Number.parseInt(hex[1]!, 16);
    const lo = Number.parseInt(hex[2]!, 16);
    return { family: "ipv4", address: `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}` };
  }
  return { family: "ipv6", address: lower };
}
