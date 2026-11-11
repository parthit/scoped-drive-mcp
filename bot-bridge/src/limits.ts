export type Limits = {
  maxBodyBytes: number;
  perLinkPerHour: number;
  perBotPerHour: number;
  linkRequestsPerHour: number;
  messageTtlMs: number;
  approvalTtlMs: number;
};

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

function intEnv(value: string | undefined, fallback: number): number {
  if (value == null || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.floor(parsed);
}

export function limitsFromEnv(env: NodeJS.ProcessEnv = process.env): Limits {
  return {
    maxBodyBytes: intEnv(env.MAX_BODY_BYTES, 2048),
    perLinkPerHour: intEnv(env.RATE_LIMIT_PER_LINK_PER_HOUR, 30),
    perBotPerHour: intEnv(env.RATE_LIMIT_PER_BOT_PER_HOUR, 60),
    linkRequestsPerHour: intEnv(env.LINK_REQUESTS_PER_HOUR, 20),
    messageTtlMs: intEnv(env.MESSAGE_TTL_DAYS, 14) * DAY_MS,
    approvalTtlMs: intEnv(env.APPROVAL_TTL_DAYS, 7) * DAY_MS,
  };
}

export const HOUR = HOUR_MS;

export type WebhookFeature = {
  enabled: boolean;
  kek: Buffer | null;
  allowlist: string[];
  maxPerBotPerHour: number;
  attemptTimeoutMs: number;
  maxAttempts: number;
};

export function webhookFeatureFromEnv(env: NodeJS.ProcessEnv = process.env): WebhookFeature {
  const kekRaw = env.WEBHOOK_KEK?.trim() ?? "";
  const kek = kekRaw ? Buffer.from(kekRaw, "base64") : null;
  const allowlistRaw = env.WEBHOOK_HOST_ALLOWLIST;
  const allowlist =
    allowlistRaw == null
      ? ["api2.cursor.sh"]
      : allowlistRaw
          .split(",")
          .map((host) => host.trim().toLowerCase())
          .filter((host) => host.length > 0);
  return {
    enabled: env.WEBHOOKS_ENABLED === "1",
    kek: kek && kek.length === 32 ? kek : null,
    allowlist,
    maxPerBotPerHour: intEnv(env.WEBHOOK_MAX_PER_BOT_PER_HOUR, 60),
    attemptTimeoutMs: intEnv(env.WEBHOOK_ATTEMPT_TIMEOUT_MS, 4000),
    maxAttempts: intEnv(env.WEBHOOK_MAX_ATTEMPTS, 5),
  };
}
