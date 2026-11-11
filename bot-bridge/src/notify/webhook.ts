import { createHmac } from "node:crypto";
import { request as httpsRequest } from "node:https";
import type { AuthScheme, MessageRow } from "../types.js";

export type WakeEvent = {
  v: 1;
  type: "bot_bridge.message_available";
  link_id: string;
  thread_id: string;
  msg_id: string;
  created_at: string;
};

export type DeliveryResult = {
  ok: boolean;
  retryable: boolean;
  statusCode?: number;
  errorCode: string;
};

export type WebhookPostInput = {
  address: string;
  hostname: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  timeoutMs: number;
};

export type WebhookTransport = (input: WebhookPostInput) => Promise<{ statusCode: number }>;

const USER_AGENT = "bot-bridge-webhook/1";

export function wakeFromMessage(message: Pick<MessageRow, "link_id" | "thread_id" | "msg_id" | "created_at">): WakeEvent {
  return {
    v: 1,
    type: "bot_bridge.message_available",
    link_id: message.link_id,
    thread_id: message.thread_id,
    msg_id: message.msg_id,
    created_at: message.created_at.toISOString(),
  };
}

export function serializeWake(event: WakeEvent): string {
  return JSON.stringify(event);
}

export async function deliverWebhook(input: {
  hostname: string;
  path: string;
  address: string;
  secret: string;
  scheme: AuthScheme;
  event: WakeEvent;
  timeoutMs: number;
  now: Date;
  post?: WebhookTransport;
}): Promise<DeliveryResult> {
  const body = serializeWake(input.event);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
    "user-agent": USER_AGENT,
  };
  if (input.scheme === "bearer" || input.scheme === "bearer_and_x_automation_key" || input.scheme === "bearer_and_hmac") {
    headers.authorization = `Bearer ${input.secret}`;
  }
  if (input.scheme === "bearer_and_x_automation_key") {
    headers["x-automation-key"] = input.secret;
  }
  if (input.scheme === "hmac_sha256" || input.scheme === "bearer_and_hmac") {
    const t = Math.floor(input.now.getTime() / 1000);
    const mac = createHmac("sha256", input.secret).update(`${t}.${body}`).digest("hex");
    headers["x-bot-bridge-signature"] = `t=${t},v1=${mac}`;
  }
  const post = input.post ?? defaultWebhookPost;
  try {
    const response = await post({
      address: input.address,
      hostname: input.hostname,
      path: input.path,
      headers,
      body,
      timeoutMs: input.timeoutMs,
    });
    return classifyStatus(response.statusCode);
  } catch (error) {
    const timedOut = error instanceof Error && error.message === "timeout";
    return { ok: false, retryable: true, errorCode: timedOut ? "timeout" : "network" };
  }
}

export function classifyStatus(status: number): DeliveryResult {
  if (status === 200) return { ok: true, retryable: false, statusCode: status, errorCode: "ok" };
  if (status >= 300 && status < 400) return { ok: false, retryable: false, statusCode: status, errorCode: "redirect_refused" };
  if (status === 408 || status === 429 || status >= 500) {
    return { ok: false, retryable: true, statusCode: status, errorCode: "http_status" };
  }
  if (status >= 400) return { ok: false, retryable: false, statusCode: status, errorCode: "http_status" };
  return { ok: false, retryable: true, statusCode: status, errorCode: "network" };
}

export function signWake(secret: string, body: string, unixSeconds: number): string {
  const mac = createHmac("sha256", secret).update(`${unixSeconds}.${body}`).digest("hex");
  return `t=${unixSeconds},v1=${mac}`;
}

export function defaultWebhookPost(input: WebhookPostInput): Promise<{ statusCode: number }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | null, statusCode?: number) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve({ statusCode: statusCode ?? 0 });
    };
    const family = input.address.includes(":") ? 6 : 4;
    const req = httpsRequest(
      {
        host: input.address,
        servername: input.hostname,
        path: input.path,
        method: "POST",
        family,
        headers: {
          ...input.headers,
          host: input.hostname,
          "content-length": Buffer.byteLength(input.body),
        },
        timeout: input.timeoutMs,
      },
      (res) => {
        let received = 0;
        res.on("data", (chunk: Buffer) => {
          received += chunk.length;
          if (received > 512) res.destroy();
        });
        res.on("end", () => finish(null, res.statusCode ?? 0));
        res.on("error", () => finish(null, res.statusCode ?? 0));
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });
    req.on("error", (error) => finish(error instanceof Error ? error : new Error("network")));
    req.end(input.body);
  });
}
