import type { IncomingMessage, ServerResponse } from "node:http";
import { getRequestListener } from "@hono/node-server";
import { waitUntil } from "@vercel/functions";
import { getApp } from "../src/app.js";
import { runWithScheduler } from "../src/background.js";

export const config = {
  api: {
    bodyParser: false,
  },
  maxDuration: 30,
};

type Listener = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

let listener: Listener | null = null;

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!listener) {
    const app = await getApp();
    listener = getRequestListener(app.fetch);
  }
  await runWithScheduler((work) => {
    const promise = work().catch((error: unknown) => {
      console.error("webhook_background_failed", error instanceof Error ? error.name : "error");
    });
    waitUntil(promise);
  }, () => listener!(req, res));
}
