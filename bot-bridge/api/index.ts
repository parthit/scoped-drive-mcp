import type { IncomingMessage, ServerResponse } from "node:http";
import { getRequestListener } from "@hono/node-server";
import { getApp } from "../src/app.js";

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
  await listener(req, res);
}
