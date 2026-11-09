import { serve } from "@hono/node-server";
import { getApp } from "./app.js";

const port = Number(process.env.PORT ?? 4471);
const hostname = process.env.HOST ?? "0.0.0.0";

const app = await getApp();
serve({ fetch: app.fetch, port, hostname }, (info) => {
  console.log(`bot-bridge listening on http://127.0.0.1:${info.port}`);
});
