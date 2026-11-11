import { serve } from "@hono/node-server";
import { getApp } from "./app.js";
import { runWithScheduler } from "./background.js";

const port = Number(process.env.PORT ?? 4471);
const hostname = process.env.HOST ?? "0.0.0.0";

const app = await getApp();
serve(
  {
    fetch: (request) =>
      runWithScheduler((work) => {
        void work().catch((error: unknown) => {
          console.error("webhook_background_failed", error instanceof Error ? error.name : "error");
        });
      }, () => app.fetch(request)),
    port,
    hostname,
  },
  (info) => {
    console.log(`bot-bridge listening on http://127.0.0.1:${info.port}`);
  },
);
