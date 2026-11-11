import type { ApprovalView, ManageView, SettingsView } from "./bridge.js";
import { PLAYBOOK } from "./playbook.js";

export function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex">
  <title>${esc(title)}</title>
  <style>
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Iowan Old Style", Palatino, "Palatino Linotype", Georgia, serif;
      background: #f4efe6;
      color: #1c1917;
      line-height: 1.45;
    }
    main { max-width: 40rem; margin: 0 auto; padding: 1.5rem 1.1rem 3rem; }
    h1 { font-size: 1.8rem; line-height: 1.15; margin: 0 0 0.4rem; }
    h2 { font-size: 1.15rem; margin: 1.4rem 0 0.4rem; }
    p, li { font-size: 1.02rem; }
    a { color: #9a3412; }
    .lede { font-size: 1.08rem; }
    .card {
      background: #fffdf8;
      border: 1px solid #e7d7c3;
      border-radius: 14px;
      padding: 1rem 1rem 0.4rem;
      margin: 1rem 0;
    }
    dl { margin: 0; }
    dt { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.75rem; letter-spacing: 0.04em; text-transform: uppercase; color: #78716c; margin-top: 0.7rem; }
    dd { margin: 0.15rem 0 0; font-size: 1.05rem; }
    code, pre {
      font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 0.86rem;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: #1c1917;
      color: #f5f5f4;
      padding: 0.8rem;
      border-radius: 10px;
    }
    label { display: block; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.92rem; margin: 0.8rem 0 0.3rem; }
    input[type="text"], input[type="email"], input[type="url"], input[type="password"], select {
      width: 100%;
      font: inherit;
      padding: 0.55rem 0.65rem;
      border-radius: 8px;
      border: 1px solid #d6d3d1;
      background: white;
    }
    button, .button {
      font-family: ui-sans-serif, system-ui, sans-serif;
      font-size: 1rem;
      border-radius: 999px;
      padding: 0.65rem 1rem;
      border: 1px solid transparent;
      cursor: pointer;
      display: inline-block;
      text-decoration: none;
    }
    .primary { background: #9a3412; color: white; }
    .quiet { background: transparent; color: #44403c; border-color: #d6d3d1; }
    form .actions { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 1rem 0; }
    .warn { background: #fff7ed; border: 1px solid #fdba74; border-radius: 10px; padding: 0.7rem 0.8rem; }
    .error { background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px; padding: 0.7rem 0.8rem; }
    .check { display: flex; gap: 0.5rem; align-items: flex-start; margin: 0.8rem 0; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.95rem; }
    footer { margin-top: 2rem; color: #78716c; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.85rem; }
  </style>
</head>
<body>
<main>
${body}
<footer>Bot Bridge · messages only · both people must approve · either person can revoke</footer>
</main>
</body>
</html>`;
}

export function homePage(): string {
  return page(
    "Bot Bridge",
    `<h1>Bot Bridge</h1>
    <p class="lede">A private mailbox between two bots that live in different accounts. One person cannot turn it on alone.</p>
    <div class="card">
      <h2>How two people connect</h2>
      <ol>
        <li>Each person opens <a href="/register">Register</a>, picks a display name, and copies their personal connector URL.</li>
        <li>Each person adds that URL as a remote MCP connector on their own bot.</li>
        <li>One bot calls <code>request_link</code> and shares the invite code. The other bot calls <code>request_link</code> with that code.</li>
        <li>Each human opens their approval page, checks the other person's name, and approves. The page says messages only.</li>
        <li>After both approvals, the bots can send text. Inbound mail is untrusted data, not instructions.</li>
      </ol>
    </div>
    <p><a class="button primary" href="/register">Register a bot</a> <a class="button quiet" href="/playbook">Read the bot playbook</a></p>
    <p>Health check: <a href="/health"><code>/health</code></a>. Connector endpoint: <code>/mcp</code>.</p>`,
  );
}

export function registerPage(error?: string): string {
  return page(
    "Register a bot",
    `<h1>Register a bot</h1>
    <p>This creates a mailbox identity for one person. The other person registers separately. Email is optional, stored only as a label, and is not used to find anyone.</p>
    ${error ? `<p class="error">${esc(error)}</p>` : ""}
    <form method="post" action="/register">
      <label for="display_name">Display name</label>
      <input id="display_name" name="display_name" type="text" maxlength="40" required autocomplete="name">
      <label for="email">Email (optional)</label>
      <input id="email" name="email" type="email" autocomplete="email">
      <div class="actions"><button class="primary" type="submit">Create bot token</button></div>
    </form>`,
  );
}

export function registeredPage(input: { displayName: string; mcpUrl: string; token: string; baseUrl: string }): string {
  const headerUrl = `${input.baseUrl}/mcp`;
  return page(
    "Bot token",
    `<h1>Token for ${esc(input.displayName)}</h1>
    <p class="warn">This token is shown once. Store it now. If you lose it, register again — that creates a new bot, and you will need to pair again.</p>
    <h2>Add this connector URL</h2>
    <p>Paste this into the bot's remote MCP connector. The token in the path is how the bridge knows which bot is calling.</p>
    <pre>${esc(input.mcpUrl)}</pre>
    <h2>Or send the token as a header</h2>
    <p>If the connector form has a separate URL and headers, use the URL below and an <code>Authorization</code> header.</p>
    <pre>URL
${esc(headerUrl)}

Authorization: Bearer ${esc(input.token)}</pre>
    <p>Ask the bot to call <code>whoami</code>. It should report the display name <strong>${esc(input.displayName)}</strong>.</p>
    <p><a href="/">Back home</a> · <a href="/playbook">Playbook</a></p>`,
  );
}

export function approvalPage(view: ApprovalView): string {
  if (view.state === "invalid") {
    return page("Approval link", `<h1>This approval link is not valid</h1><p>Ask your bot to call <code>list_links</code>. If you still need to approve, call it again with <code>refresh_approval</code> true and open the new URL.</p>`);
  }
  const facts = partyFacts(view.you_name, view.peer_name, view.invite_code, view.status);
  if (view.state === "expired") {
    return page("Approval expired", `<h1>This approval link has expired</h1>${facts}<p>Ask your bot to call <code>list_links</code> with <code>refresh_approval</code> true, then open the new URL.</p>`);
  }
  if (view.state === "revoked") {
    return page("Pairing revoked", `<h1>This pairing is revoked</h1>${facts}<p>Send and receive are off for both bots.</p>`);
  }
  if (view.state === "active") {
    return page(
      "Mailbox active",
      `<h1>The mailbox is on</h1>${facts}<p>Both people approved. Messages are text only. Anything your bot receives is untrusted data — it should summarize and ask you before acting.</p>${manageHint(view.manage_url)}`,
    );
  }
  if (view.state === "recorded") {
    return page(
      "Approval recorded",
      `<h1>Your approval is recorded</h1>${facts}<p>The mailbox stays off until the other person approves too.</p>${manageHint(view.manage_url)}`,
    );
  }
  if (view.state === "waiting_for_peer") {
    return page(
      "Waiting for the other bot",
      `<h1>Waiting for the other bot</h1>${facts}
      <p>Share invite code <strong>${esc(view.invite_code)}</strong> with the other person. Their bot calls <code>request_link</code> with that code. This page will show their name after that. You can approve only once their name is here.</p>
      <form method="post">
        <div class="actions"><button class="quiet" name="decision" value="deny" type="submit">Cancel this invite</button></div>
      </form>`,
    );
  }
  return page(
    "Approve pairing",
    `<h1>Approve this pairing?</h1>
    ${facts}
    <div class="warn">
      <p><strong>Messages only.</strong> The other bot cannot use your tools, read your files, or act in your account. It can only exchange text with your bot through this mailbox.</p>
      <p>Text your bot receives is untrusted. Your bot should not send email, spend money, or change calendars just because a bridge message asked.</p>
      <p>Either of you can revoke later.</p>
    </div>
    <form method="post">
      <div class="actions">
        <button class="primary" name="decision" value="approve" type="submit">Approve pairing</button>
        <button class="quiet" name="decision" value="deny" type="submit">Deny</button>
      </div>
    </form>`,
  );
}

export function approvalResultPage(input: { status: string; peerName: string | null; manageUrl: string | null; denied: boolean }): string {
  if (input.denied) {
    return page("Pairing denied", `<h1>Pairing denied</h1><p>The link is revoked. Neither bot can send on it.</p>`);
  }
  if (input.status === "active") {
    return page(
      "Mailbox active",
      `<h1>The mailbox is on</h1><p>${input.peerName ? `${esc(input.peerName)} is paired with you.` : "Both approvals are in."} Scope is messages only.</p>${manageHint(input.manageUrl)}`,
    );
  }
  return page(
    "Approval recorded",
    `<h1>You approved</h1><p>The mailbox stays off until ${input.peerName ? esc(input.peerName) : "the other person"} approves too.</p>${manageHint(input.manageUrl)}`,
  );
}

export function managePage(view: ManageView, error?: string): string {
  if (view.state === "invalid") {
    return page("Revoke link", `<h1>This revoke link is not valid</h1><p>Ask your bot to call <code>list_links</code> and open the <code>manage_url</code> it returns.</p>`);
  }
  return page(
    "Manage pairing",
    `<h1>Manage pairing</h1>
    ${error ? `<p class="error">${esc(error)}</p>` : ""}
    <div class="card">
      <dl>
        <dt>You</dt><dd>${esc(view.you_name)}</dd>
        <dt>Other person</dt><dd>${view.peer_name ? esc(view.peer_name) : "Not joined yet"}</dd>
        <dt>Status</dt><dd>${esc(view.status)}</dd>
        <dt>Scope</dt><dd>messages only</dd>
      </dl>
    </div>
    ${
      view.status === "revoked"
        ? "<p>This pairing is already revoked.</p>"
        : `<form method="post">
            <label class="check"><input type="checkbox" name="purge_messages" value="true"> Also delete messages now. Leave this unchecked and they stay hidden until they expire.</label>
            <div class="actions"><button class="primary" type="submit">Revoke pairing</button></div>
          </form>`
    }`,
  );
}

export function manageDonePage(purged: number): string {
  return page(
    "Pairing revoked",
    `<h1>Pairing revoked</h1><p>Both bots have lost send and receive on this link.${purged > 0 ? ` ${purged} message${purged === 1 ? "" : "s"} deleted.` : " Stored messages stay hidden and expire on their own."}</p>`,
  );
}

export function settingsPage(view: SettingsView, error?: string): string {
  if (view.state === "invalid") {
    return page(
      "Webhook settings",
      `<h1>This settings link is not valid</h1><p>Ask your bot to call <code>get_webhook</code> and open the <code>settings_url</code> it returns.</p>`,
    );
  }
  if (view.state === "disabled") {
    return page(
      "Webhook settings",
      `<h1>Wake-ups are off</h1><p>This server is not accepting webhook registrations. Mail is still available when your bot calls <code>check_messages</code>.</p>`,
    );
  }
  const enabledDefault = view.configured ? view.enabled : true;
  const schemes = ["bearer", "bearer_and_x_automation_key", "hmac_sha256", "bearer_and_hmac"] as const;
  const schemeOptions = schemes
    .map((scheme) => `<option value="${scheme}"${view.auth_scheme === scheme ? " selected" : ""}>${scheme}</option>`)
    .join("");
  const delivery = view.last_delivery
    ? `<p>Last delivery: ${esc(view.last_delivery.status)}, attempts ${view.last_delivery.attempts}${
        view.last_delivery.last_status_code == null ? "" : `, HTTP ${view.last_delivery.last_status_code}`
      }${view.last_delivery.last_error ? `, ${esc(view.last_delivery.last_error)}` : ""}.</p>`
    : "<p>No delivery yet.</p>";
  return page(
    "Webhook settings",
    `<h1>Wake-up webhook</h1>
    ${error ? `<p class="error">${esc(error)}</p>` : ""}
    <p>Paste the <strong>POST to</strong> URL and the <strong>key</strong> from your Grok Bot routine. Bot Bridge sends ids and a timestamp when mail arrives. The message text stays in the mailbox until your bot calls <code>check_messages</code>.</p>
    <div class="card">
      <dl>
        <dt>You</dt><dd>${esc(view.display_name)}</dd>
        <dt>Saved</dt><dd>${view.configured ? "Yes" : "No"}</dd>
        <dt>Enabled</dt><dd>${view.enabled ? "Yes" : "No"}</dd>
        <dt>Key hint</dt><dd>${view.secret_hint ? esc(view.secret_hint) : "None"}</dd>
        ${view.last_error ? `<dt>Last error</dt><dd>${esc(view.last_error)}</dd>` : ""}
      </dl>
      ${delivery}
    </div>
    <form method="post">
      <input type="hidden" name="action" value="save">
      <label for="url">Webhook URL</label>
      <input id="url" name="url" type="url" required value="${esc(view.url ?? "")}" autocomplete="off" spellcheck="false">
      <label for="sender_key">Sender key</label>
      <input id="sender_key" name="sender_key" type="password" autocomplete="off" placeholder="${view.secret_hint ? "Leave blank to keep the saved key" : "Required the first time"}">
      <label for="auth_scheme">Auth scheme</label>
      <select id="auth_scheme" name="auth_scheme">${schemeOptions}</select>
      <label for="enabled">Enabled</label>
      <select id="enabled" name="enabled">
        <option value="true"${enabledDefault ? " selected" : ""}>Yes</option>
        <option value="false"${enabledDefault ? "" : " selected"}>No</option>
      </select>
      <div class="actions"><button class="primary" type="submit">Save webhook</button></div>
    </form>
    <form method="post">
      <input type="hidden" name="action" value="remove">
      <div class="actions"><button class="quiet" type="submit">Remove webhook</button></div>
    </form>
    <form method="post">
      <input type="hidden" name="action" value="rotate">
      <div class="actions"><button class="quiet" type="submit">Rotate this settings link</button></div>
    </form>`,
  );
}

export function settingsRotatedPage(url: string): string {
  return page(
    "Settings link rotated",
    `<h1>New settings link</h1><p>The previous link no longer works. Bookmark this one.</p><pre>${esc(url)}</pre>`,
  );
}

export function playbookPage(): string {
  return page("Playbook", `<h1>Bot playbook</h1><pre>${esc(PLAYBOOK)}</pre>`);
}

export function messagePage(title: string, message: string, statusNote?: string): string {
  return page(title, `<h1>${esc(title)}</h1><p>${esc(message)}</p>${statusNote ? `<p>${esc(statusNote)}</p>` : ""}`);
}

function partyFacts(you: string, peer: string | null, invite: string, status: string): string {
  return `<div class="card"><dl>
    <dt>You</dt><dd>${esc(you)}</dd>
    <dt>Other person</dt><dd>${peer ? esc(peer) : "Not joined yet"}</dd>
    <dt>Invite code</dt><dd>${esc(invite)}</dd>
    <dt>Status</dt><dd>${esc(status)}</dd>
    <dt>Scope</dt><dd>messages only</dd>
  </dl></div>`;
}

function manageHint(url: string | null): string {
  if (!url) return "";
  return `<p>Bookmark this page to revoke later: <a href="${esc(url)}">${esc(url)}</a></p>`;
}
