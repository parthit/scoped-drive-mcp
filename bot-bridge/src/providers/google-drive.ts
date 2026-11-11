import { err, ok, type Result } from "../result.js";
import type { GrantRow } from "../types.js";

export const DRIVE_PROVIDER = "google_drive";
const READ_SCOPE = "https://www.googleapis.com/auth/drive.readonly";
const FULL_SCOPE = "https://www.googleapis.com/auth/drive";
const FOLDER = "application/vnd.google-apps.folder";
const DOC = "application/vnd.google-apps.document";
const SHEET = "application/vnd.google-apps.spreadsheet";
const SLIDE = "application/vnd.google-apps.presentation";

export const DRIVE_CAPABILITIES = [
  { id: "list", label: "List", tools: ["drive_list_folder", "drive_search"] },
  { id: "read", label: "Read", tools: ["drive_get_metadata", "drive_read_file"] },
  { id: "write", label: "Write", tools: ["drive_create_folder", "drive_upload_file", "drive_update_file"] },
  { id: "rename", label: "Rename", tools: ["drive_rename_file"] },
  { id: "trash", label: "Trash", tools: ["drive_trash_file"] },
] as const;

const WRITE_CAPABILITIES = new Set(["write", "rename", "trash"]);

export type DriveResource = { kind: "file" | "folder"; id: string; name: string; mimeType: string };

type DriveMeta = { id: string; name: string; mimeType: string; parents: string[]; trashed: boolean };

export function driveScopeFor(capabilities: string[]): string {
  return capabilities.some((id) => WRITE_CAPABILITIES.has(id)) ? FULL_SCOPE : READ_SCOPE;
}

export function driveScopeAllows(scope: string | null, capabilities: string[]): boolean {
  if (!capabilities.some((id) => WRITE_CAPABILITIES.has(id))) return true;
  return (scope ?? "").split(/[\s,]+/).includes(FULL_SCOPE);
}

export function driveAuthorizationUrl(input: { clientId: string; redirectUri: string; state: string; challenge: string; capabilities: string[] }): string {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", driveScopeFor(input.capabilities));
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  return url.toString();
}

export async function exchangeDriveCode(input: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  verifier: string;
  fetch: typeof fetch;
}): Promise<{ refreshToken: string; label: string; scope: string }> {
  const token = await postForm(input.fetch, "https://oauth2.googleapis.com/token", {
    code: input.code,
    client_id: input.clientId,
    client_secret: input.clientSecret,
    redirect_uri: input.redirectUri,
    grant_type: "authorization_code",
    code_verifier: input.verifier,
  });
  const refresh = stringField(token, "refresh_token");
  const access = stringField(token, "access_token");
  if (!refresh || !access) throw new Error("drive_token");
  const about = await getJson(input.fetch, "https://www.googleapis.com/drive/v3/about?fields=user", access);
  const user = about.user;
  const label = user && typeof user === "object" ? stringField(user as Record<string, unknown>, "emailAddress") : "";
  return { refreshToken: refresh, label: label || "Google Drive", scope: stringField(token, "scope") || driveScopeFor([]) };
}

export async function driveAccessToken(input: { clientId: string; clientSecret: string; refreshToken: string; fetch: typeof fetch }): Promise<string> {
  const token = await postForm(input.fetch, "https://oauth2.googleapis.com/token", {
    client_id: input.clientId,
    client_secret: input.clientSecret,
    refresh_token: input.refreshToken,
    grant_type: "refresh_token",
  });
  const access = stringField(token, "access_token");
  if (!access) throw new Error("drive_refresh");
  return access;
}

export async function listDriveChildren(fetchImpl: typeof fetch, accessToken: string, folderId?: string): Promise<DriveResource[]> {
  const q = folderId ? `'${folderId.replace(/'/g, "\\'")}' in parents and trashed=false` : "'root' in parents and trashed=false";
  const url = new URL("https://www.googleapis.com/drive/v3/files");
  url.searchParams.set("q", q);
  url.searchParams.set("fields", "files(id,name,mimeType)");
  url.searchParams.set("pageSize", "50");
  url.searchParams.set("supportsAllDrives", "true");
  url.searchParams.set("includeItemsFromAllDrives", "true");
  const body = await getJson(fetchImpl, url.toString(), accessToken);
  const files = Array.isArray(body.files) ? body.files : [];
  return files.flatMap((file) => {
    if (!file || typeof file !== "object") return [];
    const row = file as Record<string, unknown>;
    const id = stringField(row, "id");
    if (!id) return [];
    const mimeType = stringField(row, "mimeType");
    return [{ id, name: stringField(row, "name") || id, mimeType, kind: mimeType === FOLDER ? "folder" as const : "file" as const }];
  });
}

export async function driveInScope(fetchImpl: typeof fetch, accessToken: string, fileId: string, grants: Array<{ external_id: string }>): Promise<{ ok: true; meta: DriveMeta } | { ok: false }> {
  const granted = new Set(grants.map((grant) => grant.external_id));
  const seen = new Set<string>();
  const queue = [fileId];
  let lookups = 0;
  let first: DriveMeta | null = null;
  while (queue.length > 0 && lookups < 12) {
    const id = queue.shift();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    lookups += 1;
    const meta = await fetchMeta(fetchImpl, accessToken, id);
    if (!meta || meta.trashed) continue;
    if (id === fileId) first = meta;
    if (granted.has(id)) {
      if (!first) return { ok: false };
      return { ok: true, meta: first };
    }
    for (const parent of meta.parents) queue.push(parent);
  }
  return { ok: false };
}

export async function executeDriveTool(input: {
  tool: string;
  args: Record<string, unknown>;
  accessToken: string;
  grants: GrantRow[];
  fetch: typeof fetch;
}): Promise<Result<unknown>> {
  const fileId = stringArg(input.args, "file_id") || stringArg(input.args, "folder_id");
  if (input.tool === "drive_list_folder" && !stringArg(input.args, "folder_id")) {
    return ok({
      resources: input.grants.map((grant) => ({ kind: grant.kind, id: grant.external_id, name: grant.name })),
    });
  }
  if (input.tool === "drive_list_folder") {
    const folderId = stringArg(input.args, "folder_id");
    const scope = await driveInScope(input.fetch, input.accessToken, folderId, input.grants);
    if (!scope.ok) return outOfScope(folderId, FOLDER);
    const children = await listDriveChildren(input.fetch, input.accessToken, folderId);
    return ok({ resources: children.map(({ kind, id, name }) => ({ kind, id, name })) });
  }
  if (input.tool === "drive_search") {
    const query = stringArg(input.args, "query");
    if (!query) return err("invalid_input", "query is required.");
    const url = new URL("https://www.googleapis.com/drive/v3/files");
    url.searchParams.set("q", `trashed=false and name contains '${query.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`);
    url.searchParams.set("fields", "files(id,name,mimeType)");
    url.searchParams.set("pageSize", "20");
    url.searchParams.set("supportsAllDrives", "true");
    const body = await getJson(input.fetch, url.toString(), input.accessToken);
    const files = Array.isArray(body.files) ? body.files : [];
    const kept = [];
    for (const file of files) {
      if (!file || typeof file !== "object") continue;
      const id = stringField(file as Record<string, unknown>, "id");
      if (!id) continue;
      const scope = await driveInScope(input.fetch, input.accessToken, id, input.grants);
      if (!scope.ok) continue;
      kept.push({ id, name: stringField(file as Record<string, unknown>, "name") || id, mimeType: scope.meta.mimeType });
    }
    return ok({ resources: kept });
  }
  if (input.tool === "drive_create_folder") {
    const name = stringArg(input.args, "name");
    const parentId = stringArg(input.args, "parent_id");
    if (!name || !parentId) return err("invalid_input", "name and parent_id are required.");
    const parent = await driveInScope(input.fetch, input.accessToken, parentId, input.grants);
    if (!parent.ok) return outOfScope(parentId, FOLDER);
    return ok(await createDriveFolder(input.fetch, input.accessToken, name, parentId));
  }
  if (input.tool === "drive_upload_file") {
    const name = stringArg(input.args, "name");
    const content = stringArg(input.args, "content");
    const parentId = stringArg(input.args, "parent_id");
    if (!name || !content || !parentId) return err("invalid_input", "name, content, and parent_id are required.");
    const parent = await driveInScope(input.fetch, input.accessToken, parentId, input.grants);
    if (!parent.ok) return outOfScope(parentId, FOLDER);
    const created = await postJson(input.fetch, "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true", input.accessToken, {
      name,
      parents: [parentId],
    });
    const id = stringField(created, "id");
    await input.fetch(`https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(id)}?uploadType=media&supportsAllDrives=true`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${input.accessToken}`, "content-type": "text/plain" },
      body: content,
    });
    return ok({ id, name });
  }
  if (!fileId) return err("invalid_input", "file_id is required.");
  const scope = await driveInScope(input.fetch, input.accessToken, fileId, input.grants);
  if (!scope.ok) return outOfScope(fileId, "file");
  if (input.tool === "drive_get_metadata") {
    const parents = [];
    for (const parent of scope.meta.parents) {
      const parentScope = await driveInScope(input.fetch, input.accessToken, parent, input.grants);
      if (parentScope.ok) parents.push(parent);
    }
    return ok({ id: scope.meta.id, name: scope.meta.name, mime_type: scope.meta.mimeType, parents });
  }
  if (input.tool === "drive_read_file") {
    const text = await readText(input.fetch, input.accessToken, scope.meta);
    if (text == null) return err("unsupported_file", "This file is not text that the bot can read.");
    return ok({ id: scope.meta.id, name: scope.meta.name, text: text.slice(0, 100_000) });
  }
  if (input.tool === "drive_rename_file") {
    const name = stringArg(input.args, "new_name");
    if (!name) return err("invalid_input", "new_name is required.");
    const updated = await patchJson(input.fetch, `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?supportsAllDrives=true`, input.accessToken, { name });
    return ok({ id: fileId, name: stringField(updated, "name") || name });
  }
  if (input.tool === "drive_trash_file") {
    await patchJson(input.fetch, `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?supportsAllDrives=true`, input.accessToken, { trashed: true });
    return ok({ id: fileId, trashed: true });
  }
  if (input.tool === "drive_update_file") {
    const content = stringArg(input.args, "content");
    if (!content) return err("invalid_input", "content is required.");
    await input.fetch(`https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(fileId)}?uploadType=media&supportsAllDrives=true`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${input.accessToken}`, "content-type": "text/plain" },
      body: content,
    });
    return ok({ id: fileId, updated: true });
  }
  return err("unknown_tool", "This Drive action is not available.");
}

export async function createDriveFolder(fetchImpl: typeof fetch, accessToken: string, name: string, parentId: string): Promise<{ id: string; name: string }> {
  const created = await postJson(fetchImpl, "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true", accessToken, {
    name,
    mimeType: FOLDER,
    parents: [parentId],
  });
  return { id: stringField(created, "id"), name: stringField(created, "name") || name };
}

function outOfScope(externalId: string, mimeType?: string): Result<never> {
  const kind = mimeType === FOLDER ? "folder" : "file";
  return err("access_required", "This item is not granted on this bot's Google Drive card.", { external_id: externalId, kind });
}

async function readText(fetchImpl: typeof fetch, accessToken: string, meta: DriveMeta): Promise<string | null> {
  if (meta.mimeType === DOC || meta.mimeType === SLIDE) {
    const response = await fetchImpl(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(meta.id)}/export?mimeType=text/plain&supportsAllDrives=true`,
      { headers: { authorization: `Bearer ${accessToken}` } },
    );
    if (!response.ok) return null;
    return response.text();
  }
  if (meta.mimeType === SHEET) {
    const response = await fetchImpl(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(meta.id)}/export?mimeType=text/csv&supportsAllDrives=true`,
      { headers: { authorization: `Bearer ${accessToken}` } },
    );
    if (!response.ok) return null;
    return response.text();
  }
  if (meta.mimeType.startsWith("text/") || meta.mimeType === "application/json") {
    const response = await fetchImpl(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(meta.id)}?alt=media&supportsAllDrives=true`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) return null;
    return response.text();
  }
  return null;
}

async function fetchMeta(fetchImpl: typeof fetch, accessToken: string, id: string): Promise<DriveMeta | null> {
  const response = await fetchImpl(
    `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(id)}?fields=id,name,mimeType,parents,trashed&supportsAllDrives=true`,
    { headers: { authorization: `Bearer ${accessToken}` } },
  );
  if (response.status === 404) return null;
  if (!response.ok) return null;
  const body = (await response.json()) as Record<string, unknown>;
  const fileId = stringField(body, "id");
  if (!fileId) return null;
  return {
    id: fileId,
    name: stringField(body, "name") || fileId,
    mimeType: stringField(body, "mimeType"),
    parents: Array.isArray(body.parents) ? body.parents.filter((parent): parent is string => typeof parent === "string") : [],
    trashed: body.trashed === true,
  };
}

async function postForm(fetchImpl: typeof fetch, url: string, fields: Record<string, string>): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
  if (!response.ok) throw new Error("drive_http");
  return (await response.json()) as Record<string, unknown>;
}

async function getJson(fetchImpl: typeof fetch, url: string, accessToken: string): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, { headers: { authorization: `Bearer ${accessToken}` } });
  if (!response.ok) throw new Error("drive_http");
  return (await response.json()) as Record<string, unknown>;
}

async function postJson(fetchImpl: typeof fetch, url: string, accessToken: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("drive_http");
  return (await response.json()) as Record<string, unknown>;
}

async function patchJson(fetchImpl: typeof fetch, url: string, accessToken: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, {
    method: "PATCH",
    headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("drive_http");
  return (await response.json()) as Record<string, unknown>;
}

function stringField(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  return typeof value === "string" ? value : "";
}

function stringArg(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  return typeof value === "string" ? value.trim() : "";
}
