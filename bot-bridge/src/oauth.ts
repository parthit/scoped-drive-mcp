import { createHash, randomBytes } from "node:crypto";

export const LOGIN_PROVIDERS = ["google", "github", "x"] as const;
export type LoginProvider = (typeof LOGIN_PROVIDERS)[number];

export type OAuthProfile = {
  provider: LoginProvider;
  providerUserId: string;
  label: string;
};

export type OAuthClient = {
  clientId: string;
  clientSecret: string;
};

export type OAuthConfig = Partial<Record<LoginProvider, OAuthClient>>;

export function isLoginProvider(value: string): value is LoginProvider {
  return (LOGIN_PROVIDERS as readonly string[]).includes(value);
}

export function codeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

export function codeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function authorizationUrl(provider: LoginProvider, client: OAuthClient, redirectUri: string, state: string, challenge: string): string {
  if (provider === "google") {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", client.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("prompt", "select_account");
    return url.toString();
  }
  if (provider === "github") {
    const url = new URL("https://github.com/login/oauth/authorize");
    url.searchParams.set("client_id", client.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", "read:user user:email");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
  }
  const url = new URL("https://twitter.com/i/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", client.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", "users.read tweet.read");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function exchangeCode(
  provider: LoginProvider,
  client: OAuthClient,
  redirectUri: string,
  code: string,
  verifier: string,
  fetchImpl: typeof fetch,
): Promise<OAuthProfile> {
  if (provider === "google") {
    const token = await postForm(fetchImpl, "https://oauth2.googleapis.com/token", {
      code,
      client_id: client.clientId,
      client_secret: client.clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: verifier,
    });
    const access = stringField(token, "access_token");
    if (!access) throw new Error("google_token");
    const profile = await getJson(fetchImpl, "https://openidconnect.googleapis.com/v1/userinfo", access);
    const id = stringField(profile, "sub");
    if (!id) throw new Error("google_profile");
    return { provider, providerUserId: id, label: stringField(profile, "email") || stringField(profile, "name") || id };
  }
  if (provider === "github") {
    const token = await postForm(
      fetchImpl,
      "https://github.com/login/oauth/access_token",
      {
        code,
        client_id: client.clientId,
        client_secret: client.clientSecret,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
      { accept: "application/json" },
    );
    const access = stringField(token, "access_token");
    if (!access) throw new Error("github_token");
    const profile = await getJson(fetchImpl, "https://api.github.com/user", access);
    const id = profile.id;
    if (typeof id !== "number" && typeof id !== "string") throw new Error("github_profile");
    const login = stringField(profile, "login");
    return { provider, providerUserId: String(id), label: login || String(id) };
  }
  const token = await postForm(fetchImpl, "https://api.twitter.com/2/oauth2/token", {
    code,
    client_id: client.clientId,
    client_secret: client.clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: verifier,
  });
  const access = stringField(token, "access_token");
  if (!access) throw new Error("x_token");
  const profile = await getJson(fetchImpl, "https://api.twitter.com/2/users/me", access);
  const data = profile.data;
  if (!data || typeof data !== "object") throw new Error("x_profile");
  const id = stringField(data as Record<string, unknown>, "id");
  if (!id) throw new Error("x_profile");
  const username = stringField(data as Record<string, unknown>, "username");
  return { provider, providerUserId: id, label: username || id };
}

async function postForm(fetchImpl: typeof fetch, url: string, fields: Record<string, string>, headers: Record<string, string> = {}): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(fields),
  });
  if (!response.ok) throw new Error("oauth_token");
  return (await response.json()) as Record<string, unknown>;
}

async function getJson(fetchImpl: typeof fetch, url: string, accessToken: string): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url, { headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" } });
  if (!response.ok) throw new Error("oauth_profile");
  return (await response.json()) as Record<string, unknown>;
}

function stringField(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  return typeof value === "string" ? value : "";
}
