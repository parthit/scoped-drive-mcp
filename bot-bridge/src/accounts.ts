import { newId } from "./ids.js";
import type { OAuthProfile } from "./oauth.js";
import { err, ok, type Result } from "./result.js";
import type { Store } from "./store/types.js";

export class Accounts {
  constructor(
    private readonly store: Store,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async completeLogin(profile: OAuthProfile, sessionUserId: string | null): Promise<Result<{ user_id: string; created: boolean }>> {
    const label = cleanLabel(profile.label) || profile.providerUserId;
    return this.store.transaction(async (tx) => {
      const existing = await tx.findIdentity(profile.provider, profile.providerUserId);
      if (existing) {
        if (sessionUserId && sessionUserId !== existing.user_id) {
          return err("identity_taken", "That login already belongs to another account.");
        }
        return ok({ user_id: existing.user_id, created: false });
      }
      let userId = sessionUserId;
      let created = false;
      if (!userId) {
        userId = newId("usr");
        await tx.insertUser({ user_id: userId, email: null, created_at: this.now() });
        created = true;
      } else if (!(await tx.findUser(userId))) {
        return err("account_required", "Sign in again before linking a login.");
      }
      const inserted = await tx.insertIdentity({
        provider: profile.provider,
        provider_user_id: profile.providerUserId,
        user_id: userId,
        label,
        created_at: this.now(),
      });
      if (inserted === "conflict") return err("identity_taken", "That login already belongs to another account.");
      return ok({ user_id: userId, created });
    });
  }
}

function cleanLabel(value: string): string {
  return value.replace(/[\u0000-\u001f]/g, "").trim().slice(0, 200);
}
