import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function requireDeviceAuth(ctx: any, deviceId: string, authToken: string) {
  if (!authToken) throw new Error("auth_required");
  const device = await ctx.db
    .query("devices")
    .withIndex("by_device_id", (q: any) => q.eq("device_id", deviceId))
    .first();
  if (!device?.auth_token_hash) throw new Error("device_not_registered");
  if ((await sha256Hex(authToken)) !== device.auth_token_hash) {
    throw new Error("auth_failed");
  }
}

/**
 * Canonical pair ordering helper — always store (smaller, larger) so a pair
 * maps to exactly one row regardless of who calls first.
 */
function orderPair(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a];
}

/**
 * Store the encrypted session key blobs produced after a successful WiFi
 * pairing between two devices.
 *
 * How the key exchange works (high-level):
 *   1. Device A generates an X25519 keypair and publishes its public key in
 *      the `devices` table via `registerDevice`.
 *   2. When A and B first connect over WiFi:
 *      - A fetches B's public key from Convex (or directly from the local
 *        broadcast packet which also carries it).
 *      - A performs ECDH: sharedSecret = ECDH(A_private, B_public).
 *      - A derives a 256-bit key: key = HKDF-SHA256(sharedSecret, "ccp-v0").
 *      - A encrypts the raw 32-byte key with AES-256-GCM using a key
 *        derived from A's own device_id + a local machine secret — this
 *        produces `encrypted_key_a`.  Convex stores it but CANNOT decrypt it.
 *      - B does the symmetric operation, producing `encrypted_key_b`.
 *      - A SHA-256 of the raw shared secret is stored as `key_fingerprint`
 *        so both sides can verify they converged on the same secret.
 *   3. Later, when operating over the cloud relay both sides load their
 *      respective encrypted blob, decrypt it locally, and use the raw key
 *      for AES-GCM encryption of all messages.
 */
export const storeSession = mutation({
  args: {
    device_id_a: v.string(),         // lexicographically smaller device_id
    device_id_b: v.string(),         // lexicographically larger device_id
    caller_device_id: v.string(),
    auth_token: v.string(),
    encrypted_key_a: v.string(),     // base64 blob for device_a
    encrypted_key_b: v.string(),     // base64 blob for device_b
    key_fingerprint: v.string(),     // SHA-256 of the raw shared secret
    paired_via: v.string(),          // "wifi" | "bluetooth" | "manual"
  },
  handler: async (ctx, args) => {
    const [id_a, id_b] = orderPair(args.device_id_a, args.device_id_b);
    if (args.caller_device_id !== id_a && args.caller_device_id !== id_b) {
      throw new Error("caller_not_in_pair");
    }
    await requireDeviceAuth(ctx, args.caller_device_id, args.auth_token);

    // Validate: ensure device_id_a < device_id_b in args too (caller may pass
    // either order; we normalise).
    const existing = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) =>
        q.eq("device_id_a", id_a).eq("device_id_b", id_b)
      )
      .first();

    const now = Date.now();

    if (existing && !existing.revoked) {
      // Session already exists — update encrypted blobs (e.g. key rotation)
      await ctx.db.patch(existing._id, {
        encrypted_key_a: args.encrypted_key_a,
        encrypted_key_b: args.encrypted_key_b,
        key_fingerprint: args.key_fingerprint,
        paired_via: args.paired_via,
        revoked: false,
      });
      return { status: "updated", session_id: existing._id };
    } else if (existing && existing.revoked) {
      // Re-pairing after revocation — overwrite
      await ctx.db.patch(existing._id, {
        encrypted_key_a: args.encrypted_key_a,
        encrypted_key_b: args.encrypted_key_b,
        key_fingerprint: args.key_fingerprint,
        paired_via: args.paired_via,
        established_at: now,
        revoked: false,
      });
      return { status: "reinstated", session_id: existing._id };
    } else {
      const id = await ctx.db.insert("sessions", {
        device_id_a: id_a,
        device_id_b: id_b,
        encrypted_key_a: args.encrypted_key_a,
        encrypted_key_b: args.encrypted_key_b,
        key_fingerprint: args.key_fingerprint,
        established_at: now,
        paired_via: args.paired_via,
        revoked: false,
      });
      return { status: "created", session_id: id };
    }
  },
});

/**
 * Retrieve the session between two devices (if it exists and is not revoked).
 * Each side receives its own encrypted blob — the other side's blob is omitted.
 */
export const getSession = query({
  args: {
    my_device_id: v.string(),
    auth_token: v.string(),
    peer_device_id: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.my_device_id, args.auth_token);
    const [id_a, id_b] = orderPair(args.my_device_id, args.peer_device_id);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) =>
        q.eq("device_id_a", id_a).eq("device_id_b", id_b)
      )
      .first();

    if (!session || session.revoked) return null;

    // Return only the encrypted blob belonging to the caller
    const iAmA = args.my_device_id === id_a;
    return {
      session_id: session._id,
      encrypted_key: iAmA ? session.encrypted_key_a : session.encrypted_key_b,
      key_fingerprint: session.key_fingerprint,
      established_at: session.established_at,
      paired_via: session.paired_via,
    };
  },
});

/**
 * Verify that two devices share the same key fingerprint.
 * Used as a lightweight sanity check without exposing any keys.
 */
export const verifyFingerprint = query({
  args: {
    device_id_a: v.string(),
    device_id_b: v.string(),
    caller_device_id: v.string(),
    auth_token: v.string(),
    expected_fingerprint: v.string(),
  },
  handler: async (ctx, args) => {
    const [id_a, id_b] = orderPair(args.device_id_a, args.device_id_b);
    if (args.caller_device_id !== id_a && args.caller_device_id !== id_b) {
      return { valid: false, reason: "caller_not_in_pair" };
    }
    await requireDeviceAuth(ctx, args.caller_device_id, args.auth_token);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) =>
        q.eq("device_id_a", id_a).eq("device_id_b", id_b)
      )
      .first();

    if (!session || session.revoked) return { valid: false, reason: "no_session" };
    if (session.key_fingerprint !== args.expected_fingerprint) {
      return { valid: false, reason: "fingerprint_mismatch" };
    }
    return { valid: true };
  },
});

/**
 * List all active sessions for a given device (so it knows all its paired peers).
 */
export const listSessions = query({
  args: { device_id: v.string(), auth_token: v.string() },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.device_id, args.auth_token);
    const asA = await ctx.db
      .query("sessions")
      .withIndex("by_device_a", (q) => q.eq("device_id_a", args.device_id))
      .filter((q) => q.eq(q.field("revoked"), false))
      .collect();

    const asB = await ctx.db
      .query("sessions")
      .withIndex("by_device_b", (q) => q.eq("device_id_b", args.device_id))
      .filter((q) => q.eq(q.field("revoked"), false))
      .collect();

    // Combine and return peer device IDs only (no raw key material)
    const peers = [
      ...asA.map((s) => ({
        peer_id: s.device_id_b,
        key_fingerprint: s.key_fingerprint,
        established_at: s.established_at,
        paired_via: s.paired_via,
      })),
      ...asB.map((s) => ({
        peer_id: s.device_id_a,
        key_fingerprint: s.key_fingerprint,
        established_at: s.established_at,
        paired_via: s.paired_via,
      })),
    ];

    return peers;
  },
});

/**
 * Revoke a session (unpair two devices). Encrypted blobs are kept for audit
 * but the `revoked` flag prevents their use.
 */
export const revokeSession = mutation({
  args: {
    device_id_a: v.string(),
    device_id_b: v.string(),
    caller_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    const [id_a, id_b] = orderPair(args.device_id_a, args.device_id_b);
    if (args.caller_device_id !== id_a && args.caller_device_id !== id_b) {
      throw new Error("caller_not_in_pair");
    }
    await requireDeviceAuth(ctx, args.caller_device_id, args.auth_token);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) =>
        q.eq("device_id_a", id_a).eq("device_id_b", id_b)
      )
      .first();

    if (!session) return { status: "not_found" };
    await ctx.db.patch(session._id, { revoked: true });
    return { status: "revoked" };
  },
});
