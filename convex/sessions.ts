import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  ALLOWED_PAIRED_VIA,
  LIMITS,
  assertDeviceId,
  assertMaxLength,
  orderPair,
  requireDevice,
} from "./lib/auth";

/**
 * Sessions record that two devices have paired.
 *
 * How keys work (v1):
 *   1. Two devices pair on the LAN with an ephemeral ECDH P-256 exchange and a
 *      user-verified 6-digit comparison code. Both derive the same 32-byte
 *      pair secret; it never leaves either device.
 *   2. Each side derives the cloud session key locally:
 *        key = HKDF-SHA256(pair_secret, info = "ccp-session-v1|" + idA + "|" + idB)
 *   3. This table only stores an opaque wrapped copy of that key (encrypted
 *      under a key derived from the pair secret) plus its fingerprint, so
 *      Convex can never decrypt relay traffic.
 */
export const storeSession = mutation({
  args: {
    device_id_a: v.string(),
    device_id_b: v.string(),
    caller_device_id: v.string(),
    auth_token: v.string(),
    encrypted_key_a: v.string(),
    encrypted_key_b: v.string(),
    key_fingerprint: v.string(),
    paired_via: v.string(),
  },
  handler: async (ctx, args) => {
    assertDeviceId("device_id_a", args.device_id_a);
    assertDeviceId("device_id_b", args.device_id_b);
    if (args.device_id_a === args.device_id_b) throw new Error("cannot_pair_with_self");
    assertMaxLength("encrypted_key_a", args.encrypted_key_a, LIMITS.encryptedKey);
    assertMaxLength("encrypted_key_b", args.encrypted_key_b, LIMITS.encryptedKey);
    if (!/^[0-9a-f]{64}$/.test(args.key_fingerprint)) throw new Error("invalid_key_fingerprint");
    if (!ALLOWED_PAIRED_VIA.has(args.paired_via)) throw new Error("invalid_paired_via");

    const [id_a, id_b] = orderPair(args.device_id_a, args.device_id_b);
    if (args.caller_device_id !== id_a && args.caller_device_id !== id_b) {
      throw new Error("caller_not_in_pair");
    }
    await requireDevice(ctx, args.caller_device_id, args.auth_token);

    // Each caller may only replace its own wrapped blob; the peer's blob is
    // preserved so one side cannot clobber the other's copy.
    const callerIsA = args.caller_device_id === id_a;
    const ownBlob = callerIsA ? args.encrypted_key_a : args.encrypted_key_b;

    const existing = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) => q.eq("device_id_a", id_a).eq("device_id_b", id_b))
      .first();

    const now = Date.now();

    if (existing) {
      const fingerprintChanged = existing.key_fingerprint !== args.key_fingerprint;
      await ctx.db.patch(existing._id, {
        encrypted_key_a: callerIsA
          ? ownBlob
          : fingerprintChanged ? args.encrypted_key_a : existing.encrypted_key_a,
        encrypted_key_b: !callerIsA
          ? ownBlob
          : fingerprintChanged ? args.encrypted_key_b : existing.encrypted_key_b,
        key_fingerprint: args.key_fingerprint,
        paired_via: args.paired_via,
        established_at: existing.revoked || fingerprintChanged ? now : existing.established_at,
        revoked: false,
      });
      return {
        status: existing.revoked ? "reinstated" : "updated",
        session_id: existing._id,
      };
    }

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
  },
});

/**
 * Retrieve the session between two devices (if it exists and is not revoked).
 * Each side receives only its own wrapped blob.
 */
export const getSession = query({
  args: {
    my_device_id: v.string(),
    auth_token: v.string(),
    peer_device_id: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.my_device_id, args.auth_token);
    if (args.my_device_id === args.peer_device_id) return null;
    const [id_a, id_b] = orderPair(args.my_device_id, args.peer_device_id);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) => q.eq("device_id_a", id_a).eq("device_id_b", id_b))
      .first();

    if (!session || session.revoked) return null;

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
    await requireDevice(ctx, args.caller_device_id, args.auth_token);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) => q.eq("device_id_a", id_a).eq("device_id_b", id_b))
      .first();

    if (!session || session.revoked) return { valid: false, reason: "no_session" };
    if (session.key_fingerprint !== args.expected_fingerprint) {
      return { valid: false, reason: "fingerprint_mismatch" };
    }
    return { valid: true };
  },
});

/**
 * List all active sessions for a device (so it knows its paired peers).
 */
export const listSessions = query({
  args: { device_id: v.string(), auth_token: v.string() },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.device_id, args.auth_token);
    const asA = await ctx.db
      .query("sessions")
      .withIndex("by_device_a", (q) => q.eq("device_id_a", args.device_id))
      .filter((q) => q.eq(q.field("revoked"), false))
      .take(500);

    const asB = await ctx.db
      .query("sessions")
      .withIndex("by_device_b", (q) => q.eq("device_id_b", args.device_id))
      .filter((q) => q.eq(q.field("revoked"), false))
      .take(500);

    return [
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
  },
});

/**
 * Revoke a session (unpair two devices). Wrapped blobs are wiped so a revoked
 * session cannot be resurrected from stored material.
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
    await requireDevice(ctx, args.caller_device_id, args.auth_token);
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_pair", (q) => q.eq("device_id_a", id_a).eq("device_id_b", id_b))
      .first();

    if (!session) return { status: "not_found" };
    await ctx.db.patch(session._id, {
      revoked: true,
      encrypted_key_a: "",
      encrypted_key_b: "",
    });

    // Drop any queued relay traffic between the two devices.
    for (const [from, to] of [
      [id_a, id_b],
      [id_b, id_a],
    ]) {
      const queued = await ctx.db
        .query("messages")
        .withIndex("by_recipient", (q) => q.eq("recipient_id", to).eq("delivered", false))
        .filter((q) => q.eq(q.field("sender_id"), from))
        .take(500);
      for (const message of queued) await ctx.db.delete(message._id);
    }
    return { status: "revoked" };
  },
});
