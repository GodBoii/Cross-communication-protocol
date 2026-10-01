import { internalMutation, mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import {
  LIMITS,
  activeSession,
  assertDeviceId,
  assertMaxLength,
  assertMsgType,
  assertNonEmpty,
  clamp,
  requireDevice,
} from "./lib/auth";

/** Default TTL for cloud relay messages: 48 hours */
const DEFAULT_TTL_MS = 48 * 60 * 60 * 1000;
const MIN_TTL_MS = 10 * 1000;
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PURGE_BATCH = 256;

/**
 * Push an encrypted message into the cloud relay queue.
 *
 * The payload is already AES-256-GCM encrypted by the sender with the pair's
 * session key; the sender binds sender/recipient/msg_type/msg_id as AAD so the
 * relay cannot re-label or redirect ciphertext. Convex stores ciphertext only.
 *
 * Only devices with an active session may message each other.
 */
export const pushMessage = mutation({
  args: {
    sender_id: v.string(),
    auth_token: v.string(),
    recipient_id: v.string(),
    msg_type: v.string(),
    encrypted_payload: v.string(),
    nonce: v.string(),
    msg_id: v.string(),
    ttl_ms: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.sender_id, args.auth_token);
    assertDeviceId("recipient_id", args.recipient_id);
    assertMsgType(args.msg_type);
    assertNonEmpty("msg_id", args.msg_id);
    assertMaxLength("msg_id", args.msg_id, LIMITS.msgId);
    assertNonEmpty("nonce", args.nonce);
    assertMaxLength("nonce", args.nonce, LIMITS.nonce);
    assertNonEmpty("encrypted_payload", args.encrypted_payload);
    assertMaxLength("encrypted_payload", args.encrypted_payload, LIMITS.encryptedPayload);

    if (!(await activeSession(ctx, args.sender_id, args.recipient_id))) {
      throw new Error("no_session");
    }

    // Idempotency is scoped per sender so one device cannot suppress another
    // device's messages by pre-claiming its msg_id.
    const duplicate = await ctx.db
      .query("messages")
      .withIndex("by_msg_id", (q) => q.eq("msg_id", args.msg_id))
      .filter((q) => q.eq(q.field("sender_id"), args.sender_id))
      .first();
    if (duplicate) {
      return { status: "duplicate", message_id: duplicate._id };
    }

    const now = Date.now();
    const ttl = clamp(args.ttl_ms ?? DEFAULT_TTL_MS, MIN_TTL_MS, MAX_TTL_MS);
    const id = await ctx.db.insert("messages", {
      sender_id: args.sender_id,
      recipient_id: args.recipient_id,
      msg_type: args.msg_type,
      encrypted_payload: args.encrypted_payload,
      nonce: args.nonce,
      msg_id: args.msg_id,
      created_at: now,
      delivered: false,
      expires_at: now + ttl,
    });

    return { status: "queued", message_id: id };
  },
});

/**
 * Poll undelivered, unexpired messages for the caller, oldest first.
 * The caller acks each message after it has been processed.
 */
export const pollMessages = query({
  args: {
    recipient_id: v.string(),
    auth_token: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.recipient_id, args.auth_token);
    const now = Date.now();
    const limit = clamp(args.limit ?? LIMITS.pollDefault, 1, LIMITS.pollMax);

    const messages = await ctx.db
      .query("messages")
      .withIndex("by_recipient", (q) =>
        q.eq("recipient_id", args.recipient_id).eq("delivered", false)
      )
      .order("asc")
      .filter((q) => q.gt(q.field("expires_at"), now))
      .take(limit);

    return messages.map((m) => ({
      message_id: m._id,
      sender_id: m.sender_id,
      msg_type: m.msg_type,
      encrypted_payload: m.encrypted_payload,
      nonce: m.nonce,
      msg_id: m.msg_id,
      created_at: m.created_at,
    }));
  },
});

/**
 * Acknowledge a batch of messages. Acked messages are deleted immediately so
 * ciphertext does not linger on the relay.
 */
export const ackMessages = mutation({
  args: {
    recipient_id: v.string(),
    auth_token: v.string(),
    message_ids: v.array(v.id("messages")),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.recipient_id, args.auth_token);
    if (args.message_ids.length > LIMITS.ackMax) throw new Error("too_many_message_ids");
    let acked = 0;
    for (const id of args.message_ids) {
      const message = await ctx.db.get(id);
      if (message && message.recipient_id === args.recipient_id) {
        await ctx.db.delete(id);
        acked++;
      }
    }
    return { acked };
  },
});

/**
 * Purge expired messages in bounded batches. Internal only: scheduled by the
 * hourly cron and re-schedules itself while a backlog remains.
 */
export const purgeExpiredMessages = internalMutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const expired = await ctx.db
      .query("messages")
      .withIndex("by_expiry", (q) => q.lt("expires_at", now))
      .take(PURGE_BATCH);

    for (const m of expired) {
      await ctx.db.delete(m._id);
    }

    if (expired.length === PURGE_BATCH) {
      await ctx.scheduler.runAfter(0, internal.messages.purgeExpiredMessages, {});
    }
    return { purged: expired.length };
  },
});

/**
 * Pending message count for the caller (capped, for badge display).
 */
export const pendingCount = query({
  args: { recipient_id: v.string(), auth_token: v.string() },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.recipient_id, args.auth_token);
    const now = Date.now();
    const msgs = await ctx.db
      .query("messages")
      .withIndex("by_recipient", (q) =>
        q.eq("recipient_id", args.recipient_id).eq("delivered", false)
      )
      .filter((q) => q.gt(q.field("expires_at"), now))
      .take(100);
    // Documents carry ciphertext, so the scan is capped; 100 means "100+".
    return msgs.length;
  },
});
