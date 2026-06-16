import { mutation, query, action } from "./_generated/server";
import { v } from "convex/values";
import { api } from "./_generated/api";

/** Default TTL for cloud relay messages: 48 hours */
const DEFAULT_TTL_MS = 48 * 60 * 60 * 1000;

/**
 * Push an encrypted message into the cloud relay queue.
 *
 * The payload is ALREADY encrypted (AES-256-GCM) by the sender using the
 * shared session key.  Convex stores ciphertext only — zero plaintext
 * visibility.
 *
 * Supported msg_types (mirrors the local TCP protocol):
 *   - "remote.action.request"  — trigger an action on the remote device
 *   - "remote.action.response" — result of a remote action
 *   - "clipboard.sync"         — push clipboard content
 *   - "notification.push"      — mirror a notification
 *   - "file.offer"             — initiate a file transfer (metadata only)
 *   - "file.complete"          — acknowledge file transfer complete
 *   - "heartbeat"              — keep-alive / presence signal
 *   - "command"                — arbitrary JSON command envelope
 */
export const pushMessage = mutation({
  args: {
    sender_id: v.string(),
    recipient_id: v.string(),
    msg_type: v.string(),
    encrypted_payload: v.string(),   // base64 AES-256-GCM ciphertext
    nonce: v.string(),               // base64 nonce (12 bytes)
    msg_id: v.string(),              // client UUID for idempotency
    ttl_ms: v.optional(v.number()),  // custom TTL; defaults to 48h
  },
  handler: async (ctx, args) => {
    // Idempotency check: if a message with this msg_id already exists skip
    const duplicate = await ctx.db
      .query("messages")
      .withIndex("by_msg_id", (q) => q.eq("msg_id", args.msg_id))
      .first();

    if (duplicate) {
      return { status: "duplicate", message_id: duplicate._id };
    }

    const now = Date.now();
    const ttl = args.ttl_ms ?? DEFAULT_TTL_MS;
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
 * Poll undelivered messages for a given recipient.
 * Returns messages in chronological order (oldest first).
 * The caller should ack each message after processing.
 */
export const pollMessages = query({
  args: {
    recipient_id: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const now = Date.now();
    const limit = args.limit ?? 50;

    const messages = await ctx.db
      .query("messages")
      .withIndex("by_recipient", (q) =>
        q.eq("recipient_id", args.recipient_id).eq("delivered", false)
      )
      .order("asc")
      .take(limit);

    // Filter out expired messages (they haven't been purged yet)
    return messages
      .filter((m) => m.expires_at > now)
      .map((m) => ({
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
 * Acknowledge (mark as delivered) a batch of messages.
 * Call this after the recipient has successfully decrypted and processed each
 * message.
 */
export const ackMessages = mutation({
  args: {
    message_ids: v.array(v.id("messages")),
  },
  handler: async (ctx, args) => {
    for (const id of args.message_ids) {
      await ctx.db.patch(id, { delivered: true });
    }
    return { acked: args.message_ids.length };
  },
});

/**
 * Purge expired and delivered messages.
 * Run this from a Convex scheduled function or on-demand.
 */
export const purgeExpiredMessages = mutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();

    // Purge expired
    const expired = await ctx.db
      .query("messages")
      .withIndex("by_expiry", (q) => q.lt("expires_at", now))
      .collect();

    for (const m of expired) {
      await ctx.db.delete(m._id);
    }

    return { purged: expired.length };
  },
});

/**
 * Get pending message count for a device (useful for badge / status display).
 */
export const pendingCount = query({
  args: { recipient_id: v.string() },
  handler: async (ctx, args) => {
    const now = Date.now();
    const msgs = await ctx.db
      .query("messages")
      .withIndex("by_recipient", (q) =>
        q.eq("recipient_id", args.recipient_id).eq("delivered", false)
      )
      .collect();
    return msgs.filter((m) => m.expires_at > now).length;
  },
});
