import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * CCP Convex Schema
 *
 * Tables:
 *  - devices        : registered device identities
 *  - sessions       : encrypted shared-key blobs between two device pairs
 *  - messages       : cloud relay message queue (commands, events, file metadata)
 *  - presence       : lightweight heartbeat / online status
 */
export default defineSchema({
  // ── Device Registry ────────────────────────────────────────────────────────
  // Every device that has ever connected registers itself here.
  // device_id is the SHA-256 fingerprint generated locally on first run.
  devices: defineTable({
    device_id: v.string(),          // local SHA-256 identity (primary key by index)
    device_name: v.string(),         // human-readable label ("Prajwal's Windows PC")
    platform: v.string(),            // "windows" | "android" | "macos" | "linux"
    public_key_b64: v.string(),      // base64 X25519 / ECDH public key
    auth_token_hash: v.optional(v.string()), // SHA-256 of the locally-held cloud auth token
    capabilities: v.array(v.string()), // ["file.transfer", "notifications.list", ...]
    last_seen: v.number(),           // unix timestamp (ms)
    app_version: v.string(),         // "0.2.0" etc.
  })
    .index("by_device_id", ["device_id"])
    .index("by_platform", ["platform"]),

  // ── Session / Key Exchange ──────────────────────────────────────────────────
  // When two devices first connect over WiFi they perform an ECDH key exchange.
  // The resulting shared secret is stored as an AES-256-GCM encrypted blob so
  // both sides can later verify they share the same secret without exposing it.
  //
  // canonical ordering: device_id_a < device_id_b (lexicographic) so the pair
  // is always stored once regardless of who initiated.
  sessions: defineTable({
    device_id_a: v.string(),         // lexicographically smaller device_id
    device_id_b: v.string(),         // lexicographically larger device_id
    // Each side stores its own encrypted copy of the shared secret.
    // The blob is encrypted with the device's own locally-held private key so
    // Convex never sees the plaintext key — it just acts as durable storage.
    encrypted_key_a: v.string(),     // base64 AES-GCM blob for device_a
    encrypted_key_b: v.string(),     // base64 AES-GCM blob for device_b
    key_fingerprint: v.string(),     // SHA-256 of the raw shared secret (for integrity check)
    established_at: v.number(),      // unix ms of first pairing
    paired_via: v.string(),          // "wifi" | "bluetooth" | "manual"
    revoked: v.boolean(),            // if true, this pair is no longer trusted
  })
    .index("by_pair", ["device_id_a", "device_id_b"])
    .index("by_device_a", ["device_id_a"])
    .index("by_device_b", ["device_id_b"]),

  // ── Cloud Message Queue ─────────────────────────────────────────────────────
  // When two devices are NOT on the same network, they push messages here.
  // The recipient polls (or uses Convex real-time subscriptions) to read them.
  // Messages are encrypted with the shared session key so Convex never reads
  // the plaintext payload.
  //
  // This covers: remote actions, file transfer metadata, clipboard, notifications
  messages: defineTable({
    sender_id: v.string(),           // device_id of sender
    recipient_id: v.string(),        // device_id of intended recipient
    msg_type: v.string(),            // CCP message type: "remote.action.request" etc.
    encrypted_payload: v.string(),   // base64 AES-GCM ciphertext of JSON payload
    nonce: v.string(),               // base64 AES-GCM nonce (12 bytes)
    msg_id: v.string(),              // client-generated UUID (idempotency)
    created_at: v.number(),          // unix ms
    delivered: v.boolean(),          // true once recipient acks delivery
    expires_at: v.number(),          // unix ms; messages auto-purge after TTL
  })
    .index("by_recipient", ["recipient_id", "delivered"])
    .index("by_sender", ["sender_id"])
    .index("by_msg_id", ["msg_id"])
    .index("by_expiry", ["expires_at"]),

  // ── Device Presence / Heartbeat ─────────────────────────────────────────────
  // Lightweight ping so the remote side can show "online" status.
  // One row per device, upserted on each heartbeat.
  presence: defineTable({
    device_id: v.string(),
    online: v.boolean(),
    last_heartbeat: v.number(),      // unix ms
    ip_hint: v.string(),             // obfuscated / partial IP hint for direct fallback
    tcp_port: v.number(),
  })
    .index("by_device_id", ["device_id"]),
});
