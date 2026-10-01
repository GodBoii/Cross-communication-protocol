import type { DatabaseReader } from "../_generated/server";
import type { Doc } from "../_generated/dataModel";

/**
 * Shared authentication and validation helpers for every CCP Convex function.
 *
 * Identity model (v1):
 *   - Each device generates a random 32-byte cloud auth token locally and never
 *     shares it with peers.
 *   - auth_token_hash = sha256_hex(auth_token)                (stored server-side)
 *   - device_id       = sha256_hex("ccp-device-id-v1:" + auth_token_hash)
 *
 * Because device_id is derived from the token hash, a device id cannot be
 * claimed (squatted) by anyone who does not hold the matching token, even
 * though device ids are broadcast in clear on the LAN.
 */

export const DEVICE_ID_PREFIX = "ccp-device-id-v1:";

export const LIMITS = {
  deviceName: 64,
  platform: 16,
  publicKey: 512,
  appVersion: 32,
  capabilities: 32,
  capability: 64,
  msgType: 64,
  msgId: 64,
  nonce: 64,
  encryptedPayload: 512 * 1024,
  encryptedKey: 4096,
  pollMax: 50,
  pollDefault: 20,
  ackMax: 100,
  bulkPresenceMax: 100,
  ipHint: 64,
} as const;

export const ALLOWED_PLATFORMS = new Set([
  "windows",
  "android",
  "macos",
  "linux",
  "ios",
]);

export const ALLOWED_PAIRED_VIA = new Set(["wifi", "lan", "usb", "bluetooth", "manual"]);

const HEX64 = /^[0-9a-f]{64}$/;
const MSG_TYPE = /^[a-z0-9][a-z0-9._-]*$/;

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Constant-time comparison for equal-length strings. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function deviceIdFromTokenHash(tokenHash: string): Promise<string> {
  return sha256Hex(DEVICE_ID_PREFIX + tokenHash);
}

export function assertDeviceId(name: string, value: string): void {
  if (!HEX64.test(value)) throw new Error(`invalid_${name}`);
}

export function assertMaxLength(name: string, value: string, max: number): void {
  if (value.length > max) throw new Error(`${name}_too_long`);
}

export function assertNonEmpty(name: string, value: string): void {
  if (value.trim().length === 0) throw new Error(`${name}_required`);
}

export function assertMsgType(value: string): void {
  assertMaxLength("msg_type", value, LIMITS.msgType);
  if (!MSG_TYPE.test(value)) throw new Error("invalid_msg_type");
}

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

export function orderPair(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a];
}

/**
 * Authenticate a caller. Throws on any failure; returns the device row.
 * Error messages are intentionally coarse so they don't reveal whether a
 * device id exists.
 */
export async function requireDevice(
  ctx: { db: DatabaseReader },
  deviceId: string,
  authToken: string
): Promise<Doc<"devices">> {
  if (!authToken) throw new Error("auth_required");
  if (!HEX64.test(deviceId)) throw new Error("auth_failed");
  const device = await ctx.db
    .query("devices")
    .withIndex("by_device_id", (q) => q.eq("device_id", deviceId))
    .first();
  if (!device?.auth_token_hash) throw new Error("auth_failed");
  const actual = await sha256Hex(authToken);
  if (!timingSafeEqual(actual, device.auth_token_hash)) throw new Error("auth_failed");
  return device;
}

/** Returns the active (non-revoked) session row between two devices, if any. */
export async function activeSession(
  ctx: { db: DatabaseReader },
  a: string,
  b: string
): Promise<Doc<"sessions"> | null> {
  if (a === b) return null;
  const [idA, idB] = orderPair(a, b);
  const session = await ctx.db
    .query("sessions")
    .withIndex("by_pair", (q) => q.eq("device_id_a", idA).eq("device_id_b", idB))
    .first();
  if (!session || session.revoked) return null;
  return session;
}

/** A device may see details of itself and of peers it has an active session with. */
export async function canSee(
  ctx: { db: DatabaseReader },
  requesterId: string,
  targetId: string
): Promise<boolean> {
  if (requesterId === targetId) return true;
  return (await activeSession(ctx, requesterId, targetId)) !== null;
}

/** Ids of every peer the device has an active session with. */
export async function sessionPeerIds(
  ctx: { db: DatabaseReader },
  deviceId: string
): Promise<string[]> {
  const asA = await ctx.db
    .query("sessions")
    .withIndex("by_device_a", (q) => q.eq("device_id_a", deviceId))
    .filter((q) => q.eq(q.field("revoked"), false))
    .take(500);
  const asB = await ctx.db
    .query("sessions")
    .withIndex("by_device_b", (q) => q.eq("device_id_b", deviceId))
    .filter((q) => q.eq(q.field("revoked"), false))
    .take(500);
  return [...asA.map((s) => s.device_id_b), ...asB.map((s) => s.device_id_a)];
}

/** Public projection of a device row: never leak auth_token_hash. */
export function publicDevice(device: Doc<"devices">) {
  return {
    device_id: device.device_id,
    device_name: device.device_name,
    platform: device.platform,
    public_key_b64: device.public_key_b64,
    capabilities: device.capabilities,
    last_seen: device.last_seen,
    app_version: device.app_version,
  };
}
