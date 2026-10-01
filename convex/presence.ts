import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/** Heartbeat interval after which a device is considered offline: 30 seconds */
const OFFLINE_THRESHOLD_MS = 30_000;

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
 * Upsert a presence heartbeat for a device.
 * Each device should call this every ~10 seconds while running.
 *
 * ip_hint is an *obfuscated* partial IP (e.g. first two octets only) that
 * the peer can use as a fallback hint to attempt a direct connection before
 * falling through to the full cloud relay.  We deliberately don't store the
 * full IP — the peer still needs to perform discovery for the exact address.
 */
export const heartbeat = mutation({
  args: {
    device_id: v.string(),
    auth_token: v.string(),
    ip_hint: v.string(),       // e.g. "192.168.x.x" or blank
    tcp_port: v.number(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.device_id, args.auth_token);
    const now = Date.now();
    const existing = await ctx.db
      .query("presence")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        online: true,
        last_heartbeat: now,
        ip_hint: args.ip_hint,
        tcp_port: args.tcp_port,
      });
    } else {
      await ctx.db.insert("presence", {
        device_id: args.device_id,
        online: true,
        last_heartbeat: now,
        ip_hint: args.ip_hint,
        tcp_port: args.tcp_port,
      });
    }

    return { status: "ok", server_time: now };
  },
});

/**
 * Mark a device as offline (called on clean shutdown).
 */
export const goOffline = mutation({
  args: { device_id: v.string(), auth_token: v.string() },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.device_id, args.auth_token);
    const existing = await ctx.db
      .query("presence")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, { online: false });
    }
    return { status: "offline" };
  },
});

/**
 * Get the presence status of a specific device.
 * Returns online=false if the last heartbeat is older than OFFLINE_THRESHOLD_MS.
 */
export const getPresence = query({
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.requester_device_id, args.auth_token);
    const presence = await ctx.db
      .query("presence")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    if (!presence) return { device_id: args.device_id, online: false, last_heartbeat: 0, ip_hint: "", tcp_port: 0 };

    const effectivelyOnline =
      presence.online && Date.now() - presence.last_heartbeat < OFFLINE_THRESHOLD_MS;

    return {
      device_id: presence.device_id,
      online: effectivelyOnline,
      last_heartbeat: presence.last_heartbeat,
      ip_hint: presence.ip_hint,
      tcp_port: presence.tcp_port,
    };
  },
});

/**
 * Get presence for all devices in a list (bulk fetch for dashboard).
 */
export const getBulkPresence = query({
  args: {
    device_ids: v.array(v.string()),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.requester_device_id, args.auth_token);
    const now = Date.now();
    const results: Record<string, boolean> = {};

    for (const id of args.device_ids) {
      const presence = await ctx.db
        .query("presence")
        .withIndex("by_device_id", (q) => q.eq("device_id", id))
        .first();

      results[id] =
        presence != null &&
        presence.online &&
        now - presence.last_heartbeat < OFFLINE_THRESHOLD_MS;
    }

    return results;
  },
});
