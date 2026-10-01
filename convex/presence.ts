import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { LIMITS, assertMaxLength, canSee, requireDevice } from "./lib/auth";

/** Heartbeat age after which a device is considered offline: 30 seconds */
const OFFLINE_THRESHOLD_MS = 30_000;

const OFFLINE = { online: false, last_heartbeat: 0, ip_hint: "", tcp_port: 0 };

/**
 * Upsert a presence heartbeat for the caller.
 *
 * ip_hint is an obfuscated partial IP (e.g. "192.168.x.x") that peers can use
 * as a hint before falling back to the cloud relay. The full IP is never stored.
 */
export const heartbeat = mutation({
  args: {
    device_id: v.string(),
    auth_token: v.string(),
    ip_hint: v.string(),
    tcp_port: v.number(),
  },
  handler: async (ctx, args) => {
    const device = await requireDevice(ctx, args.device_id, args.auth_token);
    assertMaxLength("ip_hint", args.ip_hint, LIMITS.ipHint);
    if (!Number.isInteger(args.tcp_port) || args.tcp_port < 0 || args.tcp_port > 65535) {
      throw new Error("invalid_tcp_port");
    }
    const now = Date.now();
    const existing = await ctx.db
      .query("presence")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    const fields = {
      online: true,
      last_heartbeat: now,
      ip_hint: args.ip_hint,
      tcp_port: args.tcp_port,
    };
    if (existing) {
      await ctx.db.patch(existing._id, fields);
    } else {
      await ctx.db.insert("presence", { device_id: args.device_id, ...fields });
    }

    // Keep the registry's last_seen roughly current without a write per beat.
    if (now - device.last_seen > 5 * 60 * 1000) {
      await ctx.db.patch(device._id, { last_seen: now });
    }

    return { status: "ok", server_time: now };
  },
});

/**
 * Mark the caller offline (called on clean shutdown).
 */
export const goOffline = mutation({
  args: { device_id: v.string(), auth_token: v.string() },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.device_id, args.auth_token);
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
 * Presence of a device the caller is paired with (or itself).
 * Unpaired devices always appear offline so presence can't be used to track
 * arbitrary devices.
 */
export const getPresence = query({
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.requester_device_id, args.auth_token);
    if (!(await canSee(ctx, args.requester_device_id, args.device_id))) {
      return { device_id: args.device_id, ...OFFLINE };
    }
    const presence = await ctx.db
      .query("presence")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    if (!presence) return { device_id: args.device_id, ...OFFLINE };

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
 * Bulk presence for paired devices (dashboard).
 */
export const getBulkPresence = query({
  args: {
    device_ids: v.array(v.string()),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.requester_device_id, args.auth_token);
    if (args.device_ids.length > LIMITS.bulkPresenceMax) throw new Error("too_many_device_ids");
    const now = Date.now();
    const results: Record<string, boolean> = {};

    for (const id of args.device_ids) {
      if (!(await canSee(ctx, args.requester_device_id, id))) {
        results[id] = false;
        continue;
      }
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
