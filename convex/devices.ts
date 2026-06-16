import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Register or update a device in the global registry.
 * Called by each device on startup and periodically to refresh last_seen.
 */
export const registerDevice = mutation({
  args: {
    device_id: v.string(),
    device_name: v.string(),
    platform: v.string(),
    public_key_b64: v.string(),
    capabilities: v.array(v.string()),
    app_version: v.string(),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    const now = Date.now();

    if (existing) {
      await ctx.db.patch(existing._id, {
        device_name: args.device_name,
        platform: args.platform,
        public_key_b64: args.public_key_b64,
        capabilities: args.capabilities,
        app_version: args.app_version,
        last_seen: now,
      });
      return { status: "updated", device_id: args.device_id };
    } else {
      await ctx.db.insert("devices", {
        ...args,
        last_seen: now,
      });
      return { status: "registered", device_id: args.device_id };
    }
  },
});

/**
 * Look up a single device by its device_id.
 */
export const getDevice = query({
  args: { device_id: v.string() },
  handler: async (ctx, args) => {
    return ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();
  },
});

/**
 * List all registered devices (optionally filter by platform).
 */
export const listDevices = query({
  args: { platform: v.optional(v.string()) },
  handler: async (ctx, args) => {
    if (args.platform) {
      return ctx.db
        .query("devices")
        .withIndex("by_platform", (q) => q.eq("platform", args.platform!))
        .collect();
    }
    return ctx.db.query("devices").collect();
  },
});

/**
 * Get the public key for a specific device (used during key exchange).
 */
export const getPublicKey = query({
  args: { device_id: v.string() },
  handler: async (ctx, args) => {
    const device = await ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();
    if (!device) return null;
    return {
      device_id: device.device_id,
      device_name: device.device_name,
      platform: device.platform,
      public_key_b64: device.public_key_b64,
    };
  },
});
