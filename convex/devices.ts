import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function requireDeviceAuth(
  ctx: any,
  deviceId: string,
  authToken: string
) {
  if (!authToken) throw new Error("auth_required");
  const device = await ctx.db
    .query("devices")
    .withIndex("by_device_id", (q: any) => q.eq("device_id", deviceId))
    .first();
  if (!device?.auth_token_hash) throw new Error("device_not_registered");
  const actual = await sha256Hex(authToken);
  if (actual !== device.auth_token_hash) throw new Error("auth_failed");
  return device;
}

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
    auth_token_hash: v.string(),
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
      if (
        existing.auth_token_hash != null &&
        existing.auth_token_hash !== args.auth_token_hash
      ) {
        throw new Error("auth_token_mismatch");
      }
      await ctx.db.patch(existing._id, {
        device_name: args.device_name,
        platform: args.platform,
        public_key_b64: args.public_key_b64,
        auth_token_hash: args.auth_token_hash,
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
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.requester_device_id, args.auth_token);
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
  args: {
    platform: v.optional(v.string()),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.requester_device_id, args.auth_token);
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
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDeviceAuth(ctx, args.requester_device_id, args.auth_token);
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
