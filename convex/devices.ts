import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  ALLOWED_PLATFORMS,
  LIMITS,
  assertDeviceId,
  assertMaxLength,
  assertNonEmpty,
  canSee,
  deviceIdFromTokenHash,
  publicDevice,
  requireDevice,
  sessionPeerIds,
  sha256Hex,
  timingSafeEqual,
} from "./lib/auth";

/**
 * Register or update a device in the global registry.
 * Called by each device on startup and periodically to refresh last_seen.
 *
 * The caller proves ownership of `device_id` by presenting the raw auth token:
 * device_id must equal sha256("ccp-device-id-v1:" + sha256(auth_token)).
 */
export const registerDevice = mutation({
  args: {
    device_id: v.string(),
    device_name: v.string(),
    platform: v.string(),
    public_key_b64: v.string(),
    auth_token: v.string(),
    capabilities: v.array(v.string()),
    app_version: v.string(),
  },
  handler: async (ctx, args) => {
    assertDeviceId("device_id", args.device_id);
    assertNonEmpty("auth_token", args.auth_token);
    assertMaxLength("auth_token", args.auth_token, 128);
    assertNonEmpty("device_name", args.device_name);
    assertMaxLength("device_name", args.device_name, LIMITS.deviceName);
    if (!ALLOWED_PLATFORMS.has(args.platform)) throw new Error("invalid_platform");
    assertMaxLength("public_key_b64", args.public_key_b64, LIMITS.publicKey);
    assertMaxLength("app_version", args.app_version, LIMITS.appVersion);
    if (args.capabilities.length > LIMITS.capabilities) throw new Error("too_many_capabilities");
    for (const capability of args.capabilities) {
      assertMaxLength("capability", capability, LIMITS.capability);
    }

    const tokenHash = await sha256Hex(args.auth_token);
    const expectedId = await deviceIdFromTokenHash(tokenHash);
    if (!timingSafeEqual(expectedId, args.device_id)) {
      throw new Error("device_id_not_bound_to_token");
    }

    const existing = await ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();

    const now = Date.now();
    const fields = {
      device_name: args.device_name.trim(),
      platform: args.platform,
      public_key_b64: args.public_key_b64,
      auth_token_hash: tokenHash,
      capabilities: args.capabilities,
      app_version: args.app_version,
      last_seen: now,
    };

    if (existing) {
      await ctx.db.patch(existing._id, fields);
      return { status: "updated", device_id: args.device_id };
    }
    await ctx.db.insert("devices", { device_id: args.device_id, ...fields });
    return { status: "registered", device_id: args.device_id };
  },
});

/**
 * Look up a single device. Only the device itself or a peer with an active
 * session may read it; the auth token hash is never returned.
 */
export const getDevice = query({
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.requester_device_id, args.auth_token);
    if (!(await canSee(ctx, args.requester_device_id, args.device_id))) return null;
    const device = await ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();
    return device ? publicDevice(device) : null;
  },
});

/**
 * List the caller and every device it has an active session with
 * (optionally filtered by platform). The registry is not globally enumerable.
 */
export const listDevices = query({
  args: {
    platform: v.optional(v.string()),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    const self = await requireDevice(ctx, args.requester_device_id, args.auth_token);
    const peerIds = await sessionPeerIds(ctx, args.requester_device_id);
    const devices = [self];
    for (const peerId of peerIds) {
      const device = await ctx.db
        .query("devices")
        .withIndex("by_device_id", (q) => q.eq("device_id", peerId))
        .first();
      if (device) devices.push(device);
    }
    return devices
      .filter((d) => !args.platform || d.platform === args.platform)
      .map(publicDevice);
  },
});

/**
 * Get the public key for a specific device. Public keys are not secret, so any
 * authenticated device may fetch one (needed before a session exists).
 */
export const getPublicKey = query({
  args: {
    device_id: v.string(),
    requester_device_id: v.string(),
    auth_token: v.string(),
  },
  handler: async (ctx, args) => {
    await requireDevice(ctx, args.requester_device_id, args.auth_token);
    const device = await ctx.db
      .query("devices")
      .withIndex("by_device_id", (q) => q.eq("device_id", args.device_id))
      .first();
    if (!device) return null;
    return {
      device_id: device.device_id,
      platform: device.platform,
      public_key_b64: device.public_key_b64,
    };
  },
});
