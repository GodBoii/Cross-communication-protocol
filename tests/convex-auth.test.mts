// Unit tests for the pure helpers in convex/lib/auth.ts.
// Lives outside convex/ so it is never deployed. Run with: npm run test:convex
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  assertDeviceId,
  assertMsgType,
  clamp,
  deviceIdFromTokenHash,
  orderPair,
  publicDevice,
  sha256Hex,
  timingSafeEqual,
} from "../convex/lib/auth.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../shared/test-vectors/ccp-crypto-v1.json", import.meta.url), "utf8")
);

test("device id derivation matches the Android/Windows vectors", async () => {
  const { auth_token, auth_token_hash, device_id } = vectors.device_id;
  assert.equal(await sha256Hex(auth_token), auth_token_hash);
  assert.equal(await deviceIdFromTokenHash(auth_token_hash), device_id);
});

test("timingSafeEqual compares exactly", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
});

test("assertDeviceId accepts only lowercase 64-hex", () => {
  assertDeviceId("id", "a".repeat(64));
  assert.throws(() => assertDeviceId("id", "A".repeat(64)), /invalid_id/);
  assert.throws(() => assertDeviceId("id", "a".repeat(63)), /invalid_id/);
});

test("assertMsgType rejects odd message types", () => {
  assertMsgType("remote.action.request");
  assert.throws(() => assertMsgType("Remote Action"), /invalid_msg_type/);
  assert.throws(() => assertMsgType("x".repeat(65)), /msg_type_too_long/);
});

test("clamp bounds numbers and rejects NaN", () => {
  assert.equal(clamp(5, 1, 10), 5);
  assert.equal(clamp(50, 1, 10), 10);
  assert.equal(clamp(-1, 1, 10), 1);
  assert.equal(clamp(Number.NaN, 1, 10), 1);
});

test("orderPair is canonical", () => {
  assert.deepEqual(orderPair("b", "a"), ["a", "b"]);
  assert.deepEqual(orderPair("a", "b"), ["a", "b"]);
});

test("publicDevice never exposes the auth token hash", () => {
  const projected = publicDevice({
    _id: "x" as never,
    _creationTime: 0,
    device_id: "d",
    device_name: "n",
    platform: "android",
    public_key_b64: "",
    auth_token_hash: "secret",
    capabilities: [],
    last_seen: 1,
    app_version: "1",
  });
  assert.equal("auth_token_hash" in projected, false);
});
