// Generates shared/test-vectors/ccp-crypto-v1.json using Node's crypto module,
// an implementation independent of the Kotlin and C# clients. Both client test
// suites load the JSON and must reproduce every value byte for byte.
//
// Usage: node shared/test-vectors/generate.mjs
// Re-running regenerates the EC key pairs, so commit the output once.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const b64 = (buf) => Buffer.from(buf).toString("base64");
const hex = (buf) => Buffer.from(buf).toString("hex");
const sha256 = (data) => crypto.createHash("sha256").update(data).digest();
const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from(info, "utf8"), len));
const hmac = (key, data) => crypto.createHmac("sha256", key).update(data).digest();
const fill = (len, start) => Buffer.from(Array.from({ length: len }, (_, i) => (start + i) & 0xff));

function seal(key, nonce, aad, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

function frameNonce(counter) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  return nonce;
}

// ── HKDF (RFC 5869 test case 1 plus an empty-salt case) ────────────────────
const hkdfCases = [
  {
    ikm_hex: "0b".repeat(22),
    salt_hex: "000102030405060708090a0b0c",
    info: "ccp-test",
    length: 42,
  },
  { ikm_hex: "0b".repeat(22), salt_hex: "", info: "ccp-empty-salt", length: 32 },
].map((c) => ({
  ...c,
  okm_hex: hex(hkdf(Buffer.from(c.ikm_hex, "hex"), Buffer.from(c.salt_hex, "hex"), c.info, c.length)),
}));

// ── ECDH P-256 ──────────────────────────────────────────────────────────────
const a = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const b = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const exportKeys = (kp) => ({
  pkcs8: kp.privateKey.export({ type: "pkcs8", format: "der" }),
  spki: kp.publicKey.export({ type: "spki", format: "der" }),
});
const ka = exportKeys(a);
const kb = exportKeys(b);
const shared = crypto.diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey });

// ── Pairing ─────────────────────────────────────────────────────────────────
const initiatorId = hex(sha256("initiator"));
const responderId = hex(sha256("responder"));
const nI = fill(16, 0x10);
const nR = fill(16, 0x40);
const commitment = hex(sha256(`ccp-pair-commit-v1|${b64(ka.spki)}|${b64(nI)}`));
const transcriptHash = sha256(
  `ccp-pair-v1|${initiatorId}|${responderId}|${b64(ka.spki)}|${b64(kb.spki)}|${b64(nI)}|${b64(nR)}`
);
const pairSecret = hkdf(shared, transcriptHash, "ccp-pair-secret-v1", 32);
const sas = String(hkdf(shared, transcriptHash, "ccp-pair-sas-v1", 4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
const confirmKey = hkdf(shared, transcriptHash, "ccp-pair-confirm-v1", 32);
const responderConfirm = hmac(confirmKey, Buffer.from("responder", "utf8"));

// ── LAN secure channel ──────────────────────────────────────────────────────
const cn = fill(16, 0x80);
const sn = fill(16, 0xa0);
const lanSalt = sha256(`ccp-lan-v1|${initiatorId}|${responderId}|${b64(cn)}|${b64(sn)}`);
const c2s = hkdf(pairSecret, lanSalt, "ccp-lan-c2s-v1", 32);
const s2c = hkdf(pairSecret, lanSalt, "ccp-lan-s2c-v1", 32);
const frames = [
  { direction: "c2s", counter: 0, plaintext: '{"type":"device.snapshot.request"}' },
  { direction: "c2s", counter: 1, plaintext: "second frame" },
  { direction: "s2c", counter: 0, plaintext: '{"type":"device.snapshot.response","payload":{}}' },
].map((f) => ({
  ...f,
  sealed_b64: b64(
    seal(
      f.direction === "c2s" ? c2s : s2c,
      frameNonce(f.counter),
      Buffer.from(`ccp-lan-frame-v1|${f.direction}|${f.counter}`, "utf8"),
      Buffer.from(f.plaintext, "utf8")
    )
  ),
}));

// ── Cloud relay ─────────────────────────────────────────────────────────────
const [idA, idB] = [initiatorId, responderId].sort();
const cloudKey = hkdf(pairSecret, Buffer.alloc(0), `ccp-cloud-key-v1|${idA}|${idB}`, 32);
const wrapKey = hkdf(pairSecret, Buffer.alloc(0), `ccp-cloud-wrap-v1|${idA}|${idB}`, 32);
const cloudMsg = {
  sender_id: initiatorId,
  recipient_id: responderId,
  msg_type: "remote.action.request",
  msg_id: "00000000-0000-4000-8000-000000000001",
  nonce_b64: b64(fill(12, 0xc0)),
  plaintext: '{"action":"settings.wifi"}',
};
const cloudAad = `ccp-cloud-msg-v1|${cloudMsg.sender_id}|${cloudMsg.recipient_id}|${cloudMsg.msg_type}|${cloudMsg.msg_id}`;
cloudMsg.aad = cloudAad;
cloudMsg.ciphertext_b64 = b64(
  seal(cloudKey, fill(12, 0xc0), Buffer.from(cloudAad, "utf8"), Buffer.from(cloudMsg.plaintext, "utf8"))
);

const vectors = {
  version: 1,
  generator: "shared/test-vectors/generate.mjs (Node crypto)",
  hkdf: hkdfCases,
  ecdh: {
    a_pkcs8_b64: b64(ka.pkcs8),
    a_spki_b64: b64(ka.spki),
    b_pkcs8_b64: b64(kb.pkcs8),
    b_spki_b64: b64(kb.spki),
    shared_hex: hex(shared),
  },
  pairing: {
    initiator_id: initiatorId,
    responder_id: responderId,
    initiator_pub_b64: b64(ka.spki),
    responder_pub_b64: b64(kb.spki),
    initiator_nonce_b64: b64(nI),
    responder_nonce_b64: b64(nR),
    shared_hex: hex(shared),
    commitment_hex: commitment,
    transcript_hash_hex: hex(transcriptHash),
    pair_secret_b64: b64(pairSecret),
    sas,
    responder_confirm_b64: b64(responderConfirm),
  },
  lan_channel: {
    pair_secret_b64: b64(pairSecret),
    client_id: initiatorId,
    server_id: responderId,
    client_nonce_b64: b64(cn),
    server_nonce_b64: b64(sn),
    c2s_key_hex: hex(c2s),
    s2c_key_hex: hex(s2c),
    frames,
  },
  cloud: {
    pair_secret_b64: b64(pairSecret),
    device_a: idA,
    device_b: idB,
    cloud_key_hex: hex(cloudKey),
    wrap_key_hex: hex(wrapKey),
    fingerprint_hex: hex(sha256(cloudKey)),
    message: cloudMsg,
  },
  device_id: {
    auth_token: "dGVzdC1jbG91ZC1hdXRoLXRva2VuLTMyLWJ5dGVzISE=",
  },
};
const tokenHash = hex(sha256(vectors.device_id.auth_token));
vectors.device_id.auth_token_hash = tokenHash;
vectors.device_id.device_id = hex(sha256(`ccp-device-id-v1:${tokenHash}`));

fs.writeFileSync(path.join(here, "ccp-crypto-v1.json"), JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote ccp-crypto-v1.json");
