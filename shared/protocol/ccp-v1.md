# CCP Protocol v1

v1 replaces v0's trust model. In v0 any LAN host could claim a paired device's
id, pair secrets crossed the network in clear, and cloud keys were derivable
from public ids. v1 is **not wire-compatible** with v0; peers paired under v0
must pair again.

Reference implementations: `android/.../CcpCrypto.kt`, `LanPairing.kt`,
`LanSession.kt` and `windows/native-csharp/Services/CcpCrypto.cs`,
`LanPairing.cs`, `LanSession.cs`. Both are verified against
[`shared/test-vectors/ccp-crypto-v1.json`](../test-vectors/ccp-crypto-v1.json),
generated independently with Node (`node shared/test-vectors/generate.mjs`).

## Constants

| Item | Value |
| --- | --- |
| Protocol string | `ccp.v1` |
| UDP discovery port | `47827` |
| TCP session port | `47828` |
| Framing | UTF-8 JSON + `\n`, max 512 KiB per frame |
| TCP idle timeout | 90 s |
| Chunk size | 64 KiB (receivers accept 1 B – 256 KiB) |
| Max file size | 4 GiB LAN, 100 MiB cloud relay |

Notation: `H` = SHA-256, `HKDF(ikm, salt, info, len)` = RFC 5869 HKDF-SHA256
(empty salt = 32 zero bytes), `b64` = standard base64, `|` = literal pipe in a
UTF-8 string. AES-GCM output is `ciphertext || 16-byte tag`.

## Device identity

Each device generates a random 32-byte `auth_token` once and keeps it secret
(Android Keystore / Windows DPAPI).

```
auth_token_hash = hex(H(auth_token_b64))
device_id       = hex(H("ccp-device-id-v1:" + auth_token_hash))   // 64 lowercase hex
```

Convex recomputes this on `registerDevice`, so a device id can only be
registered by the holder of its token. On the LAN, ids are only labels; trust
comes from the pair secret.

## Discovery

UDP broadcast every 3 s, same shape as v0 with `"protocol": "ccp.v1"`.
Receivers drop packets whose `device_id` isn't 64-hex. Peers not heard from
for 20 s are removed from the list.

## Envelope

```json
{ "protocol": "ccp.v1", "id": "uuid", "type": "…",
  "sender": { "device_id": "…", "device_name": "…", "platform": "android" },
  "payload": {}, "timestamp": 1777200000 }
```

The first frame on every TCP connection is a plain-text envelope of type
`pair.request` or `session.hello`. Anything else gets
`session.error {reason: "secure_session_required"}` and the connection closes.

## Pairing (numeric comparison with commitment)

Each attempt uses fresh P-256 keys (`pub` = X.509 SubjectPublicKeyInfo DER)
and 16-byte nonces. I = initiator, R = responder.

```
I → R  pair.request    { version: 1, commitment: hex(H("ccp-pair-commit-v1|" + b64(pubI) + "|" + b64(nI))) }
R → I  pair.challenge  { ephemeral_pub: b64(pubR), nonce: b64(nR) }
I → R  pair.reveal     { ephemeral_pub: b64(pubI), nonce: b64(nI) }
       R verifies the commitment, then both compute:
         Z  = ECDH(priv, peerPub)                       // 32-byte x-coordinate
         T  = H("ccp-pair-v1|" + idI + "|" + idR + "|" + b64(pubI) + "|" + b64(pubR) + "|" + b64(nI) + "|" + b64(nR))
         pair_secret = HKDF(Z, T, "ccp-pair-secret-v1", 32)
         code        = uint32_be(HKDF(Z, T, "ccp-pair-sas-v1", 4)) mod 1_000_000, 6 digits
         kc          = HKDF(Z, T, "ccp-pair-confirm-v1", 32)
       Both devices display `code`; R's user approves only if the codes match.
R → I  pair.response   { accepted: true, confirm: b64(HMAC(kc, "responder")) }
   or  pair.response   { accepted: false, reason }
```

I verifies `confirm` before storing the pair secret. Because I commits to its
key before seeing R's, a man-in-the-middle can't choose keys that make the two
codes match except by luck (1 in 10⁶ per attempt).

Rules:

- R shows one pairing prompt at a time (`reason: "busy"` otherwise) and
  treats no answer within 60 s as rejection.
- A pair request from an already-paired id always prompts again and warns
  that approving replaces the keys. It never auto-accepts.
- Refusal reasons: `invalid_device_id`, `unsupported_pairing_version`,
  `invalid_commitment`, `commitment_mismatch`, `invalid_ephemeral_pub`,
  `invalid_nonce`, `protocol_error`, `busy`, `rejected`.

## Secure LAN session

```
C → S  session.hello           { version: 1, nonce: b64(nC) }       // 16 bytes
S → C  session.hello.response  { ok: true, version: 1, nonce: b64(nS) }
   or  session.hello.response  { ok: false, reason: "not_paired" | "bad_hello" }
```

C checks that the response's `sender.device_id` is the peer it meant to reach.
Keys, from the stored pair secret:

```
salt = H("ccp-lan-v1|" + idC + "|" + idS + "|" + b64(nC) + "|" + b64(nS))
k_c2s = HKDF(pair_secret, salt, "ccp-lan-c2s-v1", 32)
k_s2c = HKDF(pair_secret, salt, "ccp-lan-s2c-v1", 32)
```

Every later frame in either direction is:

```json
{ "sealed": "b64(AES-256-GCM(k_dir, nonce = 0x00000000 || uint64_be(counter), aad = \"ccp-lan-frame-v1|<dir>|<counter>\", envelope_json))" }
```

`dir` is `c2s` or `s2c`, and each direction counts from 0. A frame that fails
to open (forged, replayed, reordered, or sealed with another secret) ends the
session. The server may first send a plain `session.error {reason: "bad_frame"}`.
The server takes the peer's identity from the handshake, never from
`sender` fields inside sealed messages. One session can carry many requests.

### Requests inside a session

| Request | Response |
| --- | --- |
| `device.snapshot.request` | `device.snapshot.response` |
| `gallery.list.request` | `gallery.list.response` `{items}` |
| `files.list.request` | `files.list.response` `{items}` |
| `notifications.list.request` | `notifications.list.response` `{permission_granted, items}` |
| `remote.action.request {action, args}` | `remote.action.response {ok, message, action}` |
| `file.offer` | `file.offer.response {transfer_id, accepted, resume_from: 0, reason}` |
| `file.chunk` (no response) | |
| `file.complete {transfer_id, sha256}` | `file.complete.response {transfer_id, ok}` |

### File transfer

`file.offer {transfer_id ≤64 chars, filename, size, sha256, chunk_size, total_chunks}`.
Receivers reject the offer unless `total_chunks == ceil(size / chunk_size)`,
the size is within limits, and there is free space. Then each
`file.chunk {transfer_id, index, sha256, data_b64}` must carry the next index,
match its hash, and not exceed the offered size. The file is streamed to a
temp file with an incremental hash. It is accepted only if every chunk
arrived and the full hash matches. File names are sanitised (separators,
reserved and control characters, leading dots, Windows device names, max 120
chars).

## Cloud relay (Convex)

Both peers derive the relay key locally; Convex never sees it:

```
(idA, idB) = sorted(device ids)
cloud_key  = HKDF(pair_secret, "", "ccp-cloud-key-v1|"  + idA + "|" + idB, 32)
wrap_key   = HKDF(pair_secret, "", "ccp-cloud-wrap-v1|" + idA + "|" + idB, 32)
fingerprint = hex(H(cloud_key))
```

`sessions:storeSession` records the pairing with the fingerprint and an
opaque wrapped copy of the key (`{v:1, nonce, ciphertext}` =
AES-GCM(wrap_key, aad `"ccp-cloud-wrap-v1"`, cloud_key)). Either side may
store it. Clients re-publish pairings the relay is missing.

Messages:

```
plaintext = {"v": 1, "sent_at": <unix ms>, "body": <payload>}
aad       = "ccp-cloud-msg-v1|" + sender_id + "|" + recipient_id + "|" + msg_type + "|" + msg_id
encrypted_payload = b64(AES-256-GCM(cloud_key, 12-byte random nonce, aad, plaintext))
```

Receivers reject messages that fail authentication, are more than 8 days old,
or repeat a `(sender, msg_id)` already seen (persisted cache of 2,000 ids).
Messages are acked (deleted) after they are handled. Undecryptable messages
are acked too, so they aren't redelivered forever. A response resolves a
pending request only if its type ends in `.response` and it comes from the
peer the request went to. Request/response correlation uses `request_id` in
the body.

### Backend rules

All functions take `auth_token` and verify it in constant time against the
stored hash.

- `registerDevice` requires a token-bound `device_id` and validates name,
  platform, capabilities and version lengths.
- `pushMessage` requires an active session between sender and recipient. It
  bounds payload (512 KiB), TTL (10 s – 7 days) and `msg_type`, and
  de-duplicates by `(sender, msg_id)`.
- `getDevice`, `listDevices`, `getPresence` and `getBulkPresence` only show
  the caller and its session peers. They never return `auth_token_hash`.
- `ackMessages` deletes only the caller's messages. `revokeSession` wipes the
  wrapped blobs and queued messages.
- `purgeExpiredMessages` is internal, runs hourly, and works in batches.

## Known limitations

- The comparison code protects pairing only if the user actually compares.
  Approving blindly is equivalent to v0 trust-on-first-use.
- There is no forward secrecy across LAN sessions beyond per-session keys.
  Compromising a stored pair secret exposes future traffic with that peer
  until the devices re-pair.
- The relay is polled over HTTPS (3 s active, up to 10 s idle). Convex
  WebSocket subscriptions would cut latency and battery use.
- Resume (`resume_from > 0`) and parallel chunk streams are not implemented.
