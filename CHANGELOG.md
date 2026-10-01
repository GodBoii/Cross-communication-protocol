# Changelog

## v1 hardening (2026-10-01)

Breaking: protocol `ccp.v1` and the Convex functions are incompatible with v0. Deploy the backend (`npx convex deploy`) before shipping clients. Devices paired under v0 must pair again.

### Security
- Pairing uses ephemeral ECDH P-256 with a commitment. Both devices show a 6-digit comparison code, and the responder confirms the key. Pair secrets never cross the network.
- Re-pairing an already-paired id always prompts and warns. It no longer silently replaces keys.
- Every LAN capability (snapshot, gallery, files, notifications, remote actions, file transfer) is served only inside an encrypted, authenticated session (AES-256-GCM, per-direction keys, counter nonces). A copied device id gets nothing.
- Device ids are bound to a secret token (`sha256("ccp-device-id-v1:" + sha256(token))`), so Convex can stop ids being squatted.
- The cloud relay key is derived locally from the pair secret. Sender, recipient, type and message id are bound as AAD. Replays are rejected by message id and age.
- Convex functions are authenticated (constant-time token check). Messaging requires an active session. Device and presence reads are limited to the caller's session peers, and `auth_token_hash` is never returned. Inputs are length- and range-checked. Purging is internal-only. Revoking a session wipes its key blobs and queued messages.
- Secrets at rest: Android Keystore (AES-GCM) and Windows DPAPI. Android backup and device-transfer are excluded, and cleartext traffic is disabled.
- Added unpair on both platforms (forgets the secret and revokes the relay session).

### Reliability
- Malformed packets can no longer crash the Android process (coroutine exception handler; listeners restart with backoff).
- Bounded frame reader (512 KiB) on both platforms, 90 s idle timeouts, and a cap of 16 concurrent connections.
- Clean stop/restart on Android: sockets are closed, jobs cancelled, and ports reused.
- Relay messages are acked only after they're handled. Undecryptable messages are dropped rather than redelivered forever.
- Convex errors (HTTP 200 with `status: "error"`) are detected, so failed sends are no longer reported as success.
- Windows config writes are atomic and locked. A corrupt config is preserved instead of silently replaced with a new identity.
- Fixed crashes on Android 8–10: `StorageVolume.directory` (API 30) and MediaStore columns (API 29).

### File transfer
- Receivers stream to a temp file with an incremental hash. Files are no longer loaded into memory.
- Offers are validated (size limits of 4 GiB LAN and 100 MiB relay, chunk size, `total_chunks`, free space). Chunks must be in order, match their hash, and stay within the offered size.
- Hardened file names (separators, control characters, leading dots, Windows device names, length).
- Stale relay transfers and leftover `.part` files are cleaned up.

### Performance and battery
- Relay polling backs off while idle (3 s to 10 s) and wakes immediately for outgoing requests. The heartbeat interval is now 15 s.
- Cloud panel requests go out in parallel (one round trip instead of four), and duplicate panel refreshes are suppressed.
- The Android foreground service uses the `connectedDevice` type (avoids the 6 h/day `dataSync` cap on Android 15).
- Release APK built with R8 and resource shrinking (~16 MB → ~1 MB).

### Build, tests, tooling
- Shared crypto test vectors generated independently with Node. Kotlin, C# and the Convex helpers all verify against them.
- Tests: 21 Android unit tests, 24 Windows xUnit tests, 7 Convex helper tests, including pairing and sessions over real sockets and tamper/replay/impostor cases.
- CI for Convex (typecheck, tests, audit), Android (tests, debug and release builds) and Windows (warning-free build, tests).
- npm dependencies pinned. `npm audit` is clean, and `convex/_generated` is committed for typechecking.
- Convex URL configurable (`-PccpConvexUrl`, `CCP_CONVEX_URL`).
- Repo cleanup: lowercase `com/ccp` sources, starter tests replaced, stray files removed, notes and audits moved under `docs/`, `.gitattributes` added, machine-specific `org.gradle.java.home` removed.

### Docs
- New `shared/protocol/ccp-v1.md`, updated schema, README, architecture and walkthrough. v0 spec and v0 analysis marked historical.
