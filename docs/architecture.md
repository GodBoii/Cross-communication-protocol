# CCP Architecture

## Components

```text
Android app (Kotlin/Compose)                 Windows app (WPF/.NET 8)
  CcpNode ── discovery (UDP 47827)             CcpNode ── same roles
          ── LAN server (TCP 47828)
          ── LanPairing / LanSession / FileTransfer   (pure, unit-tested)
          ── ConvexBridge ───────┐            ConvexService ──┐
  PeerStore + SecretBox          │            ConfigStore (DPAPI)
  (Android Keystore)             │                            │
                                 ▼                            ▼
                      Convex backend (HTTPS API)
                      devices · sessions · messages · presence
```

## Principles

1. **Platform-neutral wire protocol.** Each OS uses native UI and APIs, but the protocol is the same everywhere (`shared/protocol/ccp-v1.md`), and the cryptography is pinned by shared test vectors that Kotlin, C#, and the Convex helpers all check.

2. **Discovery is not trust.** Anyone on the LAN can see and claim a device id. Trust exists only once two devices share a pair secret from an approved pairing. Every capability is served only inside a session keyed from that secret.

3. **Pairing resists man-in-the-middle attacks.** Pairing uses ephemeral ECDH with a commitment, followed by a 6-digit code comparison that the user performs (Bluetooth numeric-comparison style). Re-pairing always prompts.

4. **The relay is untrusted.** Convex authenticates callers and stores only ciphertext. Message metadata is bound as AAD, so the relay can't re-label or redirect messages, and replays are rejected client-side.

5. **Bounded everything.** Frame sizes, connection counts, idle timeouts, file sizes, chunk counts, prompt timeouts, relay payloads, and TTLs all have explicit limits. Malformed input is dropped and never crashes a listener.

6. **Native access stays feature-scoped.** File transfer, notifications, and remote actions are separate request types that can be gated individually. Remote input and clipboard sync aren't implemented yet.

## Data flow: sending a file over the LAN

1. The sender opens a TCP connection, sends `session.hello`, and derives the session keys.
2. The sender sends a sealed `file.offer`. The receiver validates it, checks free space, and prompts the user (Windows) before replying.
3. Sealed `file.chunk` frames stream in order. The receiver checks each one and appends it to a temp file while hashing incrementally.
4. On `file.complete`, the receiver verifies count, size, and hash, then moves the file to the inbox (Windows) or MediaStore (Android).

## Data flow: Long Distance request

1. The requester encrypts `{v, sent_at, body}` with the cloud key and pushes it to Convex. Convex checks that the two devices have an active session.
2. The recipient polls, decrypts, checks age and replay, handles the request, pushes the response, and acks the original.
3. The requester resolves its pending request when it receives a matching `.response` from that peer.

## Platform choices

Windows uses C#/WPF for native dialogs, DPAPI, and WinRT/Win32 access. Android uses Kotlin and the SDK directly for foreground services, notification access, MediaStore, and the Keystore. A Capacitor shell exists in the npm dependencies but isn't wired into the Android build.
