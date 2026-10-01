# CCP Codebase Walkthrough

A tour of the v1 code. The wire format is in [ccp-v1.md](../shared/protocol/ccp-v1.md); this explains where each piece lives and why.

## 1. Repository structure

| Path | Contents |
| --- | --- |
| `android/app/src/main/java/com/ccp/android/` | Kotlin app |
| `android/app/src/test/` | JVM unit tests (crypto vectors, pairing, sessions over sockets, transfers) |
| `windows/native-csharp/` | WPF app |
| `windows/CCP.Windows.Tests/` | xUnit tests that link the WPF-free sources |
| `convex/` | Backend functions; `convex/lib/auth.ts` holds the shared auth and validation helpers |
| `tests/` | Node tests for the Convex helpers (kept out of `convex/` so they aren't deployed) |
| `shared/` | Protocol spec, JSON schema, crypto test vectors and their generator |

## 2. One protocol, three implementations

The Android and Windows apps each implement the protocol in the same set of small, platform-free files. That makes them testable without a device or a UI:

| Concern | Android | Windows |
| --- | --- | --- |
| Primitives, pairing math, session channel, cloud keys | `CcpCrypto.kt` | `Services/CcpCrypto.cs` |
| Bounded newline framing | `LineIo.kt` | `Services/LineIo.cs` |
| Pairing state machines | `LanPairing.kt` | `Services/LanPairing.cs` |
| `session.hello` handshake + sealed frames | `LanSession.kt` | `Services/LanSession.cs` |
| Offer validation, streamed receive, safe names | `FileTransfer.kt` | `Services/FileTransfer.cs` |

`shared/test-vectors/ccp-crypto-v1.json` is generated with Node's crypto module, independently of both apps. The Kotlin, C#, and Convex test suites all check against it. If any implementation drifts, its tests fail.

## 3. Android app

- **`MainActivity.kt`** is the Compose UI: device list, pairing cards (the incoming request with its comparison code, and the outgoing code to show the other device), remote panel, transfers, and activity log. It refreshes the inspected peer's panel every 5 s on the LAN and every 30 s over the relay.
- **`CcpForegroundService.kt`** keeps the node alive in the background as a `connectedDevice` foreground service.
- **`AppGraph.kt`** holds the single `CcpNode` shared by the activity and the service.
- **`CcpNode.kt`** is the orchestrator:
  - Discovery broadcast and listener, and the TCP listener. Each is wrapped in `resilient()` (restart with backoff). A `CoroutineExceptionHandler` ensures malformed input can't crash the process, and a semaphore caps concurrent connections.
  - `handleClient` accepts only `pair.request` or `session.hello` as the first frame. `serveSecureSession` dispatches sealed requests, and `handleCapabilityRequest` answers them. The cloud path uses the same function, so LAN and relay behave identically.
  - Outbound operations (`pair`, `sendFile`, `inspectPeer`) run through `launchTask`, which reports failures to the activity log.
  - `syncCloudPeers` mirrors relay sessions into the peer list and re-publishes local pairings the relay is missing.
- **`ConvexBridge.kt`** is the relay client. It handles Convex error detection (errors arrive as HTTP 200 with `status: "error"`), AAD-bound encryption, ack-after-handle, the replay guard, and adaptive polling.
- **`PeerStore.kt` + `SecretBox.kt`** hold identity and trust. The cloud token and pair secrets are sealed with an Android Keystore AES-GCM key. Pre-v1 secrets are dropped on startup.
- **`DeviceDataRepository.kt`** builds snapshot, gallery, and file payloads, and saves received files. On Android 10+ it streams the temp file into MediaStore; on 8–9 it writes to app storage.

## 4. Windows app

- **`MainWindow.xaml(.cs)`** is the WPF shell. Prompts are `MessageBox`es that default to No. `Ui/PairCodeWindow.cs` shows the outgoing comparison code.
- **`Services/CcpNode.cs`** mirrors the Android node: resilient loops, the same first-frame rule, `ServeSecureSessionAsync`, and `HandleCapabilityRequest`. Unlike Android, Windows asks before accepting each incoming file, over both LAN and relay.
- **`Services/ConvexService.cs`** is the relay client, wire-compatible with `ConvexBridge`. It persists its replay cache to `%APPDATA%\CCP\seen-msg-ids.json`.
- **`Services/ConfigStore.cs`** handles identity and trust. Secrets are protected with DPAPI, writes are atomic and locked, and an unreadable config is preserved rather than replaced.

## 5. Convex backend

Every function goes through `requireDevice` (token check, constant time). Reads of other devices go through `canSee`, which allows only the caller itself and its session peers. Messaging requires `activeSession`. `purgeExpiredMessages` is an internal mutation scheduled hourly by `crons.ts`. `convex/_generated/` is committed so `npm run typecheck` works without deployment credentials.

## 6. End-to-end flow

1. Both devices broadcast discovery. Each lists the other as untrusted.
2. The user taps **Pair** on device A. A and B run the commitment/ECDH exchange, and both show the same 6-digit code.
3. B's user approves. B stores the pair secret and replies with a key confirmation, which A verifies before storing the secret.
4. Each device registers the session with Convex in the background.
5. Panels, file transfers, and remote actions run over sealed LAN sessions. When the peer isn't on the LAN (Long Distance), the same requests go through the encrypted relay.

## 7. Not done yet

- Real-time relay via Convex WebSocket subscriptions (it's polled today).
- Transfer resume and parallel chunk streams.
- Unpair or revoke in the UI. `PeerStore.forget`, `ConfigStore.Forget`, and `sessions:revokeSession` exist but aren't exposed.
- Remote actions on Windows. Clipboard sync and notification mirroring beyond listing.
- mDNS/BLE discovery, Wi-Fi Direct, and real Bluetooth transports (today "bluetooth" means IP over Bluetooth PAN).
- Linux, macOS, and iOS clients.
