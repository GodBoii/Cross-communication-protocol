# CCP - Cross-Platform Connectivity Protocol

CCP connects your own devices directly over the local network and, when they are apart, through an end-to-end encrypted cloud relay. Windows and Android are implemented; the other platform folders are placeholders.

## Folder layout

```text
android/   Native Android app (Kotlin, Jetpack Compose). Build APKs here.
windows/   Native Windows app (WPF, .NET 8) and its test project.
convex/    Convex backend for the cloud relay (devices, sessions, messages, presence).
shared/    Protocol spec, message schema, and cross-platform crypto test vectors.
tests/     Node tests for the Convex helpers.
docs/      Architecture notes, walkthrough, audits.
linux/ macos/ ios/   Reserved for future clients.
```

## What it does

- LAN discovery over UDP broadcast, with route advertisement for Wi-Fi, Ethernet, USB tethering and Bluetooth PAN.
- Pairing with ephemeral ECDH P-256 keys: both screens show the same 6-digit code, and the other device's user approves.
- All LAN traffic after pairing is encrypted and authenticated (AES-256-GCM, per-direction keys, replay protection).
- Streamed, hash-verified file transfer with size limits.
- Remote panel: device snapshot, recent media and files, notifications (Android), and remote actions (Android).
- "Long Distance" mode: the same requests go through Convex, encrypted with a key that only the two paired devices can derive.

See [shared/protocol/ccp-v1.md](shared/protocol/ccp-v1.md) for the wire protocol and [docs/codebase-walkthrough.md](docs/codebase-walkthrough.md) for a tour of the code.

## Build and test

| Component | Command |
| --- | --- |
| Convex typecheck + tests | `npm ci` then `npm test` |
| Android | `cd android` then `./gradlew testDebugUnitTest assembleDebug` (JDK 17–21) |
| Android release (R8) | `./gradlew assembleRelease`; override the relay with `-PccpConvexUrl=https://<deployment>.convex.cloud` |
| Windows | `dotnet build windows/native-csharp/CCP.Windows.csproj` |
| Windows tests | `dotnet test windows/CCP.Windows.Tests/CCP.Windows.Tests.csproj` |

CI (`.github/workflows/ci.yml`) runs all of the above on every push and pull request.

## Deploying the backend

The Convex functions changed incompatibly in v1 (token-bound device ids, session-gated messaging). Deploy them before shipping v1 clients:

```bash
npx convex deploy
```

v0 clients can't use the v1 backend, and v1 clients can't pair with v0 clients. Devices paired under v0 must pair again.

## Security model in one paragraph

A device's identity is a random token that stays on the device, stored in the Android Keystore or Windows DPAPI. Its public id is a hash of that token, so the relay can verify who registers an id. Trust between two devices exists only after a user-approved pairing whose comparison code defeats man-in-the-middle attacks. Every capability request then has to arrive over a channel keyed from that pairing. Copying a device's broadcast id gets an attacker nothing. Details and known limitations are in the protocol spec.
