# CCP Codebase Audit Report

Audit date: 2026-06-22  
Workspace: `C:\Users\prajw\Downloads\CCP`

## 1. Executive Summary

CCP is a Windows/Android local-first device bridge with Convex cloud relay support. The LAN and cloud architecture is coherent, and both Android and Windows builds complete locally, but the implementation is not production-safe yet: the core trust boundary is porous on local TCP, the Convex backend has no authenticated caller identity, and the cloud session-key storage is decryptable from public device IDs. The highest-risk issues are concrete and line-backed: unpaired LAN callers can request device panels and actions, Android auto-accepts pair requests, and cloud messages/sessions can be spoofed or disrupted through public Convex functions.

| Severity | Count |
| --- | ---: |
| Critical | 2 |
| High | 3 |
| Medium | 5 |
| Low | 3 |
| Cosmetic | 0 |

Scope note: I manually audited first-party source/config/docs under `android`, `windows/native-csharp`, `convex`, `shared`, `www`, and top-level config. I did not manually inspect vendored/generated artifacts such as `node_modules`, Android build output, iOS generated Capacitor assets, or .NET `bin/obj`; I used package/build tools for those.

## 2. Architecture Overview

The implemented system is a platform-native monorepo:

```text
Android app (Kotlin/Compose)
  UDP discovery 47827 -> peer list
  TCP JSON channel 47828 -> pair, inspect, remote actions, file chunks
  ConvexBridge -> HTTPS Convex relay for presence, sessions, encrypted messages

Windows app (WPF/.NET 8)
  UDP discovery 47827 -> peer list
  TCP JSON channel 47828 -> pair, inspect, remote actions, file chunks
  ConvexService -> HTTPS Convex relay for presence, sessions, encrypted messages

Convex backend
  devices, sessions, messages, presence tables
  unauthenticated mutations/queries using caller-supplied device IDs
```

The docs state “pair before capabilities” in `docs/architecture.md:17-20`, but both native TCP servers expose inspection endpoints without a trust check. The docs also describe real ECDH/X25519 in `convex/sessions.ts:16-24`; the clients implement SHA-256 pseudo-key derivation instead.

## 3. Detailed Findings

### ID: 1
Title: Cloud session keys are recoverable from public device IDs  
Severity: Critical  
Category: Security / Privacy  
Location: `convex/sessions.ts:98-123`, `android/app/src/main/java/com/CCP/android/ConvexBridge.kt:492-500`, `windows/native-csharp/Services/ConvexService.cs:62-66`

Description: `sessions:getSession` returns an encrypted key blob based solely on caller-supplied `my_device_id` and `peer_device_id`. The client-side key used to decrypt that blob is derived from the public `deviceId` and a fixed salt, so an attacker who can call the public Convex function can derive the same machine secret for any device ID.

Evidence:
```ts
// convex/sessions.ts:98-123
export const getSession = query({
  args: { my_device_id: v.string(), peer_device_id: v.string() },
  ...
  encrypted_key: iAmA ? session.encrypted_key_a : session.encrypted_key_b,
});
```

```kotlin
// android/.../ConvexBridge.kt:492-500
PBEKeySpec(deviceId.toCharArray(), "ccp-machine-secret-v0".toByteArray(), 100_000, 256)
```

Impact: A remote attacker can retrieve and decrypt cloud session keys, then decrypt cloud messages or encrypt valid messages as a paired peer. This breaks the stated end-to-end encryption model.

Recommended Fix: Add Convex authentication and bind every function call to `ctx.auth`; never accept identity solely from args. Replace pseudo-ECDH with real X25519/Noise or platform crypto. Encrypt stored session material with a device secret that is never derivable from public identifiers, preferably using OS keystore/DPAPI. Rotate all existing cloud sessions after fixing.

Confidence: High.

### ID: 2
Title: Local TCP capability endpoints do not require trusted pairing  
Severity: Critical  
Category: Security / Privacy  
Location: `android/app/src/main/java/com/CCP/android/CcpNode.kt:481-500`, `windows/native-csharp/Services/CcpNode.cs:688-717`

Description: The TCP servers guard `file.offer`, but they do not guard device snapshot, gallery list, file list, notification list, or remote-action requests. Any host that can connect to TCP `47828` can request these capabilities before pairing.

Evidence:
```kotlin
// android CcpNode.kt:481-500
"device.snapshot.request" -> { write(... deviceData.buildRemoteSnapshotPayload(...)) }
"gallery.list.request" -> { write(... deviceData.buildGalleryPayload()) }
"remote.action.request" -> { val result = performRemoteAction(action, args) }
```

```csharp
// windows CcpNode.cs:688-717
case "gallery.list.request":
    await WriteAsync(writer, Envelope("gallery.list.response", BuildDirectoryPayload(...)));
case "files.list.request":
    await WriteAsync(writer, Envelope("files.list.response", BuildDirectoryPayload(...)));
```

Impact: A LAN attacker can enumerate device metadata and recent media/files. On Android they can also trigger settings panels, dialer launch, or call-answer attempts via `performRemoteAction` at `CcpNode.kt:982-1017`.

Recommended Fix: At the top of each non-pair request handler, reject unless `store.isTrusted(sender.device_id)` / `_config.IsTrusted(message.Sender.DeviceId)` is true. Add tests that untrusted callers get a rejection for every capability.

Confidence: High.

### ID: 3
Title: Android accepts pairing without user confirmation or code verification  
Severity: High  
Category: Security / UX  
Location: `android/app/src/main/java/com/CCP/android/CcpNode.kt:418-423`, `shared/protocol/ccp-v0.md:66-72`

Description: The protocol says the receiver prompts the user, but Android immediately trusts any `pair.request`.

Evidence:
```kotlin
// CcpNode.kt:418-423
"pair.request" -> {
    store.trust(sender)
    write(writer, ccpEnvelope("pair.response", ..., JSONObject().put("accepted", true)))
}
```

Impact: Any LAN peer can pair itself with an Android device. Once paired, it can send files and use trusted-only cloud file acceptance.

Recommended Fix: Show a system/UI pairing prompt on Android, display the 6-digit code, and only call `store.trust` after explicit acceptance. Consider signed key confirmation rather than a display-only code.

Confidence: High.

### ID: 4
Title: Convex message queue allows spoofing, polling, and arbitrary ack by caller-supplied IDs  
Severity: High  
Category: Security / Data Integrity  
Location: `convex/messages.ts:25-61`, `convex/messages.ts:69-98`, `convex/messages.ts:106-115`

Description: `pushMessage`, `pollMessages`, and `ackMessages` do not authenticate the caller or verify ownership. Callers provide `sender_id`, `recipient_id`, and message IDs directly.

Evidence:
```ts
// messages.ts:25-33
sender_id: v.string(),
recipient_id: v.string(),
...
// messages.ts:106-113
for (const id of args.message_ids) {
  await ctx.db.patch(id, { delivered: true });
}
```

Impact: Even before decrypting payloads, an attacker can poll ciphertext for any recipient ID and mark known message IDs delivered, causing message loss. Combined with Finding 1, the same route can become full message forgery.

Recommended Fix: Require authenticated device identity, enforce `sender_id === authenticatedDeviceId`, only allow polling/acking messages for the authenticated recipient, and validate that acked IDs belong to that recipient.

Confidence: High.

### ID: 5
Title: Cloud and local key exchange is not real ECDH despite comments claiming it is  
Severity: High  
Category: Security / Maintainability  
Location: `windows/native-csharp/Services/ConvexService.cs:16-20`, `windows/native-csharp/Services/ConvexService.cs:127-129`, `android/app/src/main/java/com/CCP/android/ConvexBridge.kt:70-77`, `convex/sessions.ts:16-24`

Description: The documentation and comments describe X25519/ECDH, but the implementation uses `SHA256(private || peerPublic)` where `public` is itself `SHA256(private || "ccp-pub")`. This is not an authenticated Diffie-Hellman exchange and should not be treated as cryptographic key agreement.

Evidence:
```csharp
// ConvexService.cs:127-129
var sharedSecret = SHA256.HashData([.. _privateKey, .. peerPub]);
var sessionKey = HKDF.DeriveKey(... sharedSecret ...);
```

Impact: Engineers may assume the cloud channel has standard ECDH properties it does not have. This amplifies the cloud security failures and makes future fixes harder to reason about.

Recommended Fix: Replace with real X25519 or a well-reviewed Noise/TLS-style handshake and update comments/docs to match.

Confidence: High.

### ID: 6
Title: Android file receipt loads entire files into memory  
Severity: Medium  
Category: Performance / Reliability  
Location: `android/app/src/main/java/com/CCP/android/CcpNode.kt:468-474`, `android/app/src/main/java/com/CCP/android/CcpNode.kt:773-784`, `android/app/src/main/java/com/CCP/android/DeviceDataRepository.kt:40-67`

Description: Android writes incoming chunks to a temp file, then calls `readBytes()` and passes a full `ByteArray` into `saveIncomingFile`.

Evidence:
```kotlin
// CcpNode.kt:468-474
val bytes = activeFile?.readBytes()
val saved = deviceData.saveIncomingFile(activeFile.name, bytes)
```

Impact: Large transfers can trigger OOM or severe GC pauses, especially on phones. This is a real edge case because the protocol exposes file transfer and does not enforce a maximum size in `file.offer`.

Recommended Fix: Stream from the temp file to MediaStore and compute SHA-256 incrementally. Reject files above a configured limit before accepting.

Confidence: High.

### ID: 7
Title: File chunk index is ignored, so duplicate or out-of-order chunks corrupt transfers  
Severity: Medium  
Category: Data Integrity / Edge Case  
Location: `android/app/src/main/java/com/CCP/android/CcpNode.kt:750-760`, `windows/native-csharp/Services/CcpNode.cs:1335-1352`, `shared/protocol/ccp-v0.md:118-126`

Description: Chunks include an `index`, but receivers append data without checking expected order, duplicates, or total chunk count.

Evidence:
```kotlin
// CcpNode.kt:753-760
val chunk = Base64.decode(...)
transfer.output.write(chunk)
```

```csharp
// CcpNode.cs:1341-1352
var raw = Convert.FromBase64String(...);
transfer.Output.Write(raw);
```

Impact: Out-of-order delivery, retries, or duplicate messages can corrupt files. Final SHA verification catches the corruption only after all bytes have been transferred.

Recommended Fix: Track expected next index for sequential transfers, reject duplicates/out-of-order chunks, and include `total_chunks` validation at completion.

Confidence: High.

### ID: 8
Title: Android peer map is not thread-safe across IO coroutines  
Severity: Medium  
Category: Concurrency / Reliability  
Location: `android/app/src/main/java/com/CCP/android/CcpNode.kt:41-47`, `android/app/src/main/java/com/CCP/android/CcpNode.kt:559-617`

Description: `peersById` is a `linkedMapOf` mutated by multiple `Dispatchers.IO` coroutines: discovery listener, cloud peer loop, and stale-prune loop.

Evidence:
```kotlin
// CcpNode.kt:45
private val peersById = linkedMapOf<String, DeviceInfo>()
// CcpNode.kt:607-612
val iterator = peersById.iterator()
iterator.remove()
```

Impact: Concurrent mutation can throw or publish inconsistent peer lists, especially while cloud refresh and UDP discovery overlap.

Recommended Fix: Protect peer state with a `Mutex` or use a concurrent map plus single-threaded state reducer.

Confidence: Medium.

### ID: 9
Title: Android backs up plaintext local identity and cloud key material  
Severity: Medium  
Category: Security / Privacy  
Location: `android/app/src/main/AndroidManifest.xml:16-22`, `android/app/src/main/java/com/CCP/android/ConvexBridge.kt:484-489`, `android/app/src/main/java/com/CCP/android/PeerStore.kt:24-29`

Description: `android:allowBackup="true"` permits app data backup by default, while the cloud private key and trusted peers are stored in `SharedPreferences`.

Evidence:
```xml
<!-- AndroidManifest.xml:16-22 -->
<application android:allowBackup="true" ...>
```

```kotlin
// ConvexBridge.kt:484-489
prefs.edit().putString("convex_private_key", Base64.encodeToString(key, Base64.NO_WRAP)).apply()
```

Impact: Device backups or rooted/debuggable contexts can expose long-lived identity/trust material. Restoring backups can also clone device identity onto another handset.

Recommended Fix: Store private keys in Android Keystore, exclude sensitive prefs with backup rules or set `allowBackup=false`, and regenerate identity on restore if appropriate.

Confidence: High.

### ID: 10
Title: npm audit reports vulnerable transitive packages  
Severity: Medium  
Category: Dependency / Security  
Location: `package-lock.json:841-850`, `package-lock.json:1562-1564`

Description: `npm audit --json` reports 1 high and 3 moderate vulnerabilities. The high issue is `ws@8.18.0`, pulled through `convex@1.38.0`; `npm outdated --json` shows `convex` latest/wanted is `1.41.0` and Capacitor packages can move from `8.3.1` to `8.4.1`.

Evidence:
```json
// package-lock.json:841-850
"node_modules/convex": { "version": "1.38.0", ... "ws": "8.18.0" }
// package-lock.json:1562-1564
"node_modules/ws": { "version": "8.18.0" }
```

Impact: The dev toolchain includes known DoS/memory-disclosure advisories. The vulnerable `ws` is dev/transitive, so production exposure depends on how the CLI/dev server is used.

Recommended Fix: Upgrade `convex` and Capacitor packages, regenerate lockfile, and rerun `npm audit`.

Confidence: High.

### ID: 11
Title: Android test suite is placeholder-only and instrumentation assertion is stale  
Severity: Medium  
Category: Testing  
Location: `android/app/src/test/java/com/getcapacitor/myapp/ExampleUnitTest.java:14-17`, `android/app/src/androidTest/java/com/getcapacitor/myapp/ExampleInstrumentedTest.java:20-25`, `android/app/build.gradle:8-15`

Description: The only local unit test asserts `2 + 2 == 4`. The instrumentation test expects `com.getcapacitor.app`, but the app ID is `com.ccp.android`.

Evidence:
```java
// ExampleUnitTest.java:14-17
assertEquals(4, 2 + 2);
// ExampleInstrumentedTest.java:20-25
assertEquals("com.getcapacitor.app", appContext.getPackageName());
```

```gradle
// android/app/build.gradle:8-15
applicationId "com.ccp.android"
```

Impact: `testDebugUnitTest` can pass while core networking, pairing, crypto, file transfer, and UI flows are completely untested. The instrumentation test would fail if run.

Recommended Fix: Replace starter tests with protocol parsing, trust-gate, pairing, file chunk, and Convex bridge tests. Fix the package assertion or remove the starter test.

Confidence: High.

### ID: 12
Title: Android Gradle DSL uses syntax deprecated for future Gradle versions  
Severity: Low  
Category: Maintainability  
Location: `android/app/build.gradle:17-23`

Description: `./gradlew.bat assembleDebug --warning-mode all` reports deprecated Groovy space-assignment syntax for `compose true` and `kotlinCompilerExtensionVersion '1.5.14'`.

Evidence:
```gradle
// android/app/build.gradle:17-23
buildFeatures {
    compose true
}
composeOptions {
    kotlinCompilerExtensionVersion '1.5.14'
}
```

Impact: Build scripts will need cleanup before Gradle 10 compatibility. Build currently succeeds.

Recommended Fix: Use assignment syntax: `compose = true`; `kotlinCompilerExtensionVersion = '1.5.14'`.

Confidence: High.

### ID: 13
Title: No root npm scripts for repeatable JS/Convex validation  
Severity: Low  
Category: Testing / Developer Experience  
Location: `package.json:1-10`

Description: The root package has dependencies but no `scripts`. `npm test` fails with “Missing script: test.”

Evidence:
```json
// package.json:1-10
{
  "dependencies": { ... },
  "devDependencies": { "convex": "^1.38.0" }
}
```

Impact: Convex validation depends on humans remembering commands. CI cannot run a standard `npm test` or `npm run check`.

Recommended Fix: Add scripts such as `convex:codegen`, `audit`, and `check` that run the intended validation commands.

Confidence: High.

## 4. Easily Missed Findings

- Finding 1 is subtle because the payload is encrypted, but the stored key-encryption key is deterministic from public IDs.
- Finding 7 is a timing/data-order issue: it will often pass on LAN and fail only under retry/out-of-order cloud behavior.
- Finding 8 is a concurrency issue hidden by light manual testing.
- Finding 6 appears only with large enough files to exceed practical mobile memory headroom.

## 5. Security & Privacy Summary

Security work should start with the trust boundary. Enforce authenticated identity in Convex, replace the cloud key exchange, and rotate sessions. Then enforce local TCP trust checks before every capability endpoint. Android pairing must require user confirmation. Android private keys should move to Android Keystore and be excluded from backups.

## 6. Test Coverage Assessment

Commands run:

| Command | Result |
| --- | --- |
| `dotnet build .\CCP.Windows.csproj` | Passed, 0 warnings |
| `.\gradlew.bat testDebugUnitTest` | Passed, but only starter arithmetic test |
| `.\gradlew.bat assembleDebug` | Passed; Gradle deprecation warning |
| `.\gradlew.bat assembleDebug --warning-mode all` | Passed; warnings at `android/app/build.gradle:18,22` |
| `npm exec convex -- codegen` | Passed; contacted deployment and uploaded/generated Convex functions |
| `npm audit --json` | Failed status due to vulnerabilities: 1 high, 3 moderate |
| `npm test` | Failed: missing script |
| `dotnet list .\CCP.Windows.csproj package --outdated` | No package updates because project has no NuGet package references |

Highest-value next tests:

- Untrusted TCP caller cannot access snapshot/gallery/files/notifications/remote actions.
- Android pair request requires explicit acceptance.
- Convex functions reject spoofed sender/recipient IDs.
- Cloud session decrypt attempt fails without authenticated device secret.
- File transfer rejects duplicate/out-of-order chunks and handles large files without loading into memory.

## 7. Prioritized Action Plan

1. Fix Convex authentication/authorization and replace session-key storage/key exchange. Rotate all cloud sessions.
2. Add local TCP trust checks for every capability endpoint on Android and Windows.
3. Implement Android pairing confirmation and code verification.
4. Move Android key material to Android Keystore and disable/exclude sensitive backups.
5. Rework Android file receipt to stream large files and enforce file size limits.
6. Enforce file chunk order/deduplication on both platforms.
7. Add real protocol/security tests and wire them into root/package scripts.
8. Upgrade npm dependencies and rerun `npm audit`.
9. Clean Gradle deprecated syntax.
