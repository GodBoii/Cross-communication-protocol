> **Historical (v0).** Written before the v1 hardening. Directed-broadcast targets, bind error handling, encrypted LAN sessions and the relay changes it discusses have since been implemented; see `shared/protocol/ccp-v1.md`.

# CCP Connectivity — Deep Analysis Report

> Wi-Fi · Bluetooth · Wired (Ethernet / USB-RNDIS) · Cloud (Convex)
> What is implemented, what works, what is broken, and where the code lies.

---

## 0. Mental model — what CCP calls a "transport"

CCP advertises **five** transport labels in its discovery packet:

| Label   | Intended meaning              | Actual implementation                                  |
| ------- | ----------------------------- | ------------------------------------------------------ |
| `wifi`  | Wi-Fi ad-hoc / infrastructure | IP-based TCP over the Wi-Fi interface's IPv4 address    |
| `lan`   | Wired Ethernet                | IP-based TCP over the Ethernet interface's IPv4 address |
| `usb`   | USB tethering / RNDIS         | IP-based TCP over a RNDIS/USB interface's IPv4 address  |
| `bluetooth` | Bluetooth PAN / Classic RFCOMM | **Nothing.** It's a label only.                    |
| `cloud` | Internet relay via Convex     | Real. AES-256-GCM encrypted HTTP polling against Convex |

**Critical insight:** Wi-Fi, LAN, USB, and Bluetooth are all just "give me the IPv4 address of this interface" and run **plain TCP** on top. There is **no Wi-Fi Direct, no Bluetooth RFCOMM/L2CAP socket, no USB-specific protocol**. The discovery packet advertises multiple `(transport, host, port)` tuples, the peer tries them in priority order, and the first TCP connect within 2.5 s wins. Wi-Fi ≠ Wi-Fi Direct, Bluetooth ≠ Bluetooth tethering; the code only ever uses **TCP over IP**.

---

## 1. Discovery (works on both sides — partially)

**Protocol:** UDP broadcast JSON to `255.255.255.255:47827` every 3 seconds.

### 1.1 Windows side — `CcpNode.BroadcastLoopAsync` / `ListenDiscoveryAsync`

```csharp
private async Task SendDiscoveryAsync() {
    using var udp = new UdpClient { EnableBroadcast = true };
    var packet = JsonSerializer.Serialize(...);
    await udp.SendAsync(bytes, new IPEndPoint(IPAddress.Broadcast, UdpPort));
}
```

- ✅ Broadcasts a well-formed JSON packet every 3 s.
- ✅ Includes `transports` map + `endpoints` array.
- ✅ Listener filters by `protocol == "ccp.v0"` and ignores own `device_id`.
- ⚠️ **Sends to `255.255.255.255` (limited broadcast) — this does NOT cross routers**, only the local L2 segment. On a typical home Wi-Fi (where the AP isolates clients — "AP isolation" / "Client isolation"), broadcasts from the laptop never reach the phone. This is the **#1 reason** "Windows doesn't see my Android" in the field. The correct fix is to also send to the **directed broadcast** of every active subnet (e.g. `192.168.1.255`), which the code does **not** do.
- ⚠️ **Listener uses the same `UdpClient(UdpPort)` on `0.0.0.0`** — on Windows, only **one** process can bind to a given UDP port, so if another app on the same machine uses 47827, this fails silently. The code does not handle the `SocketException`.
- ⚠️ The listener never calls `udp.ReceiveAsync(token)` with a **cancellation** that releases the socket — `StopAsync` calls `_stop.Cancel()` but the blocking `ReceiveAsync` won't surface it cleanly until a packet arrives. On shutdown the socket is leaked briefly.

### 1.2 Android side — `CcpNode.broadcastDiscovery` / `listenDiscovery`

```kotlin
private suspend fun broadcastDiscovery() {
    DatagramSocket().use { socket ->
        socket.broadcast = true
        // ...
        socket.send(DatagramPacket(data, data.size, InetAddress.getByName("255.255.255.255"), CCP_UDP_PORT))
    }
}
private fun listenDiscovery() {
    DatagramSocket(CCP_UDP_PORT).use { socket ->
        socket.soTimeout = 2000
        // loop read packets
    }
}
```

- ✅ Acquires a `WifiManager.MulticastLock` ("ccp-discovery") — this is **required** on Android 5+ when the app is backgrounded, otherwise multicast/broadcast packets are silently dropped. Correct.
- ✅ Broadcasts every 3 s, listens with 2 s SO timeout so `running=false` is checked regularly.
- ⚠️ Same **limited-broadcast** problem as Windows: `255.255.255.255` doesn't cross AP isolation.
- ⚠️ **`DatagramSocket(CCP_UDP_PORT)` on Android** — Android **requires** the `CHANGE_WIFI_MULTICAST_STATE` permission (declared) **AND** the multicast lock for receiving; the lock is held, so this works. Good.
- ⚠️ **But sending a *broadcast* over `DatagramSocket.broadcast=true` on Android** has a known quirk: since Android 4, `DatagramSocket.broadcast` was deprecated and later made a no-op; you actually need to send **per-interface directed broadcasts**. As written, `socket.broadcast = true` is silently ignored. This means **Android-to-Android discovery over the same Wi-Fi often works only because some Android Wi-Fi drivers accept limited broadcasts on the same subnet**; Android-to-Windows is even more fragile.
- 🐛 **No error handling on `socket.send(...)`**: any `IOException` (e.g. ENETUNREACH, EACCES) terminates the entire `broadcastDiscovery` coroutine and **the app stops announcing itself** for the rest of the session. There's no retry/relaunch.

### 1.3 What works, what doesn't

| Scenario                                                        | Result                                                                          |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Same Wi-Fi, no AP isolation, Windows ↔ Android                 | ✅ Works                                                                        |
| Same Wi-Fi, with AP isolation (default on coffee shops, etc.)   | ❌ Limited broadcast doesn't cross. No directed-broadcast fallback.             |
| Windows PC on Ethernet + Android on same Wi-Fi                  | ⚠️ Works only if the router bridges Ethernet & Wi-Fi in the same L2 broadcast. |
| Different VLANs / subnets                                       | ❌ Limited broadcast never reaches.                                             |
| iOS device on same network                                      | ❌ Not implemented (iOS restricts UDP broadcast sockets entirely).             |

**Verdict:** Discovery works in the most common home Wi-Fi scenario, **does not work** on corporate / public Wi-Fi, and is brittle on Android because the `socket.broadcast = true` flag is a no-op.

---

## 2. Transport detection (the "bluetooth" lie)

Both sides classify interfaces by **substring matching on the interface name**. This is the source of most of the "Bluetooth works / doesn't work" confusion.

### 2.1 Windows — `CcpNode.DetectTransportStatus`

```csharp
private static bool IsUsbInterface(NetworkInterface nic) {
    var text = $"{nic.Name} {nic.Description}";
    return text.Contains("usb", StringComparison.OrdinalIgnoreCase) ||
           text.Contains("rndis", StringComparison.OrdinalIgnoreCase);
}
private static bool IsBluetoothInterface(NetworkInterface nic) {
    var text = $"{nic.Name} {nic.Description}";
    return text.Contains("bluetooth", StringComparison.OrdinalIgnoreCase) ||
           nic.NetworkInterfaceType == NetworkInterfaceType.Ppp;
}
```

- The Bluetooth classifier **only matches if the interface name literally contains "bluetooth"** — which is true only when Bluetooth tethering is active and Windows exposes it as a `NetworkInterface` (Bluetooth PAN / BNEP). If the user has Bluetooth on but not tethering, there's no interface to match.
- The classifier **also matches `NetworkInterfaceType.Ppp`** for "Bluetooth" — PPP is dial-up, not Bluetooth. This is a wrong tag.
- ✅ Wi-Fi (`Wireless80211`) and Ethernet (`Ethernet`, `GigabitEthernet`, etc.) classifications are correct.

### 2.2 Android — `CcpNode.classifyTransport`

```kotlin
private fun classifyTransport(network: NetworkInterface): String {
    val name = "${network.name} ${network.displayName.orEmpty()}".lowercase(...)
    return when {
        "usb" in name || "rndis" in name -> "usb"
        "wlan" in name || "wifi" in name -> "wifi"
        "eth" in name -> "lan"
        "bluetooth" in name || "bt" in name -> "bluetooth"
        else -> "cloud"
    }
}
```

- Same approach: substring match. "bluetooth" tethering on Android shows up as `bt-pan`, `bt-tether`, or similar — sometimes matched, sometimes not.
- The Android classifier also has a second path via `NetworkCapabilities.TRANSPORT_BLUETOOTH` (used in `detectTransportStatus`), which is more reliable.
- 🐛 **Transport detection is performed only at peer-discovery time** (every 3 s when broadcasting). It is **never re-classified after a route becomes unreachable** — once a peer is known, its `routes` are static for its peer card lifetime.

### 2.3 What "bluetooth" actually buys you

- **Nothing beyond standard TCP/IP** when Bluetooth tethering exposes a network interface.
- **There is no Bluetooth RFCOMM socket** anywhere in the codebase. Verified with `findstr` on both `windows/native-csharp` and `android/app/src/main` — no `BluetoothClient`, `BluetoothListener`, `BluetoothAdapter`, `BluetoothSocket`, `RfcommSocket`, etc.
- The "bluetooth" pill in the UI literally means **"there's a network interface whose name happens to contain the word bluetooth"**. It's a label, not a transport.

**Verdict:** Bluetooth is **a cosmetic feature**. The code will not work device-to-device over Bluetooth unless the OS has paired+tethered to expose a PAN IP interface. The "Bluetooth" button on the dashboard is a routing selector — when you choose "bluetooth" as preferred transport and the peer's endpoint list contains a `bluetooth`-labeled route (which only exists when PAN is up), TCP connection proceeds normally. No Bluetooth sockets are used.

### 2.4 Wired (Ethernet) and USB-RNDIS

- ✅ **Ethernet** works end-to-end: the NIC has a real IPv4 address, the route is advertised, and TCP connects.
- ✅ **USB-RNDIS** works *if* the device exposes itself as a USB Ethernet adapter (Android in USB-tethering mode, or Windows over a USB-C hub). Same TCP path.
- ⚠️ **On Windows, the priority for `usb` is 0** (the highest in `RankRoutes`), so a USB-RNDIS link is preferred over Wi-Fi. This is a sensible default (USB is faster + more reliable + battery-friendly) but means **a phone plugged in to charge via USB will be auto-promoted to top-priority transport** even if the user prefers Wi-Fi for some reason.

---

## 3. TCP control channel (works, plaintext)

### 3.1 Windows — `CcpNode.ListenTcpAsync` / `HandleClientAsync`

- ✅ TcpListener on `0.0.0.0:47828`, accepts clients, spawns a `Task.Run` per client.
- ✅ `socket.NoDelay = true` (Nagle off, good for small JSON messages).
- ✅ StreamReader/StreamWriter with `leaveOpen: true` so the socket isn't closed when the reader/writer go out of scope.
- ✅ Handles `pair.request`, `file.offer`, `file.chunk`, `file.complete`, `device.snapshot.request`, `gallery.list.request`, `files.list.request`, `notifications.list.request`, `remote.action.request` — all response types are sent back.
- ⚠️ **Each accepted client connection is a state machine with a single in-flight file transfer at a time** (`output`, `target`, `expectedHash` are per-connection fields). The protocol doesn't support two interleaved transfers on one socket. Acceptable for v0.
- ⚠️ **Cancellation**: `while (!token.IsCancellationRequested)` is checked between messages. If the client is mid-chunk, the cancel only takes effect at the next read. Fine.
- 🐛 **No length-prefix framing.** Messages are newline-delimited JSON. A malicious peer that sends a `Content-Length`-style header would break nothing (we don't parse it), but a 200 MB single line **would** allocate 200 MB in `ReadLineAsync`. Not an attack surface in practice (only paired peers can reach this) but it's a hardening miss.
- 🐛 **No SSL/TLS.** Pair code, file contents, device panel data, all in plaintext on the wire. Documented in the protocol spec as a v0 tradeoff. **Anyone on the same L2 segment can sniff everything.**

### 3.2 Android — `CcpNode.listenTcp` / `handleClient`

- Mirrors the Windows state machine. Same issues.
- ✅ Uses `ServerSocket(CCP_TCP_PORT)` with 2 s `soTimeout` so `running=false` is responsive.
- ✅ `socket.tcpNoDelay = true`.
- ⚠️ **`File.appendBytes` is used to accumulate incoming chunks.** This is O(n²) — every chunk writes to a `FileOutputStream` opened on the same `File` handle. For a 100 MB file with 1500 chunks, that's 1500 open-write-close cycles. Better: hold a `FileOutputStream` open for the duration of the transfer. (The receiver is single-threaded per connection, so this is safe.)
- 🐛 **In `file.complete`, `activeFile?.readBytes()` is called twice** when verification passes — once for the hash check, once for `deviceData.saveIncomingFile(activeFile.name, activeFile.readBytes())`. For a 100 MB file that's 200 MB of allocations. Should read once, hash, then save the same `ByteArray`.

### 3.3 End-to-end TCP transfer

**Working scenarios** (LAN, paired peers):
- ✅ Pair request/response.
- ✅ File send (chunked, SHA-256 verified, base64 in JSON, 64 KB chunks).
- ✅ Device panel snapshot, gallery list, files list, notifications list.
- ⚠️ **Notifications list on Windows is always empty** (`permission_granted: false, items: []`) — Windows doesn't have a notification listener. Correct given the platform.
- ⚠️ **Remote actions on Windows are stubbed** — every `remote.action.request` returns `ok: false, "Remote actions are not fully implemented on Windows yet."`. Documented, intentional.

---

## 4. Cloud relay (works for everything, with caveats)

### 4.1 Registration / heartbeat

**Windows (`ConvexService`):**
- ✅ Registers on startup via `devices:registerDevice` with platform, name, public key, capabilities, app version.
- ✅ Heartbeat every 10 s with obfuscated IP hint (`192.168.x.x`).
- ✅ Polls every 3 s.

**Android (`ConvexBridge`):**
- ✅ Same shape.
- ⚠️ `getOrCreatePrivateKey()` stores a 32-byte private key in `SharedPreferences("ccp_convex")` — **plaintext on disk**. Anyone with root or with a backup can extract it and decrypt past/future cloud messages for every paired peer.
- ⚠️ `heartbeatLoop` uses `delay(10_000)` after a `try/catch (_: Exception) {}` that swallows **all** exceptions silently. If Convex is unreachable, the loop keeps retrying with no backoff, and there's no diagnostic that anything is wrong beyond the status bar text.

### 4.2 Discovery via cloud (Long Distance mode)

**Windows (`CcpNode.ToggleCloudModeAsync` → `LoadCloudPeersAsync`):**
- ✅ When user toggles "Long Distance", calls `Convex.ListPairedPeersAsync()` which queries `sessions:listSessions`.
- ✅ For each paired peer, queries `presence:getPresence` to know if online.
- ✅ Queries `devices:getDevice` to get name + platform.
- ✅ Calls `Convex.LoadSessionFromCloudAsync(deviceId)` to decrypt the session key from the Convex-stored blob.
- ✅ Adds each peer to the in-memory `PeerView` list with `IsCloudPeer = true` and a dummy `IPAddress.Loopback`.

**Android:** `Long Distance` is just a **status pill** — there is no equivalent `loadCloudPeers` on the Android side. The Android UI shows "Long Distance / Connecting…" but **doesn't actually populate the device list with cloud peers**. This is an asymmetry: a Windows user with Long Distance on can see paired Android phones that are on a different network; the Android user cannot see paired Windows PCs that are elsewhere. **Asymmetric implementation.**

### 4.3 End-to-end request/response via cloud

Both sides support this, with proper `request_id` correlation:

- **Windows (`ConvexService.SendCloudRequestAsync`):** generates a `request_id` UUID, inserts a `TaskCompletionSource<JsonObject>` into `_pendingRequests[request_id]`, encrypts the payload with the session key, pushes to Convex. The `PollLoopAsync` runs every 3 s, fetches all undelivered messages, decrypts, and:
  - If the payload contains a `request_id` that matches a pending TCS, **removes the TCS from the dict and resolves it**.
  - Otherwise, dispatches the message to `OnMessageReceived` which is handled by `CcpNode.HandleCloudMessage`.

- **Android (`ConvexBridge.pollMessages` + `CcpNode.handleConvexMessage`):** same shape. The Android side **does** correctly copy `request_id` from the incoming request into the response payload (see `if (requestId.isNotBlank()) response.put("request_id", requestId)`), so the Windows TCS does get resolved.

✅ Request/response correlation via cloud works in both directions for the four list/snapshot request types (`device.snapshot`, `gallery.list`, `files.list`, `notifications.list`).

### 4.4 File transfer over cloud is not implemented

**This is the big one.** For a cloud peer on Windows (`peer.IsCloudPeer == true`):

- `CcpNode.SendFileAsync` is called from the UI's `SendFileCommand` when the user picks a file. It opens a real TCP socket via `ConnectPeerAsync` → `RankRoutes(peer)`.
- `RankRoutes` for a cloud peer returns `peer.Routes` (which is `[]` for cloud peers), then falls through to `new PeerRoute { Transport = "direct", Host = peer.Address.ToString(), Port = peer.TcpPort }` — which is `IPAddress.Loopback:0`.
- TCP connect to `127.0.0.1:0` fails. The user sees "Could not connect to <peer>" in the activity log.

**Same problem on Android:** `CcpNode.inspectPeer` and `CcpNode.sendFile` go through `connectPeer` which opens a real TCP socket. For a cloud peer with no routes, the only route is `IPAddress.Loopback:0`, which fails silently. Android has no `*ViaCloudAsync` equivalents of Windows' `GetPeerPanelViaCloudAsync` / `RequestRemoteActionViaCloudAsync`.

**Net result:** Files cannot be sent to cloud peers on either side. **Device panel inspection works from Windows → Android over cloud (uses `GetPeerPanelViaCloudAsync`), but not from Android → Windows (no cloud path on Android).**

### 4.5 Cloud session key exchange

**Works**, with the pseudo-ECDH caveat (SHA-256 over `myPriv || peerPub` is not real Diffie-Hellman). The session key is encrypted with each device's local "machine secret" (PBKDF2 over device_id) before being stored in Convex, so Convex can't decrypt. ✅

### 4.6 Cloud message encryption

- ✅ **Windows**: Real .NET 8 `AesGcm` with 12-byte nonce and 16-byte auth tag.
- ✅ **Android**: `javax.crypto.Cipher` with `AES/GCM/NoPadding` — real AEAD.
- ✅ **Wire format matches**: nonce is base64'd, ciphertext+tag are concatenated and base64'd (16-byte tag appended to ciphertext, then both sides strip the last 16 bytes as the tag).
- ✅ `machineSecret` is 32 bytes (PBKDF2) and the AES-GCM key constructor accepts 16/24/32-byte keys.

---

## 5. What the user can actually do (the operational truth)

| Action                                | LAN, same Wi-Fi          | LAN, different subnets | Via Convex (Long Distance)         |
| ------------------------------------- | ------------------------ | ---------------------- | ---------------------------------- |
| Discover peer                         | ✅ on most home Wi-Fi     | ❌                     | ✅ (Windows side only, on toggle)  |
| Pair                                  | ✅                        | ❌                     | ❌                                 |
| Send file                             | ✅                        | ❌                     | ❌ (Windows says "could not connect") |
| Inspect device panel                  | ✅                        | ❌                     | ✅ from Windows, ❌ from Android    |
| Gallery / files / notifications       | ✅                        | ❌                     | ✅ from Windows, ❌ from Android    |
| Remote action (Wi-Fi panel, dial)     | ✅ on both sides         | ❌                     | ❌ (Windows stubs, no cloud path on Android) |
| Answer call                           | ❌ (Android-only feature) | ❌                    | ❌                                 |
| Notification mirror                   | ✅ from Android          | ❌                     | ❌                                 |

**The cloud relay is essentially a one-way street:** Windows can see and probe paired Android devices that are on a different network, but cannot send files to them, and the Android app has no cloud-discovery at all.

---

## 6. Concrete bugs and broken behaviors to fix

### Critical (breaks the user-visible flow)
1. **Android's `inspectPeer` and `sendFile` go through `connectPeer`** — for a cloud peer, the only route is `IPAddress.Loopback:0`, which fails silently. The Android side has no `*ViaCloudAsync` equivalents of Windows' `GetPeerPanelViaCloudAsync` / `RequestRemoteActionViaCloudAsync`. **Add the cloud path to Android.**
2. **Windows `SendFileAsync` doesn't have a `*ViaCloudAsync` branch** — clicking Send on a cloud peer fails. **Add the cloud file-transfer path on Windows** (push the file in chunks via Convex messages; the protocol already has `file.offer`/`file.chunk`/`file.complete` message types).
3. **Cloud polling latency**: both sides poll every 3 s, so a cloud-relayed action takes 0-3 s of round-trip latency. Acceptable, but the user should know.
4. **Limited broadcast doesn't cross AP isolation** — add **directed-broadcast fallback** to every active subnet on both sides.
5. **Android `socket.broadcast = true` is a no-op** — replace with per-subnet `MulticastSocket` join on `255.255.255.255` (or `224.0.0.1` for mDNS-style discovery). For sending, use per-interface directed broadcasts.

### High (UX / robustness)
6. **`activeFile.appendBytes` re-opens the file on every chunk** — hold a `FileOutputStream` for the lifetime of the transfer.
7. **Double `readBytes()` on file complete** — read once, hash, save.
8. **No exception handling in `broadcastDiscovery` coroutine** — wrap the inner `while` in a try/catch with a small backoff, otherwise one network blip kills discovery forever.
9. **Android's heartbeat swallows all exceptions** — at least log them to the events flow.
10. **Cloud peer file-send UI affordance** — the Windows `SendFileCommand` is enabled when `peer.Trusted == true`, but for a cloud peer it will fail. Disable the button for cloud peers, or wire up the cloud path.
11. **Pseudo-ECDH** — replace with real X25519 (libsodium-net / libsodium-jni / Tink).

### Medium (correctness, not user-visible)
12. **No revoke UI on either side** — `sessions:revokeSession` exists in Convex, no client calls it.
13. **`NotificationListener` doesn't filter its own package's notifications** — the user will see "CCP is connected" notifications show up in the cached list.
14. **Cloud private key in `SharedPreferences` plaintext on Android** — should use `EncryptedSharedPreferences` or Android Keystore.
15. **`IsBluetoothInterface` also matches `NetworkInterfaceType.Ppp`** — remove that condition.
16. **Transport detection is per-discovery, not per-route** — if a peer's Wi-Fi disappears, the cached routes still claim `wifi` is available until the next 3 s discovery packet arrives. Better: probe routes lazily and demote failures.

### Low (cosmetic / docs)
17. **The "bluetooth" label is misleading** — the UI button makes users think Bluetooth Direct is supported. Either implement it (RFCOMM on Android, `InTheHand.Net.Bluetooth` on Windows) or relabel to "Bluetooth tethering" / "Bluetooth PAN".
18. **Cloud transport UI**: the cloud status pill on Windows and the "Long Distance" pill on Android are both shown, but only Windows actually populates cloud peers. The Android pill is a permanent "Connecting…" until paired, which is confusing.

---

## 7. Summary

- **Wi-Fi (infrastructure) and Ethernet**: fully working end-to-end for the features that exist.
- **USB-RNDIS**: works as a side effect of being an IP interface.
- **Bluetooth**: **not a transport**, just a label that lights up when Bluetooth tethering exposes a PAN IP interface. No native Bluetooth sockets anywhere.
- **Cloud (Convex)**: registered, heartbeating, polling, encrypted message queue all work. **The cloud file transfer is missing on both sides; the cloud device-panel inspection is missing on Android.**
- **The most important user-visible bug**: a Windows user who turns on Long Distance can browse a paired Android phone's panel across the internet, but **cannot send files to it** and **cannot trigger remote actions on it** (Windows has a `*ViaCloudAsync` for `RequestRemoteAction` but it always returns "not implemented on Windows yet"). A paired Android user **cannot browse the Windows panel across the internet** at all.

The protocol design and the cloud-relay architecture are sound. The implementation is roughly **80% there for the LAN case**, **~40% there for the cloud case** (only Windows → Android panel inspection actually works over cloud), and **0% there for any real Bluetooth**.
