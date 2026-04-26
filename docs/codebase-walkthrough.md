# CCP Codebase Walkthrough

This document explains the current Windows and Android implementation as code, not just as architecture ideas.

## 1. Repository Structure

The repository is split by platform:

- `shared/`: protocol contract and schemas.
- `android/`: native Kotlin Android app.
- `windows/native-csharp/`: native WPF Windows app.
- `windows/ccp_windows.py`: Python prototype kept as a fast protocol test rig.
- `docs/`: implementation notes and design explanations.

That split is intentional. The user workflow is:

- `cd android` to build APKs.
- `cd windows/native-csharp` to build Windows binaries.
- later, the same pattern can apply to `linux/`, `macos/`, and `ios/`.

## 2. Shared Protocol

The protocol is defined in [ccp-v0.md](C:/Users/prajw/Downloads/CCP/shared/protocol/ccp-v0.md). In code, both native apps use the same ideas:

- UDP broadcast discovery on `47827`
- TCP control and transfer channel on `47828`
- newline-delimited JSON control messages
- chunked file transfer
- SHA-256 integrity checks

The protocol is LAN-first. Right now there is no BLE, mDNS, relay server, TURN, WebRTC, or TLS. That is a conscious first-stage tradeoff so the native apps can connect quickly and predictably on the same network.

## 3. Windows Native App

The native Windows code lives in [windows/native-csharp](C:/Users/prajw/Downloads/CCP/windows/native-csharp).

### UI layer

[MainWindow.xaml](C:/Users/prajw/Downloads/CCP/windows/native-csharp/MainWindow.xaml) defines the desktop surface:

- top status band
- nearby device list
- pair action
- send file action
- activity feed
- footer status

The UI is WPF, which is a sensible first native Windows choice because it gives:

- standard file dialogs
- real desktop window behavior
- easy packaging through .NET
- access to Windows APIs later

[MainWindow.xaml.cs](C:/Users/prajw/Downloads/CCP/windows/native-csharp/MainWindow.xaml.cs) is the bridge between UI and backend:

- creates the `CcpNode`
- exposes `PairCommand`, `SendFileCommand`, and `RefreshCommand`
- receives peer updates and event log messages from the backend
- marshals backend callbacks back onto the WPF dispatcher thread

### Data model

[Models/PeerView.cs](C:/Users/prajw/Downloads/CCP/windows/native-csharp/Models/PeerView.cs) is the device model shown in the UI. It contains:

- stable device identity
- display name
- platform
- IP address and TCP port
- trust state
- last seen time

It also exposes display helpers like `EndpointLabel`, `PlatformInitial`, and `BadgeBrush` so the XAML stays clean.

[Models/CcpMessages.cs](C:/Users/prajw/Downloads/CCP/windows/native-csharp/Models/CcpMessages.cs) defines the protocol envelope types:

- `SenderInfo`
- `CcpMessage`

This is the typed contract the C# backend serializes and deserializes on the wire.

### Persistence

[Services/ConfigStore.cs](C:/Users/prajw/Downloads/CCP/windows/native-csharp/Services/ConfigStore.cs) owns local identity and trust persistence.

It stores:

- generated `device_id`
- friendly device name
- trusted peers

The file is written to `%APPDATA%\CCP\config-windows-native.json`.

This is the Windows trust anchor right now. It is basic but practical for a v0 system.

### Networking backend

[Services/CcpNode.cs](C:/Users/prajw/Downloads/CCP/windows/native-csharp/Services/CcpNode.cs) is the real core of the Windows app.

Its responsibilities are:

1. Broadcast discovery packets every 3 seconds.
2. Listen for other devices broadcasting discovery.
3. Maintain the in-memory peer table.
4. Accept incoming TCP connections.
5. Send pairing requests and process pairing responses.
6. Offer files, stream chunks, and confirm transfer integrity.
7. Receive files into `Downloads\CCP-Inbox`.

Important implementation details:

- Discovery is stateless UDP broadcast.
- Pairing uses a short code plus user confirmation on Windows.
- File chunks are base64 inside JSON for now.
- Full-file integrity is checked with SHA-256 at completion.
- Incoming filenames are sanitized and uniqued so files do not overwrite each other.
- The backend now has a helper to normalize string values from JSON payloads, which matters because `System.Text.Json` deserializes payload values as `JsonElement`.

That last point is one of the subtle C# issues that was easy to miss. Without handling `JsonElement` properly, string payload fields such as `sha256`, `pair_code`, or `filename` become fragile.

## 4. Android Native App

The native Android implementation lives under [android/app/src/main/java/com/ccp/android](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android).

### Activity and UI

[MainActivity.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/MainActivity.kt) is the app entry point.

It does four things:

1. Gets the shared `CcpNode` instance.
2. Starts the foreground service.
3. Requests notification permission on Android 13+.
4. Renders the Compose UI.

The Compose screen shows:

- nearby devices
- pair button
- send button
- scrolling activity feed

Files are selected via `OpenDocument`, then read into memory and sent through the node.

### Foreground service

[CcpForegroundService.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/CcpForegroundService.kt) keeps the networking stack alive in the background.

This is important on Android because long-running local connectivity features are not reliable if they only live inside the activity lifecycle.

The service:

- creates a notification channel
- starts foreground execution
- ensures the node is running
- now stops the node on service destruction

### Shared app graph

[AppGraph.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/AppGraph.kt) is a simple singleton holder for the `CcpNode`.

This avoids creating one node in the activity and another in the service.

### Protocol and persistence

[CcpProtocol.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/CcpProtocol.kt) contains:

- constants
- `DeviceInfo`
- SHA-256 helper
- JSON envelope builder
- discovery packet builder

[PeerStore.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/PeerStore.kt) plays the same role as the Windows config store:

- stable local `device_id`
- local `device_name`
- trusted peer entries

It uses `SharedPreferences`, which is appropriate for the current data size.

### Networking backend

[CcpNode.kt](C:/Users/prajw/Downloads/CCP/android/app/src/main/java/com/ccp/android/CcpNode.kt) mirrors the Windows backend responsibilities:

- UDP discovery broadcast
- UDP discovery listener
- TCP listener
- outbound pair requests
- outbound file send
- inbound file receive
- event log updates
- peer state updates

Recent fixes here matter:

- the node now has an actual `running` flag rather than endless `while (true)` loops
- UDP and TCP listeners use timeouts so they can stop cleanly
- incoming filenames are sanitized
- duplicate received filenames are uniqued
- the unnecessary non-null assertions were removed
- the deprecated send icon was replaced with the auto-mirrored version

That makes the Android side less brittle during service restarts and repeated app launches.

## 5. Python Prototype

[windows/ccp_windows.py](C:/Users/prajw/Downloads/CCP/windows/ccp_windows.py) is still useful even though C# is now the main Windows path.

It gives:

- a quick protocol sanity check
- a reference implementation of the wire behavior
- a backup test surface if the WPF app is mid-refactor

It is not the long-term Windows product surface because Python will be weaker than C# for native Windows integration.

## 6. Current End-to-End Flow

When everything is running on the same LAN, the flow is:

1. Windows and Android broadcast discovery packets over UDP.
2. Each side builds a local peer list from incoming packets.
3. The user chooses a peer and initiates pairing.
4. The receiver decides whether to trust that peer.
5. Trusted peers are persisted locally.
6. File sending starts with a `file.offer`.
7. The receiver accepts or rejects the transfer.
8. Chunks are sent in order.
9. The receiver writes chunks to disk.
10. Full-file SHA-256 is checked at completion.
11. Success or failure is reported in the activity feed.

## 7. What Is Still Missing

The codebase is now in a working v0 shape, but it is not finished in the larger product sense.

Major missing areas include:

- transport encryption
- signed identity keys
- certificate or trust revocation
- clipboard sync
- notification mirroring
- remote input
- media control
- mDNS or BLE discovery
- Wi-Fi Direct
- transfer resume
- streaming large files without full in-memory buffering on Android sends
- richer permission UX on Android for inbound approvals

Those are the right next layers, but they belong on top of this current native transport foundation rather than replacing it.
