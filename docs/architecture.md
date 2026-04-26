# CCP Architecture

## Step 1: Keep The Wire Protocol Platform-Neutral

Each OS app can use native UI and native OS APIs, but devices must agree on the same network contract. CCP uses JSON control messages and binary-safe file chunks so Windows, Android, Linux, macOS, and iOS can implement the same behavior independently.

## Step 2: Discovery Before Transport

For the first Windows/Android version, discovery is LAN-first:

- UDP broadcast port: `47827`
- TCP session port: `47828`
- Service name: `ccp.v0`

Later phases can add mDNS, BLE advertisements, Wi-Fi Direct, WebRTC, and relay servers without changing the app-level message model.

## Step 3: Pair Before Capabilities

Devices can see each other before they are trusted. A discovered device is not allowed to request clipboard, notification, file, or native OS access until pairing succeeds. The first version uses a short pairing code and stores trusted peers locally. A later version should replace this with signed public-key pairing and TLS certificates.

## Step 4: Transfer Files In Resumable Chunks

Files are described first, accepted or rejected by the receiver, then sent in numbered chunks. Every transfer has:

- `transfer_id`
- filename
- size
- SHA-256 hash
- chunk size
- ordered chunks
- completion verification

The current Windows implementation uses sequential chunks. The protocol leaves room for resume and parallel chunk streams.

## Step 5: Native Access Is A Plugin Layer

Native OS access should be feature-scoped:

- File transfer: filesystem picker and downloads/inbox access.
- Clipboard sync: clipboard APIs and explicit permissions.
- Notifications: Android notification listener, Windows toast listener/sender.
- Remote input: accessibility/input APIs, opt-in only.
- Media control: platform media session APIs.

This keeps powerful features auditable instead of mixing them into the core transport.

## Current Platform Choices

Windows should use C#/.NET WPF first. It gives native Windows UI, file dialogs, notifications, tray support, startup registration, firewall integration, Windows credential storage, and access to WinRT/Win32 APIs when needed. C++ or Rust can still be added later as helper libraries for hot paths or low-level device features.

Android should use Kotlin and the Android SDK directly. This gives foreground services, notification access, Bluetooth, NFC, USB, Wi-Fi APIs, scoped storage, sensors, and system broadcasts. A Capacitor shell can make a UI quickly, but it is not the right base for the OS-level bridge.
