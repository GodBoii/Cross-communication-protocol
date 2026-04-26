# CCP - Cross-Platform Connectivity Protocol

CCP is a local-first cross-device connectivity project. The repository is split by operating system so each platform can be built from its own folder.

## Folder Layout

```text
android/   Android app source. Open in Android Studio and build APKs here.
windows/   Windows desktop app and backend. Build EXEs here.
linux/     Reserved for future Linux client and .deb packaging.
macos/     Reserved for future macOS client.
ios/       Reserved for future iOS client.
shared/    Protocol docs, message schemas, and cross-platform contracts.
docs/      Architecture and implementation notes.
```

## Current Focus

The first implementation targets Windows and Android:

- LAN discovery over UDP broadcast.
- Device identity and trust-on-first-use pairing.
- Multi-route discovery metadata for Wi-Fi, LAN, USB networking, Bluetooth-backed IP paths, and internet-capable environments.
- TCP control channel with newline-delimited JSON and route fallback across advertised endpoints.
- Chunked file transfer with SHA-256 verification.
- GUI shells for Windows and Android.

See [ccp-v0.md](C:/Users/prajw/Downloads/CCP/shared/protocol/ccp-v0.md) for the protocol and [codebase-walkthrough.md](C:/Users/prajw/Downloads/CCP/docs/codebase-walkthrough.md) for the implementation walkthrough.
