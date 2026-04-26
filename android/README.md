# CCP Android

This folder is now a native Kotlin Android app. Capacitor is no longer the main app path because this project needs deep Android access: foreground services, Wi-Fi discovery, Bluetooth/Wi-Fi Direct later, notification APIs, storage access, and system integrations that are awkward or limited through a web shell.

## Build APK

```powershell
cd android
.\gradlew.bat assembleDebug
```

The debug APK is created at:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

## Current Native Features

- Material 3 Compose UI.
- Foreground service for background connectivity.
- UDP discovery on port `47827`.
- TCP protocol server on port `47828`.
- Pairing and trusted peer storage.
- Chunked file transfer with SHA-256 verification.

