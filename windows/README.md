# CCP Windows

The Windows client lives in `native-csharp/`. It is a native WPF / .NET 8 app. Tests are in `CCP.Windows.Tests/`; they link the WPF-free protocol sources directly, so they run on any OS.

## Build and test

```powershell
dotnet build windows\native-csharp\CCP.Windows.csproj
dotnet test windows\CCP.Windows.Tests\CCP.Windows.Tests.csproj
dotnet run --project windows\native-csharp
```

Publish an EXE:

```powershell
dotnet publish windows\native-csharp -c Release -r win-x64 --self-contained true
```

Set `CCP_CONVEX_URL` to point the app at a different Convex deployment.

## Local data

- `%APPDATA%\CCP\config-windows-native.json` holds the device identity and trusted peers. The cloud auth token and pair secrets are encrypted with DPAPI for the current Windows user. Writes are atomic. An unreadable file is renamed to `*.corrupt-<timestamp>` rather than silently replaced.
- `%APPDATA%\CCP\seen-msg-ids.json` is the relay replay cache.
- Received files go to `%USERPROFILE%\Downloads\CCP-Inbox\`. Incoming files are always confirmed with a prompt first.
