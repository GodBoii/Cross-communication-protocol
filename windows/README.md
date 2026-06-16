# CCP Windows

The Windows client lives entirely in `native-csharp/`. It is a native WPF / .NET 8
app that gives CCP proper Windows integration: file dialogs, tray support,
notifications, startup registration, firewall integration, Windows credential
storage, and access to WinRT / Win32 APIs when needed.

## Build

```powershell
cd windows\native-csharp
dotnet build
dotnet run
```

Publish an EXE later:

```powershell
cd windows\native-csharp
dotnet publish -c Release -r win-x64 --self-contained true
```

The app stores trusted peers, device identity, and the local private key in
`%APPDATA%\CCP\config-windows-native.json`. Files received over the LAN are
saved to `%USERPROFILE%\Downloads\CCP-Inbox\`.
