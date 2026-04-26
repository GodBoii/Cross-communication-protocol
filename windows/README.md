# CCP Windows

Windows now has two implementations:

- `native-csharp/`: the main Windows direction. This is a native WPF/.NET app for better Windows integration, packaging, notifications, tray behavior, startup tasks, firewall rules, and future OS APIs.
- `ccp_windows.py`: a quick Python compatibility rig that is useful for protocol testing.

Use C# for the real app. Keep Python only for fast experiments.

## Native C# App

Build when the .NET Desktop SDK is installed:

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

The native app stores trusted peers and identity in `%APPDATA%\CCP\config-windows-native.json`.

## Python Test Rig

```powershell
cd windows
python .\ccp_windows.py
```

## Build EXE Later

```powershell
cd windows
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name CCP-Windows .\ccp_windows.py
```

The app stores trusted peers and device identity in `%APPDATA%\CCP\config.json`.
