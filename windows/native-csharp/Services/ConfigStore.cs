using CCP.Windows.Models;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CCP.Windows.Services;

public sealed class ConfigStore
{
    private readonly string _path;
    private ConfigDocument _config;

    public ConfigStore()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CCP");
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "config-windows-native.json");
        _config = TryLoad() ?? ConfigDocument.Create();
        // Migrate: if loaded config is missing a private key, add one
        if (string.IsNullOrWhiteSpace(_config.PrivateKeyB64))
        {
            _config = _config with { PrivateKeyB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) };
        }
        Save();
    }

    private ConfigDocument? TryLoad()
    {
        try
        {
            if (!File.Exists(_path)) return null;
            return JsonSerializer.Deserialize<ConfigDocument>(File.ReadAllText(_path));
        }
        catch
        {
            return null; // Corrupt or old format — start fresh
        }
    }

    public string DeviceId => _config.DeviceId;
    public string DeviceName => _config.DeviceName;
    public SenderInfo Sender => new(DeviceId, DeviceName, "windows");

    /// <summary>32-byte random private key used for cloud key exchange.</summary>
    public byte[] PrivateKey => Convert.FromBase64String(_config.PrivateKeyB64);

    public bool IsTrusted(string deviceId) => _config.TrustedPeers.ContainsKey(deviceId);

    public void Trust(SenderInfo sender)
    {
        _config.TrustedPeers[sender.DeviceId] = sender;
        Save();
    }

    private void Save()
    {
        File.WriteAllText(_path, JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true }));
    }

    private sealed record ConfigDocument
    {
        public required string DeviceId { get; init; }
        public required string DeviceName { get; init; }
        public string PrivateKeyB64 { get; init; } = "";  // not required — migrated on load
        public Dictionary<string, SenderInfo> TrustedPeers { get; init; } = [];

        public static ConfigDocument Create()
        {
            var seed = $"{Environment.MachineName}-{Guid.NewGuid()}";
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed))).ToLowerInvariant();
            return new ConfigDocument
            {
                DeviceId = hash,
                DeviceName = $"{Environment.MachineName} Windows",
                PrivateKeyB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            };
        }
    }
}
