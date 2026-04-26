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
        _config = File.Exists(_path)
            ? JsonSerializer.Deserialize<ConfigDocument>(File.ReadAllText(_path)) ?? ConfigDocument.Create()
            : ConfigDocument.Create();
        Save();
    }

    public string DeviceId => _config.DeviceId;
    public string DeviceName => _config.DeviceName;
    public SenderInfo Sender => new(DeviceId, DeviceName, "windows");

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

    private sealed class ConfigDocument
    {
        public required string DeviceId { get; init; }
        public required string DeviceName { get; init; }
        public Dictionary<string, SenderInfo> TrustedPeers { get; init; } = [];

        public static ConfigDocument Create()
        {
            var seed = $"{Environment.MachineName}-{Guid.NewGuid()}";
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed))).ToLowerInvariant();
            return new ConfigDocument
            {
                DeviceId = hash,
                DeviceName = $"{Environment.MachineName} Windows"
            };
        }
    }
}
