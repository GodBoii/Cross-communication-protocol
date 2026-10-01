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

        if (string.IsNullOrWhiteSpace(_config.PrivateKeyB64))
        {
            _config = _config with { PrivateKeyB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) };
        }
        if (string.IsNullOrWhiteSpace(_config.CloudAuthTokenB64))
        {
            _config = _config with { CloudAuthTokenB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) };
        }
        // v1 identity: the device id is bound to the cloud auth token so the
        // Convex backend can verify ownership of the id.
        var derivedId = DeriveDeviceId(_config.CloudAuthTokenB64);
        if (!string.Equals(_config.DeviceId, derivedId, StringComparison.Ordinal))
        {
            _config = _config with { DeviceId = derivedId };
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
            return null;
        }
    }

    public string DeviceId => _config.DeviceId;
    public string DeviceName => _config.DeviceName;
    public SenderInfo Sender => new(DeviceId, DeviceName, "windows");

    public byte[] PrivateKey => Convert.FromBase64String(_config.PrivateKeyB64);
    public string CloudAuthToken => _config.CloudAuthTokenB64;

    public bool IsTrusted(string deviceId) => _config.TrustedPeers.ContainsKey(deviceId);
    public string? PairSecret(string deviceId) =>
        _config.PairSecrets.TryGetValue(deviceId, out var secret) ? secret : null;

    public void Trust(SenderInfo sender, string? pairSecretB64 = null)
    {
        _config.TrustedPeers[sender.DeviceId] = sender;
        if (!string.IsNullOrWhiteSpace(pairSecretB64))
        {
            _config.PairSecrets[sender.DeviceId] = pairSecretB64;
        }
        Save();
    }

    /// <summary>device_id = sha256_hex("ccp-device-id-v1:" + sha256_hex(token)).</summary>
    public static string DeriveDeviceId(string cloudAuthToken) => CcpIdentity.DeriveDeviceId(cloudAuthToken);

    private void Save()
    {
        File.WriteAllText(_path, JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true }));
    }

    private sealed record ConfigDocument
    {
        public required string DeviceId { get; init; }
        public required string DeviceName { get; init; }
        public string PrivateKeyB64 { get; init; } = "";
        public string CloudAuthTokenB64 { get; init; } = "";
        public Dictionary<string, SenderInfo> TrustedPeers { get; init; } = [];
        public Dictionary<string, string> PairSecrets { get; init; } = [];

        public static ConfigDocument Create()
        {
            var seed = $"{Environment.MachineName}-{Guid.NewGuid()}";
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed))).ToLowerInvariant();
            return new ConfigDocument
            {
                DeviceId = hash,
                DeviceName = $"{Environment.MachineName} Windows",
                PrivateKeyB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                CloudAuthTokenB64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            };
        }
    }
}
