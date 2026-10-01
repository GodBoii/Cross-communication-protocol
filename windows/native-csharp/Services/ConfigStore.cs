using CCP.Windows.Models;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CCP.Windows.Services;

/// <summary>
/// Persists identity and trust in %APPDATA%\CCP\config-windows-native.json.
///
///  • Secrets (cloud auth token, pair secrets) are encrypted with DPAPI for the
///    current Windows user, so copying the file to another account or machine
///    doesn't reveal them.
///  • Writes go to a temp file and are swapped in atomically, so a crash can't
///    leave a truncated config.
///  • A config that can't be read is moved aside instead of being silently
///    replaced by a new identity.
///  • v1 trust: a peer is trusted only with a pair secret from an approved ECDH
///    pairing. Pre-v1 secrets were sent in clear and are discarded.
/// </summary>
public sealed class ConfigStore
{
    private const string ProtectedPrefix = "dpapi:";
    private static readonly byte[] Entropy = "ccp-config-v1"u8.ToArray();

    private readonly object _lock = new();
    private readonly string _path;
    private ConfigDocument _config;

    public ConfigStore(string? directory = null)
    {
        var root = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CCP");
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "config-windows-native.json");
        _config = TryLoad() ?? ConfigDocument.Create();

        var token = Unprotect(_config.CloudAuthTokenB64);
        if (string.IsNullOrWhiteSpace(token))
        {
            token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }
        CloudAuthToken = token;

        _config = _config with
        {
            // v1 identity: the device id is bound to the cloud auth token so the
            // Convex backend can verify ownership of the id.
            DeviceId = CcpIdentity.DeriveDeviceId(token),
            CloudAuthTokenB64 = Protect(token),
            PrivateKeyB64 = "",
            PairSecrets = [],
        };
        // Peers without a v1 secret are no longer trusted.
        foreach (var id in _config.TrustedPeers.Keys.Where(id => !_config.PairSecretsV1.ContainsKey(id)).ToList())
        {
            _config.TrustedPeers.Remove(id);
        }
        Save();
    }

    public string DeviceId => _config.DeviceId;
    public string DeviceName => _config.DeviceName;
    public string CloudAuthToken { get; }
    public SenderInfo Sender => new(DeviceId, DeviceName, "windows");

    public bool IsTrusted(string deviceId) => PairSecret(deviceId) is not null;

    /// <summary>The 32-byte v1 pair secret, or null when the peer isn't paired.</summary>
    public byte[]? PairSecret(string deviceId)
    {
        lock (_lock)
        {
            if (!_config.PairSecretsV1.TryGetValue(deviceId, out var stored)) return null;
            try
            {
                var secret = Convert.FromBase64String(Unprotect(stored));
                return secret.Length == 32 ? secret : null;
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                return null;
            }
        }
    }

    public SenderInfo? PeerInfo(string deviceId)
    {
        lock (_lock) return _config.TrustedPeers.GetValueOrDefault(deviceId);
    }

    public IReadOnlyList<string> TrustedPeerIds()
    {
        lock (_lock) return _config.PairSecretsV1.Keys.ToList();
    }

    public void Trust(SenderInfo peer, byte[] pairSecret)
    {
        if (pairSecret.Length != 32) throw new ArgumentException("pair secret must be 32 bytes", nameof(pairSecret));
        if (!CcpIdentity.IsValidDeviceId(peer.DeviceId)) throw new ArgumentException("invalid device id", nameof(peer));
        var clean = new SenderInfo(
            peer.DeviceId,
            Truncate(peer.DeviceName, 64),
            Truncate(peer.Platform, 16));
        lock (_lock)
        {
            _config.TrustedPeers[peer.DeviceId] = clean;
            _config.PairSecretsV1[peer.DeviceId] = Protect(Convert.ToBase64String(pairSecret));
            Save();
        }
    }

    public void Forget(string deviceId)
    {
        lock (_lock)
        {
            _config.TrustedPeers.Remove(deviceId);
            _config.PairSecretsV1.Remove(deviceId);
            Save();
        }
    }

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? "Unknown" : value.Length <= max ? value : value[..max];

    private ConfigDocument? TryLoad()
    {
        if (!File.Exists(_path)) return null;
        try
        {
            return JsonSerializer.Deserialize<ConfigDocument>(File.ReadAllText(_path))
                ?? throw new JsonException("empty config");
        }
        catch (Exception ex) when (ex is JsonException or IOException or NotSupportedException)
        {
            // Keep the unreadable file for recovery rather than overwriting it.
            var backup = $"{_path}.corrupt-{DateTime.Now:yyyyMMddHHmmss}";
            try { File.Move(_path, backup); } catch (IOException) { }
            return null;
        }
    }

    private void Save()
    {
        lock (_lock)
        {
            var temp = _path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, _path, overwrite: true);
        }
    }

    private static string Protect(string plaintext)
    {
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(plaintext), Entropy, DataProtectionScope.CurrentUser);
        return ProtectedPrefix + Convert.ToBase64String(data);
    }

    /// <summary>Decrypts a DPAPI value; values from older builds (plain text) are returned as-is.</summary>
    private static string Unprotect(string stored)
    {
        if (string.IsNullOrEmpty(stored)) return "";
        if (!stored.StartsWith(ProtectedPrefix, StringComparison.Ordinal)) return stored;
        var data = Convert.FromBase64String(stored[ProtectedPrefix.Length..]);
        return Encoding.UTF8.GetString(ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser));
    }

    private sealed record ConfigDocument
    {
        public required string DeviceId { get; init; }
        public required string DeviceName { get; init; }
        /// <summary>Unused since v1; kept so older files still deserialize.</summary>
        public string PrivateKeyB64 { get; init; } = "";
        public string CloudAuthTokenB64 { get; init; } = "";
        public Dictionary<string, SenderInfo> TrustedPeers { get; init; } = [];
        /// <summary>Pre-v1 secrets (sent in clear); always emptied on load.</summary>
        public Dictionary<string, string> PairSecrets { get; init; } = [];
        public Dictionary<string, string> PairSecretsV1 { get; init; } = [];

        public static ConfigDocument Create() => new()
        {
            DeviceId = "",
            DeviceName = $"{Environment.MachineName} Windows",
        };
    }
}
