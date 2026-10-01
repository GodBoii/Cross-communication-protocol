using System.IO;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace CCP.Windows.Services;

public static class TransferLimits
{
    public const long MaxLanFileBytes = 4L * 1024 * 1024 * 1024;
    /// <summary>Each cloud chunk is a relay message, so relay transfers are capped lower.</summary>
    public const long MaxCloudFileBytes = 100L * 1024 * 1024;
    public const int MaxChunkSize = 256 * 1024;
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(10);

    public static int ChunkCount(long size, int chunkSize) => (int)((size + chunkSize - 1) / chunkSize);

    /// <summary>Strips path separators, reserved/control characters, leading dots, and caps the length.</summary>
    public static string SafeFilename(string? name)
    {
        var invalid = Path.GetInvalidFileNameChars().Concat("<>:\"/\\|?*").ToHashSet();
        var chars = (name ?? "").Select(c => invalid.Contains(c) || char.IsControl(c) ? '_' : c).ToArray();
        var cleaned = new string(chars).Trim().TrimStart('.').Trim();
        if (cleaned.Length > 120)
        {
            cleaned = cleaned[..120];
            if (char.IsHighSurrogate(cleaned[^1])) cleaned = cleaned[..^1];
        }
        // Windows reserved device names (CON, NUL, COM1, ...) can't be created as files.
        var stem = Path.GetFileNameWithoutExtension(cleaned).ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL" || (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && char.IsDigit(stem[3])))
        {
            cleaned = "_" + cleaned;
        }
        return cleaned.Length == 0 ? "received-file" : cleaned;
    }

    public static string UniquePath(string path)
    {
        if (!File.Exists(path)) return path;
        var dir = Path.GetDirectoryName(path)!;
        var name = Path.GetFileNameWithoutExtension(path);
        var ext = Path.GetExtension(path);
        for (var i = 1; ; i++)
        {
            var candidate = Path.Combine(dir, $"{name}-{i}{ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }
}

/// <summary>Throttles progress logging to roughly every 10%.</summary>
public sealed class ProgressReporter(long total, Action<int> report)
{
    private int _lastBucket = -1;

    public void Update(long done)
    {
        var percent = total <= 0 ? 100 : (int)(done * 100 / total);
        if (percent / 10 == _lastBucket) return;
        _lastBucket = percent / 10;
        report(percent);
    }
}

/// <summary>
/// An inbound transfer streamed to a temp file. Chunks must arrive in order,
/// match their hash, and never exceed the offer; the file hash is computed
/// incrementally. Not thread-safe; callers serialise access.
/// </summary>
public sealed class IncomingTransfer : IDisposable
{
    private readonly FileStream _output;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly int _chunkSize;
    private readonly string _expectedHash;

    public string TransferId { get; }
    public string DisplayName { get; }
    public string TempPath { get; }
    public long DeclaredSize { get; }
    public int TotalChunks { get; }
    public int NextIndex { get; private set; }
    public long Received { get; private set; }
    public DateTime LastActivity { get; private set; } = DateTime.UtcNow;

    private IncomingTransfer(string inbox, JsonObject offer)
    {
        Directory.CreateDirectory(inbox);
        TransferId = CcpWire.Str(offer["transfer_id"]);
        DisplayName = TransferLimits.SafeFilename(CcpWire.Str(offer["filename"], "received-file"));
        TempPath = Path.Combine(inbox, $"{Guid.NewGuid()}.part");
        DeclaredSize = CcpWire.Long(offer["size"]);
        _chunkSize = (int)CcpWire.Long(offer["chunk_size"]);
        TotalChunks = (int)CcpWire.Long(offer["total_chunks"]);
        _expectedHash = CcpWire.Str(offer["sha256"]).ToLowerInvariant();
        _output = new FileStream(TempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024);
    }

    /// <summary>Returns a refusal reason, or null if the offer is acceptable.</summary>
    public static string? ValidateOffer(JsonObject offer, long maxBytes = TransferLimits.MaxLanFileBytes)
    {
        var transferId = CcpWire.Str(offer["transfer_id"]);
        if (transferId.Length is 0 or > 64) return "invalid_transfer_id";
        var size = CcpWire.Long(offer["size"]);
        if (size < 0) return "invalid_size";
        if (size > maxBytes) return "file_too_large";
        var chunkSize = CcpWire.Long(offer["chunk_size"], 0);
        if (chunkSize < 1 || chunkSize > TransferLimits.MaxChunkSize) return "invalid_chunk_size";
        if (CcpWire.Long(offer["total_chunks"]) != TransferLimits.ChunkCount(size, (int)chunkSize)) return "invalid_total_chunks";
        if (!CcpIdentity.IsValidDeviceId(CcpWire.Str(offer["sha256"]).ToLowerInvariant())) return "invalid_sha256"; // 64-hex
        return null;
    }

    /// <summary>Call only after <see cref="ValidateOffer"/> returned null.</summary>
    public static IncomingTransfer Create(string inbox, JsonObject offer) => new(inbox, offer);

    /// <summary>Synchronous so relay chunks are applied strictly in arrival order.</summary>
    public void Append(int index, byte[] chunk, string chunkSha256)
    {
        if (index != NextIndex) throw new InvalidDataException($"Unexpected chunk {index}; expected {NextIndex}");
        if (index >= TotalChunks) throw new InvalidDataException("More chunks than offered");
        if (chunk.Length > _chunkSize) throw new InvalidDataException("Chunk larger than offered chunk size");
        if (Received + chunk.Length > DeclaredSize) throw new InvalidDataException("More data than offered");
        if (!string.Equals(CcpCrypto.Hex(CcpCrypto.Sha256(chunk)), chunkSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Chunk checksum mismatch");
        }
        _output.Write(chunk);
        _hash.AppendData(chunk);
        Received += chunk.Length;
        NextIndex++;
        LastActivity = DateTime.UtcNow;
    }

    /// <summary>Closes the file; true only if every chunk arrived and the full hash matches.</summary>
    public bool Finish()
    {
        _output.Dispose();
        return NextIndex == TotalChunks &&
               Received == DeclaredSize &&
               CcpCrypto.Hex(_hash.GetHashAndReset()) == _expectedHash;
    }

    /// <summary>Moves the verified temp file into <paramref name="directory"/> under its display name.</summary>
    public string MoveTo(string directory)
    {
        Directory.CreateDirectory(directory);
        var target = TransferLimits.UniquePath(Path.Combine(directory, DisplayName));
        File.Move(TempPath, target);
        return target;
    }

    public void Discard()
    {
        Dispose();
        try { File.Delete(TempPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    public void Dispose()
    {
        _output.Dispose();
        _hash.Dispose();
    }
}
