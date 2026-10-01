using System.IO;
using System.Text;

namespace CCP.Windows.Services;

public sealed class FrameTooLargeException(int limit) : IOException($"Frame exceeds {limit} bytes");

/// <summary>
/// Reads UTF-8, newline-delimited frames with a hard size cap so a peer cannot
/// exhaust memory with a line that never ends (StreamReader.ReadLine is unbounded).
/// </summary>
public sealed class BoundedLineReader(Stream stream, int maxBytes = BoundedLineReader.DefaultMaxBytes)
{
    public const int DefaultMaxBytes = 512 * 1024;

    private readonly byte[] _buffer = new byte[16 * 1024];
    private int _start;
    private int _end;

    /// <summary>Returns the next line without terminator, or null at end of stream.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken ct = default)
    {
        using var line = new MemoryStream();
        while (true)
        {
            if (_start == _end)
            {
                _start = 0;
                _end = await stream.ReadAsync(_buffer.AsMemory(), ct).ConfigureAwait(false);
                if (_end == 0)
                {
                    return line.Length == 0 ? null : Encoding.UTF8.GetString(line.GetBuffer(), 0, (int)line.Length);
                }
            }

            var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
            var stop = newline >= 0 ? newline : _end;
            var count = stop - _start;
            if (line.Length + count > maxBytes) throw new FrameTooLargeException(maxBytes);
            line.Write(_buffer, _start, count);
            _start = stop;

            if (newline >= 0)
            {
                _start++; // consume '\n'
                var length = (int)line.Length;
                var bytes = line.GetBuffer();
                if (length > 0 && bytes[length - 1] == (byte)'\r') length--;
                return Encoding.UTF8.GetString(bytes, 0, length);
            }
        }
    }
}

/// <summary>Writes one UTF-8 frame terminated by '\n'; safe for concurrent callers.</summary>
public sealed class LineWriter(Stream stream)
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task WriteLineAsync(string text, CancellationToken ct = default)
    {
        var bytes = Encoding.UTF8.GetBytes(text + "\n");
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }
}
