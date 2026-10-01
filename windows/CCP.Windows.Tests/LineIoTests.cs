using System.Text;
using CCP.Windows.Services;
using Xunit;

namespace CCP.Windows.Tests;

public class LineIoTests
{
    private static BoundedLineReader Reader(string text, int max = BoundedLineReader.DefaultMaxBytes) =>
        new(new MemoryStream(Encoding.UTF8.GetBytes(text)), max);

    [Fact]
    public async Task ReadsLinesCrlfAndEof()
    {
        var reader = Reader("one\r\ntwo\nthree");
        Assert.Equal("one", await reader.ReadLineAsync());
        Assert.Equal("two", await reader.ReadLineAsync());
        Assert.Equal("three", await reader.ReadLineAsync());
        Assert.Null(await reader.ReadLineAsync());
    }

    [Fact]
    public async Task DecodesUtf8AcrossBufferBoundaries()
    {
        var text = new string('a', 16 * 1024 - 1) + "✓📁\n";
        Assert.Equal(text.TrimEnd('\n'), await Reader(text).ReadLineAsync());
    }

    [Fact]
    public async Task RejectsOversizedFrames()
    {
        await Assert.ThrowsAsync<FrameTooLargeException>(() => Reader(new string('a', 4096), 1024).ReadLineAsync());
    }

    [Fact]
    public async Task WriterTerminatesFrames()
    {
        var stream = new MemoryStream();
        var writer = new LineWriter(stream);
        await writer.WriteLineAsync("a");
        await writer.WriteLineAsync("b");
        Assert.Equal("a\nb\n", Encoding.UTF8.GetString(stream.ToArray()));
    }
}
