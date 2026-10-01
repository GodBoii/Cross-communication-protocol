using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CCP.Windows.Services;
using Xunit;

namespace CCP.Windows.Tests;

public class LanProtocolTests
{
    private static readonly string InitiatorId = new('a', 64);
    private static readonly string ResponderId = new('b', 64);

    private static JsonObject Sender(string id) => new() { ["device_id"] = id, ["device_name"] = "test", ["platform"] = "test" };

    [Fact]
    public void PairingDerivesTheSameSecretAndCodeOnBothSides()
    {
        using var initiator = new PairingInitiator(InitiatorId);
        using var responder = new PairingResponder(ResponderId, InitiatorId, initiator.RequestPayload());
        var i = initiator.OnChallenge(ResponderId, responder.ChallengePayload());
        var r = responder.OnReveal(initiator.RevealPayload());

        Assert.Equal(i.Sas, r.Sas);
        Assert.Equal(i.PairSecret, r.PairSecret);
        Assert.True(i.VerifyResponderConfirm(CcpCrypto.B64(r.ResponderConfirm())));
        Assert.Matches("^[0-9]{6}$", i.Sas);
    }

    [Fact]
    public void ResponderRejectsARevealThatDoesNotMatchTheCommitment()
    {
        using var honest = new PairingInitiator(InitiatorId);
        using var attacker = new PairingInitiator(InitiatorId);
        using var responder = new PairingResponder(ResponderId, InitiatorId, honest.RequestPayload());
        responder.ChallengePayload();
        var ex = Assert.Throws<PairingException>(() => responder.OnReveal(attacker.RevealPayload()));
        Assert.Equal("commitment_mismatch", ex.Message);
    }

    [Theory]
    [InlineData(0, "0000000000000000000000000000000000000000000000000000000000000000", "unsupported_pairing_version")]
    [InlineData(1, "xyz", "invalid_commitment")]
    public void ResponderRejectsBadRequests(int version, string commitment, string reason)
    {
        var ex = Assert.Throws<PairingException>(() =>
            new PairingResponder(ResponderId, InitiatorId, new JsonObject { ["version"] = version, ["commitment"] = commitment }));
        Assert.Equal(reason, ex.Message);
    }

    [Fact]
    public async Task SecureSessionRoundTripsOverRealSockets()
    {
        var secret = CcpCrypto.RandomBytes(32);
        await WithServerAsync(async server =>
        {
            var stream = server.GetStream();
            var reader = new BoundedLineReader(stream);
            var writer = new LineWriter(stream);
            var hello = CcpWire.ParseObject((await reader.ReadLineAsync())!);
            using var conn = (await LanHandshake.ServerAsync(server, reader, writer, Sender(ResponderId), hello,
                id => id == InitiatorId ? secret : null))!;
            var request = (await conn.ReceiveAsync())!;
            await conn.SendAsync(new JsonObject { ["type"] = "echo.response", ["payload"] = CcpWire.Payload(request).DeepClone() });
        }, async port =>
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            using var conn = await LanHandshake.ClientAsync(client, Sender(InitiatorId), ResponderId, secret);
            var reply = await conn.RequestAsync(new JsonObject { ["type"] = "echo", ["payload"] = new JsonObject { ["x"] = "✓" } });
            Assert.Equal("✓", CcpWire.Str(CcpWire.Payload(reply)["x"]));
        });
    }

    [Fact]
    public async Task ServerRefusesUnpairedClients()
    {
        await WithServerAsync(async server =>
        {
            var stream = server.GetStream();
            var reader = new BoundedLineReader(stream);
            var writer = new LineWriter(stream);
            var hello = CcpWire.ParseObject((await reader.ReadLineAsync())!);
            Assert.Null(await LanHandshake.ServerAsync(server, reader, writer, Sender(ResponderId), hello, _ => null));
        }, async port =>
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            var ex = await Assert.ThrowsAsync<SessionRefusedException>(() =>
                LanHandshake.ClientAsync(client, Sender(InitiatorId), ResponderId, CcpCrypto.RandomBytes(32)));
            Assert.Equal("not_paired", ex.Reason);
            client.Dispose();
        });
    }

    [Fact]
    public async Task ImpostorWithWrongSecretIsRejected()
    {
        await WithServerAsync(async server =>
        {
            var stream = server.GetStream();
            var reader = new BoundedLineReader(stream);
            var writer = new LineWriter(stream);
            var hello = CcpWire.ParseObject((await reader.ReadLineAsync())!);
            using var conn = (await LanHandshake.ServerAsync(server, reader, writer, Sender(ResponderId), hello,
                _ => CcpCrypto.RandomBytes(32)))!;
            await Assert.ThrowsAnyAsync<CryptographicException>(() => conn.ReceiveAsync());
            await conn.SendPlainErrorAsync(Sender(ResponderId), "bad_frame");
        }, async port =>
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            using var conn = await LanHandshake.ClientAsync(client, Sender(InitiatorId), ResponderId, CcpCrypto.RandomBytes(32));
            var ex = await Assert.ThrowsAsync<SessionRefusedException>(() =>
                conn.RequestAsync(new JsonObject { ["type"] = "device.snapshot.request" }));
            Assert.Equal("bad_frame", ex.Reason);
        });
    }

    [Fact]
    public void IncomingTransferValidatesOffersAndChunks()
    {
        var data = Enumerable.Range(0, 150_000).Select(i => (byte)(i % 251)).ToArray();
        const int chunkSize = 64 * 1024;
        JsonObject Offer(string id) => new()
        {
            ["transfer_id"] = id,
            ["filename"] = "..\\..\\evil\u0000name.txt",
            ["size"] = data.Length,
            ["sha256"] = CcpCrypto.Hex(CcpCrypto.Sha256(data)),
            ["chunk_size"] = chunkSize,
            ["total_chunks"] = TransferLimits.ChunkCount(data.Length, chunkSize),
        };

        Assert.Null(IncomingTransfer.ValidateOffer(Offer("t1")));
        Assert.Equal("file_too_large", IncomingTransfer.ValidateOffer(Offer("t1"), maxBytes: 10));
        var badCount = Offer("t1"); badCount["total_chunks"] = 1;
        Assert.Equal("invalid_total_chunks", IncomingTransfer.ValidateOffer(badCount));

        var inbox = Directory.CreateTempSubdirectory("ccp-inbox").FullName;
        try
        {
            var chunks = data.Chunk(chunkSize).ToArray();
            using (var transfer = IncomingTransfer.Create(inbox, Offer("t1")))
            {
                Assert.Equal("_.._evil_name.txt", transfer.DisplayName);
                Assert.Throws<InvalidDataException>(() => transfer.Append(1, chunks[1], CcpCrypto.Hex(CcpCrypto.Sha256(chunks[1]))));
                for (var i = 0; i < chunks.Length; i++) transfer.Append(i, chunks[i], CcpCrypto.Hex(CcpCrypto.Sha256(chunks[i])));
                Assert.True(transfer.Finish());
                var saved = transfer.MoveTo(Path.Combine(inbox, "out"));
                Assert.Equal(data, File.ReadAllBytes(saved));
            }

            var truncated = IncomingTransfer.Create(inbox, Offer("t2"));
            truncated.Append(0, chunks[0], CcpCrypto.Hex(CcpCrypto.Sha256(chunks[0])));
            Assert.False(truncated.Finish());
            truncated.Discard();
            Assert.False(File.Exists(truncated.TempPath));
        }
        finally
        {
            Directory.Delete(inbox, recursive: true);
        }
    }

    [Theory]
    [InlineData("...", "received-file")]
    [InlineData("photo.jpg", "photo.jpg")]
    [InlineData("CON.txt", "_CON.txt")]
    [InlineData("a/b\\c", "a_b_c")]
    public void SafeFilenameNeutralisesHostileNames(string input, string expected) =>
        Assert.Equal(expected, TransferLimits.SafeFilename(input));

    private static async Task WithServerAsync(Func<TcpClient, Task> serve, Func<int, Task> client)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () =>
            {
                using var accepted = await listener.AcceptTcpClientAsync();
                await serve(accepted);
            });
            await client(port);
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            listener.Stop();
        }
    }
}
