using System.Net;
using System.Net.Sockets;
using System.Text;
using HsmSim.CardAuth;
using HsmSim.Dukpt;
using HsmSim.Emv;
using HsmSim.Keys;
using HsmSim.PinBlocks;
using HsmSim.Tokenization;
using HsmSim.Wire;

namespace HsmSim.Tests;

public class BehaviourTests
{
    private static readonly byte[] Tdes = KeyMaterial.Hex("0123456789ABCDEFFEDCBA9876543210");
    private static readonly byte[] Aes128 = KeyMaterial.Hex("2B7E151628AED2A6ABF7158809CF4F3C");

    [Fact]
    public void EqualHalvesTdesKeyWorks()
    {
        // TripleDES rejects K1 == K2 as weak; payment systems use such keys (they degrade to DES).
        byte[] k = KeyMaterial.Hex("0123456789ABCDEF0123456789ABCDEF");
        byte[] data = KeyMaterial.Hex("0000000000000000");
        Assert.Equal(KeyMaterial.ToHex(KeyMaterial.EncryptEcb(k[..8], data)), KeyMaterial.ToHex(KeyMaterial.EncryptEcb(k, data)));
    }

    [Fact]
    public void SplitCombineRoundTrip()
    {
        byte[] key = KeyMaterial.Random(16);
        for (int n = 2; n <= 5; n++)
        {
            byte[][] comps = KeyMaterial.Split(key, n);
            Assert.All(comps, c => Assert.True(KeyMaterial.HasOddParity(c)));
            Assert.Equal(key, KeyMaterial.Combine(comps));
        }
    }

    [Fact]
    public void CbcRoundTrip()
    {
        byte[] data = Encoding.ASCII.GetBytes("0123456789abcdef");
        Assert.Equal(data, KeyMaterial.DecryptCbc(Tdes, null, KeyMaterial.EncryptCbc(Tdes, null, data)));
    }

    [Theory]
    [InlineData(PinBlockFormat.Iso0)]
    [InlineData(PinBlockFormat.Iso1)]
    [InlineData(PinBlockFormat.Iso2)]
    [InlineData(PinBlockFormat.Iso3)]
    [InlineData(PinBlockFormat.Iso4)]
    public void PinBlockRoundTrip(PinBlockFormat format)
    {
        byte[] key = format == PinBlockFormat.Iso4 ? Aes128 : Tdes;
        foreach (string pin in new[] { "0000", "1234", "123456789012" })
        {
            byte[] enc = PinBlock.Encrypt(format, key, pin, "4111111111111111");
            Assert.Equal(PinBlock.BlockSize(format), enc.Length);
            Assert.Equal(pin, PinBlock.Decrypt(format, key, enc, "4111111111111111"));
        }
    }

    [Fact]
    public void Format4IsBoundToPan()
    {
        byte[] enc = PinBlock.Encrypt(PinBlockFormat.Iso4, Aes128, "1234", "4111111111111111");
        var e = Assert.Throws<PinBlockException>(() => PinBlock.Decrypt(PinBlockFormat.Iso4, Aes128, enc, "4111111111111129"));
        Assert.Equal(PinBlockError.Malformed, e.Error);
    }

    [Theory]
    [InlineData("123")]
    [InlineData("1234567890123")]
    [InlineData("12a4")]
    public void InvalidPinsAreRejected(string pin)
    {
        var e = Assert.Throws<PinBlockException>(() => PinBlock.Encode(PinBlockFormat.Iso0, pin, "4111111111111111"));
        Assert.Equal(PinBlockError.Pin, e.Error);
    }

    [Fact]
    public void TerminalMatchesHost()
    {
        Ksn ksn0 = Ksn.Parse("FFFF9876543210E00000");
        var term = new DukptTerminal(TdesDukpt.Ipek(Tdes, ksn0), ksn0);
        var seen = new HashSet<string>();
        for (int i = 0; i < 200; i++)
        {
            (Ksn ksn, byte[] key) = term.Next(KeyUsage.Pin);
            Assert.Equal(KeyMaterial.ToHex(TdesDukpt.HostKey(Tdes, ksn, KeyUsage.Pin)), KeyMaterial.ToHex(key));
            Assert.True(seen.Add(KeyMaterial.ToHex(key)));
        }
    }

    [Fact]
    public void CounterRules()
    {
        Assert.Equal(0x400, TdesDukpt.NextCounter(0x3FF));
        Assert.Equal(0x800, TdesDukpt.NextCounter(0x7FE));
        Assert.Throws<InvalidOperationException>(() => TdesDukpt.NextCounter(Ksn.MaxCounter));
        Assert.Equal(0x1ABCDE, Ksn.Parse("FFFF9876543210E00000").WithCounter(0x1ABCDE).Counter);
        Assert.Throws<FormatException>(() => Ksn.Parse("FFFF"));
    }

    [Fact]
    public void Ibm3624OffsetsVerify()
    {
        var s = new Ibm3624(Tdes);
        string nat = s.NaturalPin("4123456789012345", 4);
        Assert.Equal("0000", s.Offset("4123456789012345", nat));
        string off = s.Offset("4123456789012345", "9876");
        Assert.True(s.Verify("4123456789012345", "9876", off));
        Assert.False(s.Verify("4123456789012345", "9877", off));
        Assert.False(s.Verify("4123456789012345", "98765", off));
    }

    [Fact]
    public void ArqcStopsVerifyingWhenDataChanges()
    {
        var tx = new EmvTransaction { Amount = 1000, TerminalCountry = 76, Currency = 986, Date = "261127", Atc = 9, Aip = [0x39, 0] };
        byte[] mk = EmvCrypto.DeriveIccKey(Tdes, "4761739001010119", "01");
        byte[] arqc = EmvCrypto.Arqc(mk, tx, CryptogramScheme.Cvn18);
        Assert.True(EmvCrypto.VerifyArqc(Tdes, "4761739001010119", "01", tx, CryptogramScheme.Cvn18, arqc));
        Assert.False(EmvCrypto.VerifyArqc(Tdes, "4761739001010119", "01", tx with { Amount = 1001 }, CryptogramScheme.Cvn18, arqc));
        Assert.False(EmvCrypto.VerifyArqc(Tdes, "4761739001010119", "02", tx, CryptogramScheme.Cvn18, arqc));
    }

    [Fact]
    public void VaultTokensKeepShapeAndFailLuhn()
    {
        using var vault = new TokenVault(VaultKeys.Random());
        foreach (string pan in new[] { "4111111111111111", "5555555555554444", "378282246310005", "4222222222222" })
        {
            string tok = vault.Tokenize(pan);
            Assert.Equal(pan.Length, tok.Length);
            Assert.StartsWith(pan[..6], tok);
            Assert.EndsWith(pan[^4..], tok);
            Assert.False(TokenVault.Luhn(tok));
            Assert.Equal(tok, vault.Tokenize(pan));
            Assert.Equal(pan, vault.Detokenize(tok));
        }

        Assert.Throws<ArgumentException>(() => vault.Tokenize("4111111111111112"));
        Assert.Throws<KeyNotFoundException>(() => vault.Detokenize("4111110000001111"));
        Assert.Equal("411111******1111", TokenVault.Mask("4111111111111111"));
    }

    [Fact]
    public void VaultIsSafeUnderConcurrency()
    {
        using var vault = new TokenVault(VaultKeys.Random());
        string[] tokens = new string[500];
        Parallel.For(0, tokens.Length, i =>
        {
            string body = "411111" + i.ToString("D9", System.Globalization.CultureInfo.InvariantCulture);
            string pan = Enumerable.Range(0, 10).Select(d => body + d).First(TokenVault.Luhn);
            tokens[i] = vault.Tokenize(pan);
        });
        Assert.Equal(tokens.Length, tokens.Distinct().Count());
        Assert.Equal(tokens.Length, vault.Count);
    }

    [Fact]
    public void WireCodec()
    {
        Assert.Equal("0042CW;a;;b", Encoding.ASCII.GetString(HsmWire.EncodeRequest("0042", "CW", new[] { "a", "", "b" })));
        Assert.Throws<FormatException>(() => HsmWire.EncodeRequest("1", "CW", Array.Empty<string>()));
        Assert.Throws<FormatException>(() => HsmWire.EncodeRequest("0001", "CW", new[] { "a;b" }));
        HsmResponse r = HsmWire.DecodeResponse("0001CX00;561"u8);
        Assert.True(r.IsOk);
        Assert.Equal("561", Assert.Single(r.Fields));
        Assert.Empty(HsmWire.DecodeResponse("0001CZ01"u8).Fields);
        Assert.Throws<FormatException>(() => HsmWire.DecodeResponse("0001CX00x"u8));
        Assert.Equal("CB", HsmWire.ResponseCode("CA"));
    }

    [Fact]
    public async Task ClientTalksToAServer()
    {
        // A tiny stand-in server that answers CW with the real CVV.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task server = Task.Run(async () =>
        {
            using TcpClient c = await listener.AcceptTcpClientAsync();
            NetworkStream s = c.GetStream();
            for (int i = 0; i < 2; i++)
            {
                byte[] len = new byte[2];
                await s.ReadExactlyAsync(len);
                byte[] p = new byte[(len[0] << 8) | len[1]];
                await s.ReadExactlyAsync(p);
                string req = Encoding.ASCII.GetString(p);
                string[] f = req[7..].Split(';');
                string cvv = CardVerification.Cvv(Tdes, f[1], f[2], f[3]);
                await s.WriteAsync(HsmWire.Frame(Encoding.ASCII.GetBytes(req[..4] + "CX00;" + cvv)));
            }
        });

        await using HsmClient client = await HsmClient.ConnectAsync("127.0.0.1", port);
        HsmResponse r = await client.SendAsync("CW", "token", "4123456789012345", "8701", "101");
        Assert.True(r.IsOk);
        Assert.Equal("CX", r.Code);
        Assert.Equal("561", r.Fields[0]);
        r = await client.SendAsync("CW", "token", "4123456789012345", "8701", "000");
        Assert.Equal(3, r.Fields[0].Length);
        await server;
    }
}
