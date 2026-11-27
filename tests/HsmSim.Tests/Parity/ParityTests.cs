using HsmSim.CardAuth;
using HsmSim.Dukpt;
using HsmSim.Emv;
using HsmSim.Fpe;
using HsmSim.Keys;
using HsmSim.PinBlocks;
using HsmSim.Tokenization;

namespace HsmSim.Tests.Parity;

/// <summary>Every output must match the Go implementation byte for byte.</summary>
public class ParityTests
{
    private static byte[] H(string s) => KeyMaterial.Hex(s);

    private static string X(byte[] b) => KeyMaterial.ToHex(b);

    [Fact]
    public void TdesKcv()
    {
        foreach (var v in GoVectors.TdesKcv)
        {
            Assert.Equal(v.Kcv, KeyMaterial.Kcv(H(v.Key)));
        }
    }

    [Fact]
    public void AesCmacAndKcv()
    {
        foreach (var v in GoVectors.AesCmac)
        {
            Assert.Equal(v.Cmac, X(Mac.Cmac(H(v.Key), H(v.Data))));
            Assert.Equal(v.KcvAes, KeyMaterial.KcvAes(H(v.Key)));
        }
    }

    [Fact]
    public void DesMacs()
    {
        foreach (var v in GoVectors.Macs)
        {
            Padding p = (Padding)v.Padding;
            Assert.Equal(v.Retail, X(Mac.Retail(H(v.Key), H(v.Data), p)));
            Assert.Equal(v.CbcMac, X(Mac.CbcMac(H(v.Key), H(v.Data), p)));
            Assert.Equal(v.TdesCmac, X(Mac.TdesCmac(H(v.Key), H(v.Data))));
        }
    }

    [Fact]
    public void PinBlocks()
    {
        foreach (var v in GoVectors.PinBlocks)
        {
            var f = (PinBlockFormat)v.Format;
            byte[] fill = H(v.Fill);
            int pos = 0;
            byte[] Next(int n)
            {
                byte[] r = fill[pos..(pos + n)];
                pos += n;
                return r;
            }

            byte[] clear = PinBlock.Encode(f, v.Pin, v.Pan, Next);
            Assert.Equal(v.Clear, X(clear));
            Assert.Equal(v.Encrypted, X(PinBlock.EncryptClear(f, H(v.Key), clear, v.Pan)));
            Assert.Equal(v.Pin, PinBlock.Decrypt(f, H(v.Key), H(v.Encrypted), v.Pan));
        }
    }

    [Fact]
    public void Dukpt()
    {
        foreach (var v in GoVectors.Dukpt)
        {
            Ksn ksn = Ksn.Parse(v.Ksn);
            Assert.Equal(v.Ipek, X(TdesDukpt.Ipek(H(v.Bdk), ksn)));
            byte[] tx = TdesDukpt.Derive(H(v.Bdk), ksn);
            Assert.Equal(v.Transaction, X(tx));
            Assert.Equal(v.Pin, X(TdesDukpt.WorkingKey(tx, KeyUsage.Pin)));
            Assert.Equal(v.MacRequest, X(TdesDukpt.WorkingKey(tx, KeyUsage.MacRequest)));
            Assert.Equal(v.MacResponse, X(TdesDukpt.WorkingKey(tx, KeyUsage.MacResponse)));
            Assert.Equal(v.DataRequest, X(TdesDukpt.WorkingKey(tx, KeyUsage.DataRequest)));
            Assert.Equal(v.DataResponse, X(TdesDukpt.WorkingKey(tx, KeyUsage.DataResponse)));
        }
    }

    [Fact]
    public void Cvv()
    {
        foreach (var v in GoVectors.Cvv)
        {
            Assert.Equal(v.Cvv, CardVerification.Cvv(H(v.Key), v.Pan, v.Expiry, v.Service));
        }
    }

    [Fact]
    public void PvvAndIbm3624()
    {
        foreach (var v in GoVectors.PinVerification)
        {
            Assert.Equal(v.Pvv, CardVerification.Pvv(H(v.Key), v.Pan, v.Pvki, v.Pin));
            var s = new Ibm3624(H(v.Key));
            Assert.Equal(v.Natural, s.NaturalPin(v.Pan, v.Pin.Length));
            Assert.Equal(v.Offset, s.Offset(v.Pan, v.Pin));
            Assert.True(s.Verify(v.Pan, v.Pin, v.Offset));
        }
    }

    [Fact]
    public void Emv()
    {
        foreach (var v in GoVectors.Emv)
        {
            var tx = new EmvTransaction
            {
                Amount = v.Amount,
                TerminalCountry = 76,
                Currency = 986,
                Date = "261127",
                Atc = v.Atc,
                Aip = [0x39, 0x00],
                UnpredictableNumber = H(v.Un),
                Iad = H(v.Iad),
            };
            byte[] mk = EmvCrypto.DeriveIccKey(H(v.Imk), v.Pan, v.Psn);
            Assert.Equal(v.Mk, X(mk));
            byte[] sk = EmvCrypto.SessionKey(mk, v.Atc);
            Assert.Equal(v.Sk, X(sk));
            Assert.Equal(v.Data, X(tx.Data()));
            byte[] a18 = EmvCrypto.Arqc(mk, tx, CryptogramScheme.Cvn18);
            Assert.Equal(v.Arqc18, X(a18));
            Assert.Equal(v.Arqc10, X(EmvCrypto.Arqc(mk, tx, CryptogramScheme.Cvn10)));
            Assert.Equal(v.Arpc1, X(EmvCrypto.ArpcMethod1(sk, a18, "00"u8)));
            Assert.Equal(v.Arpc2, X(EmvCrypto.ArpcMethod2(sk, a18, new byte[] { 0, 0x82, 0, 0 }, ReadOnlySpan<byte>.Empty)));
            Assert.True(EmvCrypto.VerifyArqc(H(v.Imk), v.Pan, v.Psn, tx, CryptogramScheme.Cvn18, a18));
        }
    }

    [Fact]
    public void Ff1Vectors()
    {
        foreach (var v in GoVectors.Ff1)
        {
            using var f = new Ff1(H(v.Key), v.Alphabet);
            Assert.Equal(v.Cipher, f.Encrypt(v.Plain, H(v.Tweak)));
            Assert.Equal(v.Plain, f.Decrypt(v.Cipher, H(v.Tweak)));
        }
    }

    [Fact]
    public void Tokens()
    {
        foreach (var v in GoVectors.Tokens)
        {
            using var vault = new TokenVault(new VaultKeys(H(v.FpeKey), new byte[32], new byte[32]));
            Assert.Equal(v.Token, vault.Tokenize(v.Pan));
            Assert.Equal(v.Pan, vault.Detokenize(v.Token));
        }
    }
}
