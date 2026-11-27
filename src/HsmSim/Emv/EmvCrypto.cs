using System.Security.Cryptography;
using HsmSim.Keys;

namespace HsmSim.Emv;

/// <summary>How the application cryptogram is computed.</summary>
public enum CryptogramScheme
{
    /// <summary>EMV common session key per ATC, ISO 9797-1 padding method 2 (Visa CVN 18/22, M/Chip CSK).</summary>
    Cvn18,

    /// <summary>Visa CVN 10: ICC master key used directly, zero padding.</summary>
    Cvn10,
}

/// <summary>The data elements an EMV card MACs, in the order of the recommended minimum CDOL1 set.</summary>
public sealed record EmvTransaction
{
    /// <summary>9F02, amount in minor units.</summary>
    public ulong Amount { get; init; }

    /// <summary>9F03, other amount.</summary>
    public ulong AmountOther { get; init; }

    /// <summary>9F1A, ISO 3166 numeric (Brazil 76).</summary>
    public ushort TerminalCountry { get; init; }

    /// <summary>95, terminal verification results (5 bytes).</summary>
    public byte[] Tvr { get; init; } = new byte[5];

    /// <summary>5F2A, ISO 4217 numeric (BRL 986).</summary>
    public ushort Currency { get; init; }

    /// <summary>9A, YYMMDD.</summary>
    public string Date { get; init; } = "";

    /// <summary>9C, transaction type.</summary>
    public byte Type { get; init; }

    /// <summary>9F37, unpredictable number (4 bytes).</summary>
    public byte[] UnpredictableNumber { get; init; } = new byte[4];

    /// <summary>82, application interchange profile (2 bytes).</summary>
    public byte[] Aip { get; init; } = new byte[2];

    /// <summary>9F36, application transaction counter.</summary>
    public ushort Atc { get; init; }

    /// <summary>The part of 9F10 issuer application data the scheme MACs.</summary>
    public byte[] Iad { get; init; } = [];

    private static byte[] Bcd(ulong v, int n)
    {
        byte[] output = new byte[n];
        for (int i = n - 1; i >= 0; i--)
        {
            ulong lo = v % 10;
            v /= 10;
            ulong hi = v % 10;
            v /= 10;
            output[i] = (byte)((hi << 4) | lo);
        }

        return output;
    }

    /// <summary>The byte string the cryptogram is computed over.</summary>
    /// <exception cref="ArgumentException">Malformed date or element lengths.</exception>
    public byte[] Data()
    {
        if (Date.Length != 6 || !Date.All(char.IsAsciiDigit) || Tvr.Length != 5 || UnpredictableNumber.Length != 4 || Aip.Length != 2)
        {
            throw new ArgumentException("Invalid EMV transaction data.");
        }

        return
        [
            .. Bcd(Amount, 6), .. Bcd(AmountOther, 6), .. Bcd(TerminalCountry, 2), .. Tvr,
            .. Bcd(Currency, 2), .. KeyMaterial.Hex(Date), Type, .. UnpredictableNumber, .. Aip,
            (byte)(Atc >> 8), (byte)Atc, .. Iad,
        ];
    }
}

/// <summary>Issuer-side EMV cryptography: key derivation, ARQC and ARPC.</summary>
public static class EmvCrypto
{
    private static void Key16(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
        {
            throw new CryptographicException("Key must be 16 bytes.");
        }
    }

    /// <summary>ICC master key derivation, EMV Book 2 Annex A1.4.1 option A.</summary>
    public static byte[] DeriveIccKey(ReadOnlySpan<byte> imk, string pan, string? psn = null)
    {
        Key16(imk);
        psn = string.IsNullOrEmpty(psn) ? "00" : psn;
        string s = (pan ?? "") + psn;
        if (pan is null || pan.Length < 12 || psn.Length != 2 || !s.All(char.IsAsciiDigit))
        {
            throw new ArgumentException("Invalid PAN or PSN.");
        }

        s = s.Length > 16 ? s[^16..] : s.PadLeft(16, '0');
        byte[] y = KeyMaterial.Hex(s);
        byte[] zl = KeyMaterial.EncryptEcb(imk, y);
        byte[] inv = y.Select(b => (byte)~b).ToArray();
        byte[] zr = KeyMaterial.EncryptEcb(imk, inv);
        return KeyMaterial.FixParity([.. zl, .. zr]);
    }

    /// <summary>EMV common session key, Book 2 Annex A1.3.</summary>
    public static byte[] SessionKey(ReadOnlySpan<byte> mk, ushort atc)
    {
        Key16(mk);
        byte[] l = new byte[8];
        byte[] r = new byte[8];
        l[0] = r[0] = (byte)(atc >> 8);
        l[1] = r[1] = (byte)atc;
        l[2] = 0xF0;
        r[2] = 0x0F;
        return KeyMaterial.FixParity([.. KeyMaterial.EncryptEcb(mk, l), .. KeyMaterial.EncryptEcb(mk, r)]);
    }

    /// <summary>The ARQC the card computes, given the ICC master key.</summary>
    public static byte[] Arqc(ReadOnlySpan<byte> mk, EmvTransaction transaction, CryptogramScheme scheme)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        byte[] data = transaction.Data();
        return scheme switch
        {
            CryptogramScheme.Cvn18 => Mac.Retail(SessionKey(mk, transaction.Atc), data, Padding.Method2),
            CryptogramScheme.Cvn10 => Mac.Retail(mk, data, Padding.Method1),
            _ => throw new ArgumentOutOfRangeException(nameof(scheme)),
        };
    }

    /// <summary>Recomputes the ARQC from the issuer master key and compares it in constant time.</summary>
    public static bool VerifyArqc(ReadOnlySpan<byte> imk, string pan, string? psn, EmvTransaction transaction, CryptogramScheme scheme, ReadOnlySpan<byte> arqc)
        => Mac.Equal(Arqc(DeriveIccKey(imk, pan, psn), transaction, scheme), arqc);

    /// <summary>ARPC method 1: TDES(key, ARQC ⊕ (ARC ‖ 000000000000)).</summary>
    public static byte[] ArpcMethod1(ReadOnlySpan<byte> key, ReadOnlySpan<byte> arqc, ReadOnlySpan<byte> arc)
    {
        if (arqc.Length != 8 || arc.Length != 2)
        {
            throw new ArgumentException("ARQC must be 8 bytes and ARC 2 bytes.");
        }

        byte[] x = new byte[8];
        arc.CopyTo(x);
        return KeyMaterial.EncryptEcb(key, KeyMaterial.Xor(arqc, x));
    }

    /// <summary>ARPC method 2: first 4 bytes of MAC algorithm 3 (padding 2) over ARQC ‖ CSU ‖ proprietary data.</summary>
    public static byte[] ArpcMethod2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> arqc, ReadOnlySpan<byte> csu, ReadOnlySpan<byte> proprietaryAuthData)
    {
        if (arqc.Length != 8 || csu.Length != 4 || proprietaryAuthData.Length > 8)
        {
            throw new ArgumentException("Invalid ARPC method 2 input.");
        }

        return Mac.Retail(key, [.. arqc, .. csu, .. proprietaryAuthData], Padding.Method2)[..4];
    }
}
