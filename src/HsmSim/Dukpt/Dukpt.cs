using System.Numerics;
using System.Security.Cryptography;
using HsmSim.Keys;

namespace HsmSim.Dukpt;

/// <summary>A 10-byte DUKPT key serial number with a 21-bit transaction counter.</summary>
public readonly struct Ksn : IEquatable<Ksn>
{
    private readonly byte[] _bytes;

    private Ksn(byte[] bytes) => _bytes = bytes;

    /// <summary>The largest valid counter.</summary>
    public const int MaxCounter = 0x1FFFFF;

    /// <summary>Parses 20 hex digits.</summary>
    /// <exception cref="FormatException">Not 20 hex digits.</exception>
    public static Ksn Parse(string hex)
    {
        byte[] b;
        try
        {
            b = KeyMaterial.Hex(hex ?? "");
        }
        catch (FormatException)
        {
            throw new FormatException("KSN must be 20 hex digits.");
        }

        if (b.Length != 10)
        {
            throw new FormatException("KSN must be 20 hex digits.");
        }

        return new Ksn(b);
    }

    /// <summary>The raw 10 bytes (a copy).</summary>
    public byte[] ToArray() => (byte[])(_bytes ?? new byte[10]).Clone();

    /// <summary>The 21-bit transaction counter.</summary>
    public int Counter
    {
        get
        {
            byte[] b = _bytes ?? new byte[10];
            return ((b[7] << 16) | (b[8] << 8) | b[9]) & MaxCounter;
        }
    }

    /// <summary>Returns this KSN with the counter replaced.</summary>
    public Ksn WithCounter(int counter)
    {
        byte[] b = ToArray();
        counter &= MaxCounter;
        b[7] = (byte)((b[7] & ~0x1F) | (counter >> 16));
        b[8] = (byte)(counter >> 8);
        b[9] = (byte)counter;
        return new Ksn(b);
    }

    /// <inheritdoc />
    public override string ToString() => KeyMaterial.ToHex(_bytes ?? new byte[10]);

    /// <inheritdoc />
    public bool Equals(Ksn other) => ToString() == other.ToString();

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Ksn k && Equals(k);

    /// <inheritdoc />
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);

    /// <summary>Equality.</summary>
    public static bool operator ==(Ksn a, Ksn b) => a.Equals(b);

    /// <summary>Inequality.</summary>
    public static bool operator !=(Ksn a, Ksn b) => !a.Equals(b);
}

/// <summary>DUKPT working key usages.</summary>
public enum KeyUsage
{
    /// <summary>PIN encryption.</summary>
    Pin,

    /// <summary>MAC, request.</summary>
    MacRequest,

    /// <summary>MAC, response.</summary>
    MacResponse,

    /// <summary>Data encryption, request.</summary>
    DataRequest,

    /// <summary>Data encryption, response.</summary>
    DataResponse,
}

/// <summary>TDES DUKPT, ANSI X9.24-1:2009 (host side).</summary>
public static class TdesDukpt
{
    private static readonly byte[] C0 = KeyMaterial.Hex("C0C0C0C000000000C0C0C0C000000000");
    private static readonly byte[] VariantPin = KeyMaterial.Hex("00000000000000FF00000000000000FF");
    private static readonly byte[] VariantMac = KeyMaterial.Hex("000000000000FF00000000000000FF00");
    private static readonly byte[] VariantMacResponse = KeyMaterial.Hex("00000000FF00000000000000FF000000");
    private static readonly byte[] VariantData = KeyMaterial.Hex("0000000000FF00000000000000FF0000");
    private static readonly byte[] VariantDataResponse = KeyMaterial.Hex("000000FF00000000000000FF00000000");

    private static void Check16(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
        {
            throw new CryptographicException("BDK and IPEK must be 16 bytes.");
        }
    }

    /// <summary>Derives the initial PIN encryption key from the BDK and KSN (counter ignored).</summary>
    public static byte[] Ipek(ReadOnlySpan<byte> bdk, Ksn ksn)
    {
        Check16(bdk);
        byte[] reg = ksn.WithCounter(0).ToArray()[..8];
        byte[] left = KeyMaterial.EncryptEcb(bdk, reg);
        byte[] right = KeyMaterial.EncryptEcb(KeyMaterial.Xor(bdk, C0), reg);
        return [.. left, .. right];
    }

    private static byte[] Nrkgp(byte[] key, byte[] reg)
    {
        byte[] Half(byte[] k)
        {
            byte[] kr = k[8..];
            byte[] x = KeyMaterial.Xor(reg, kr);
            KeyMaterial.TdesBlock(k.AsSpan(0, 8), x, x, true);
            return KeyMaterial.Xor(x, kr);
        }

        byte[] right = Half(key);
        byte[] left = Half(KeyMaterial.Xor(key, C0));
        return [.. left, .. right];
    }

    /// <summary>Derives the current transaction key from an IPEK.</summary>
    public static byte[] FromIpek(ReadOnlySpan<byte> ipek, Ksn ksn)
    {
        Check16(ipek);
        byte[] key = ipek.ToArray();
        byte[] reg = ksn.WithCounter(0).ToArray()[2..];
        int counter = ksn.Counter;
        for (int bit = 1 << 20; bit > 0; bit >>= 1)
        {
            if ((counter & bit) == 0)
            {
                continue;
            }

            reg[5] |= (byte)(bit >> 16);
            reg[6] |= (byte)(bit >> 8);
            reg[7] |= (byte)bit;
            key = Nrkgp(key, reg);
        }

        return key;
    }

    /// <summary>Derives the current transaction key from the BDK.</summary>
    public static byte[] Derive(ReadOnlySpan<byte> bdk, Ksn ksn) => FromIpek(Ipek(bdk, ksn), ksn);

    /// <summary>Applies the usage variant to a transaction key.</summary>
    public static byte[] WorkingKey(ReadOnlySpan<byte> transactionKey, KeyUsage usage)
    {
        Check16(transactionKey);
        switch (usage)
        {
            case KeyUsage.Pin:
                return KeyMaterial.Xor(transactionKey, VariantPin);
            case KeyUsage.MacRequest:
                return KeyMaterial.Xor(transactionKey, VariantMac);
            case KeyUsage.MacResponse:
                return KeyMaterial.Xor(transactionKey, VariantMacResponse);
            case KeyUsage.DataRequest:
            case KeyUsage.DataResponse:
                byte[] k = KeyMaterial.Xor(transactionKey, usage == KeyUsage.DataRequest ? VariantData : VariantDataResponse);
                byte[] l = KeyMaterial.EncryptEcb(k, k.AsSpan(0, 8));
                byte[] r = KeyMaterial.EncryptEcb(k, k.AsSpan(8, 8));
                return [.. l, .. r];
            default:
                throw new ArgumentOutOfRangeException(nameof(usage));
        }
    }

    /// <summary>Derives the working key for a usage from the BDK.</summary>
    public static byte[] HostKey(ReadOnlySpan<byte> bdk, Ksn ksn, KeyUsage usage) => WorkingKey(Derive(bdk, ksn), usage);

    /// <summary>Whether a compliant device may use the counter (at most ten one bits).</summary>
    public static bool IsValidCounter(int counter) => counter is > 0 and <= Ksn.MaxCounter && BitOperations.PopCount((uint)counter) <= 10;

    /// <summary>The next valid counter after <paramref name="counter"/>.</summary>
    /// <exception cref="InvalidOperationException">The counter is exhausted.</exception>
    public static int NextCounter(int counter)
    {
        for (int n = counter + 1; n <= Ksn.MaxCounter; n++)
        {
            if (IsValidCounter(n))
            {
                return n;
            }
        }

        throw new InvalidOperationException("DUKPT transaction counter exhausted.");
    }
}

/// <summary>A simulated DUKPT PIN pad (keeps the IPEK; real devices keep future key registers).</summary>
public sealed class DukptTerminal
{
    private readonly byte[] _ipek;

    /// <summary>Loads the terminal with its IPEK and initial KSN.</summary>
    public DukptTerminal(ReadOnlySpan<byte> ipek, Ksn initial)
    {
        if (ipek.Length != 16)
        {
            throw new CryptographicException("IPEK must be 16 bytes.");
        }

        _ipek = ipek.ToArray();
        Ksn = initial.WithCounter(0);
    }

    /// <summary>The KSN of the last transaction.</summary>
    public Ksn Ksn { get; private set; }

    /// <summary>Advances to the next transaction and returns its KSN and working key.</summary>
    public (Ksn Ksn, byte[] Key) Next(KeyUsage usage)
    {
        Ksn = Ksn.WithCounter(TdesDukpt.NextCounter(Ksn.Counter));
        return (Ksn, TdesDukpt.WorkingKey(TdesDukpt.FromIpek(_ipek, Ksn), usage));
    }
}
