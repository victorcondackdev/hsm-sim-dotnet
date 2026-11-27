using System.Numerics;
using System.Security.Cryptography;

namespace HsmSim.Keys;

/// <summary>ISO/IEC 9797-1 padding methods.</summary>
public enum Padding
{
    /// <summary>Zero bytes up to a block boundary (empty data becomes one zero block).</summary>
    Method1 = 1,

    /// <summary>0x80 then zero bytes; always adds at least one byte (EMV).</summary>
    Method2 = 2,
}

/// <summary>
/// Symmetric key primitives for payment cryptography: DES/TDES and AES block
/// operations, odd parity, key check values, key components and the ISO 9797-1
/// and CMAC message authentication codes. Mirrors the Go <c>keys</c> package.
/// </summary>
/// <remarks>
/// TDES is computed as three single-DES passes so that double-length keys with
/// equal halves (legal in payment systems, rejected by <see cref="TripleDES"/>
/// as weak) still work.
/// </remarks>
public static class KeyMaterial
{
    /// <summary>Decodes hex, ignoring spaces.</summary>
    /// <exception cref="FormatException">The text is not valid hex.</exception>
    public static byte[] Hex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return Convert.FromHexString(hex.Replace(" ", "", StringComparison.Ordinal));
    }

    /// <summary>Encodes bytes as upper-case hex.</summary>
    public static string ToHex(ReadOnlySpan<byte> data) => Convert.ToHexString(data);

    private static DES Des(ReadOnlySpan<byte> key)
    {
        DES d = DES.Create();
        d.Key = key.ToArray();
        return d;
    }

    private static void CheckTdesKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (8 or 16 or 24))
        {
            throw new CryptographicException($"TDES key must be 8, 16 or 24 bytes, got {key.Length}.");
        }
    }

    /// <summary>Encrypts one 8-byte block with a DES/TDES key.</summary>
    internal static void TdesBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output, bool encrypt)
    {
        CheckTdesKey(key);
        if (input.Length != 8 || output.Length < 8)
        {
            throw new CryptographicException("DES operates on 8-byte blocks.");
        }

        // Never hand overlapping buffers to the platform cipher: callers often
        // encrypt in place.
        Span<byte> a = stackalloc byte[8];
        Span<byte> b = stackalloc byte[8];
        input.CopyTo(a);
        ReadOnlySpan<byte> k1 = key[..8];
        if (key.Length == 8)
        {
            Pass(k1, a, b, encrypt);
            b.CopyTo(output);
            return;
        }

        ReadOnlySpan<byte> k2 = key.Slice(8, 8);
        ReadOnlySpan<byte> k3 = key.Length == 24 ? key.Slice(16, 8) : k1;
        if (encrypt)
        {
            Pass(k1, a, b, true);
            Pass(k2, b, a, false);
            Pass(k3, a, b, true);
        }
        else
        {
            Pass(k3, a, b, false);
            Pass(k2, b, a, true);
            Pass(k1, a, b, false);
        }

        b.CopyTo(output);
    }

    private static void Pass(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output, bool encrypt)
    {
        using DES d = Des(key);
        if (encrypt)
        {
            d.EncryptEcb(input, output, PaddingMode.None);
        }
        else
        {
            d.DecryptEcb(input, output, PaddingMode.None);
        }
    }

    /// <summary>Encrypts data (a multiple of 8 bytes) with a DES/TDES key in ECB mode.</summary>
    public static byte[] EncryptEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => Ecb(key, data, true);

    /// <summary>Decrypts data with a DES/TDES key in ECB mode.</summary>
    public static byte[] DecryptEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => Ecb(key, data, false);

    private static byte[] Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, bool encrypt)
    {
        if (data.Length % 8 != 0)
        {
            throw new CryptographicException("Data is not a multiple of the block size.");
        }

        byte[] output = new byte[data.Length];
        for (int i = 0; i < data.Length; i += 8)
        {
            TdesBlock(key, data.Slice(i, 8), output.AsSpan(i, 8), encrypt);
        }

        return output;
    }

    /// <summary>Encrypts data with a DES/TDES key in CBC mode; a null IV means zeros.</summary>
    public static byte[] EncryptCbc(ReadOnlySpan<byte> key, byte[]? iv, ReadOnlySpan<byte> data)
    {
        if (data.Length % 8 != 0)
        {
            throw new CryptographicException("Data is not a multiple of the block size.");
        }

        byte[] chain = iv is null ? new byte[8] : (byte[])iv.Clone();
        byte[] output = new byte[data.Length];
        for (int i = 0; i < data.Length; i += 8)
        {
            Xor(chain, data.Slice(i, 8), chain);
            TdesBlock(key, chain, chain, true);
            chain.CopyTo(output, i);
        }

        return output;
    }

    /// <summary>Decrypts data with a DES/TDES key in CBC mode; a null IV means zeros.</summary>
    public static byte[] DecryptCbc(ReadOnlySpan<byte> key, byte[]? iv, ReadOnlySpan<byte> data)
    {
        if (data.Length % 8 != 0)
        {
            throw new CryptographicException("Data is not a multiple of the block size.");
        }

        byte[] chain = iv is null ? new byte[8] : (byte[])iv.Clone();
        byte[] output = new byte[data.Length];
        Span<byte> t = stackalloc byte[8];
        for (int i = 0; i < data.Length; i += 8)
        {
            TdesBlock(key, data.Slice(i, 8), t, false);
            Xor(t, chain, output.AsSpan(i, 8));
            data.Slice(i, 8).CopyTo(chain);
        }

        return output;
    }

    /// <summary>Encrypts data (a multiple of 16 bytes) with an AES key in ECB mode.</summary>
    public static byte[] EncryptAesEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.EncryptEcb(data, PaddingMode.None);
    }

    /// <summary>Decrypts data with an AES key in ECB mode.</summary>
    public static byte[] DecryptAesEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.DecryptEcb(data, PaddingMode.None);
    }

    /// <summary>Returns a ⊕ b.</summary>
    /// <exception cref="ArgumentException">The lengths differ.</exception>
    public static byte[] Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] output = new byte[a.Length];
        Xor(a, b, output);
        return output;
    }

    internal static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> output)
    {
        if (a.Length != b.Length || output.Length < a.Length)
        {
            throw new ArgumentException("XOR of unequal lengths.");
        }

        for (int i = 0; i < a.Length; i++)
        {
            output[i] = (byte)(a[i] ^ b[i]);
        }
    }

    /// <summary>Returns a copy of the key with every byte set to odd parity.</summary>
    public static byte[] FixParity(ReadOnlySpan<byte> key)
    {
        byte[] output = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
        {
            int b = key[i] & 0xFE;
            if (BitOperations.PopCount((uint)b) % 2 == 0)
            {
                b |= 1;
            }

            output[i] = (byte)b;
        }

        return output;
    }

    /// <summary>Reports whether every byte has odd parity.</summary>
    public static bool HasOddParity(ReadOnlySpan<byte> key)
    {
        foreach (byte b in key)
        {
            if (BitOperations.PopCount(b) % 2 == 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The TDES key check value: first three bytes of the key encrypting zeros, as hex.</summary>
    public static string Kcv(ReadOnlySpan<byte> key) => ToHex(EncryptEcb(key, new byte[8]).AsSpan(0, 3));

    /// <summary>The AES key check value of X9.24-1:2017: first five bytes of AES-CMAC over zeros.</summary>
    public static string KcvAes(ReadOnlySpan<byte> key) => ToHex(Mac.Cmac(key, new byte[16]).AsSpan(0, 5));

    /// <summary>XORs key components into a key with fixed parity.</summary>
    /// <exception cref="ArgumentException">Fewer than two components, or lengths differ.</exception>
    public static byte[] Combine(params byte[][] components)
    {
        ArgumentNullException.ThrowIfNull(components);
        if (components.Length < 2)
        {
            throw new ArgumentException("At least two components are required.", nameof(components));
        }

        byte[] acc = (byte[])components[0].Clone();
        foreach (byte[] c in components.Skip(1))
        {
            Xor(acc, c, acc);
        }

        return FixParity(acc);
    }

    /// <summary>Splits a key with odd parity into n random odd-parity components; <see cref="Combine"/> restores it.</summary>
    public static byte[][] Split(ReadOnlySpan<byte> key, int n)
    {
        if (n < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(n), "n must be >= 2.");
        }

        if (!HasOddParity(key))
        {
            throw new ArgumentException("Key must have odd parity.", nameof(key));
        }

        byte[][] comps = new byte[n][];
        byte[] acc = key.ToArray();
        for (int i = 0; i < n - 1; i++)
        {
            comps[i] = FixParity(RandomNumberGenerator.GetBytes(key.Length));
            Xor(acc, comps[i], acc);
        }

        comps[n - 1] = FixParity(acc);
        return comps;
    }

    /// <summary>A random DES/TDES key of 8, 16 or 24 bytes with odd parity.</summary>
    public static byte[] Random(int length)
    {
        if (length is not (8 or 16 or 24))
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        return FixParity(RandomNumberGenerator.GetBytes(length));
    }

    /// <summary>Pads data to a multiple of blockSize with the given method.</summary>
    public static byte[] Pad(ReadOnlySpan<byte> data, int blockSize, Padding padding)
    {
        int len = data.Length + (padding == Padding.Method2 ? 1 : 0);
        int total = len == 0 ? blockSize : (len + blockSize - 1) / blockSize * blockSize;
        byte[] output = new byte[total];
        data.CopyTo(output);
        if (padding == Padding.Method2)
        {
            output[data.Length] = 0x80;
        }

        return output;
    }
}
