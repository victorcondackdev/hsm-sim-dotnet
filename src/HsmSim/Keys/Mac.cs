using System.Security.Cryptography;

namespace HsmSim.Keys;

/// <summary>Message authentication codes used in payment systems.</summary>
public static class Mac
{
    /// <summary>
    /// ISO/IEC 9797-1 MAC algorithm 3 (retail MAC, ANSI X9.19) with a 16-byte key:
    /// single-DES CBC under K1, final block decrypted under K2 and encrypted under K1.
    /// </summary>
    public static byte[] Retail(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Padding padding)
    {
        if (key.Length != 16)
        {
            throw new CryptographicException("Retail MAC key must be 16 bytes.");
        }

        byte[] d = KeyMaterial.Pad(data, 8, padding);
        byte[] h = new byte[8];
        ReadOnlySpan<byte> k1 = key[..8];
        for (int i = 0; i < d.Length; i += 8)
        {
            KeyMaterial.Xor(h, d.AsSpan(i, 8), h);
            KeyMaterial.TdesBlock(k1, h, h, true);
        }

        KeyMaterial.TdesBlock(key.Slice(8, 8), h, h, false);
        KeyMaterial.TdesBlock(k1, h, h, true);
        return h;
    }

    /// <summary>ISO/IEC 9797-1 MAC algorithm 1: CBC-MAC under a DES/TDES key.</summary>
    public static byte[] CbcMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Padding padding)
    {
        byte[] d = KeyMaterial.Pad(data, 8, padding);
        byte[] h = new byte[8];
        for (int i = 0; i < d.Length; i += 8)
        {
            KeyMaterial.Xor(h, d.AsSpan(i, 8), h);
            KeyMaterial.TdesBlock(key, h, h, true);
        }

        return h;
    }

    /// <summary>AES-CMAC (NIST SP 800-38B, RFC 4493), 16-byte tag.</summary>
    public static byte[] Cmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        return CmacCore(16, 0x87, data, (i, o) => aes.EncryptEcb(i.ToArray(), o, PaddingMode.None));
    }

    /// <summary>CMAC over a TDES key, 8-byte tag.</summary>
    public static byte[] TdesCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        byte[] k = key.ToArray();
        return CmacCore(8, 0x1B, data, (i, o) => KeyMaterial.TdesBlock(k, i, o, true));
    }

    private delegate void BlockFn(ReadOnlySpan<byte> input, Span<byte> output);

    private static byte[] CmacCore(int bs, byte rb, ReadOnlySpan<byte> data, BlockFn enc)
    {
        byte[] l = new byte[bs];
        enc(l, l);
        byte[] k1 = ShiftLeft(l, rb);
        byte[] k2 = ShiftLeft(k1, rb);

        int n = (data.Length + bs - 1) / bs;
        bool complete = n > 0 && data.Length % bs == 0;
        if (n == 0)
        {
            n = 1;
        }

        byte[] last = new byte[bs];
        if (complete)
        {
            KeyMaterial.Xor(data.Slice((n - 1) * bs, bs), k1, last);
        }
        else
        {
            ReadOnlySpan<byte> rest = data[((n - 1) * bs)..];
            rest.CopyTo(last);
            last[rest.Length] = 0x80;
            KeyMaterial.Xor(last, k2, last);
        }

        byte[] x = new byte[bs];
        for (int i = 0; i < n - 1; i++)
        {
            KeyMaterial.Xor(x, data.Slice(i * bs, bs), x);
            enc(x, x);
        }

        KeyMaterial.Xor(x, last, x);
        enc(x, x);
        return x;
    }

    private static byte[] ShiftLeft(byte[] input, byte rb)
    {
        byte[] output = new byte[input.Length];
        int carry = 0;
        for (int i = input.Length - 1; i >= 0; i--)
        {
            output[i] = (byte)((input[i] << 1) | carry);
            carry = input[i] >> 7;
        }

        if (carry != 0)
        {
            output[^1] ^= rb;
        }

        return output;
    }

    /// <summary>Compares two MACs in constant time.</summary>
    public static bool Equal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => CryptographicOperations.FixedTimeEquals(a, b);
}
