using System.Security.Cryptography;
using HsmSim.Keys;

namespace HsmSim.PinBlocks;

/// <summary>ISO 9564-1 PIN block formats.</summary>
public enum PinBlockFormat
{
    /// <summary>PIN ⊕ PAN with 'F' fill (ANSI X9.8).</summary>
    Iso0 = 0,

    /// <summary>PIN with random fill, no PAN.</summary>
    Iso1 = 1,

    /// <summary>PIN with 'F' fill, no PAN (offline ICC PIN only).</summary>
    Iso2 = 2,

    /// <summary>PIN ⊕ PAN with random fill in A–F.</summary>
    Iso3 = 3,

    /// <summary>AES 16-byte block, two-pass encryption bound to the PAN.</summary>
    Iso4 = 4,
}

/// <summary>Why a PIN block operation failed. Malformed blocks are not explained further on purpose.</summary>
public enum PinBlockError
{
    /// <summary>The format is not supported.</summary>
    Format,

    /// <summary>The PIN is not 4 to 12 decimal digits.</summary>
    Pin,

    /// <summary>The PAN is not decimal digits of a usable length.</summary>
    Pan,

    /// <summary>The block does not decode to a valid PIN.</summary>
    Malformed,
}

/// <summary>A PIN block could not be built or decoded.</summary>
public sealed class PinBlockException : Exception
{
    /// <summary>Creates the exception.</summary>
    public PinBlockException(PinBlockError error)
        : base("PIN block error: " + error)
    {
        Error = error;
    }

    /// <summary>Creates the exception (serialization-free default).</summary>
    public PinBlockException()
        : this(PinBlockError.Malformed)
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public PinBlockException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and inner exception.</summary>
    public PinBlockException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The failure category.</summary>
    public PinBlockError Error { get; }
}

/// <summary>Encodes, decodes, encrypts and decrypts ISO 9564-1 PIN blocks (formats 0–4).</summary>
public static class PinBlock
{
    /// <summary>16 for format 4, 8 otherwise.</summary>
    public static int BlockSize(PinBlockFormat format) => format == PinBlockFormat.Iso4 ? 16 : 8;

    private static bool AllDigits(string s, int min, int max)
    {
        if (s.Length < min || s.Length > max)
        {
            return false;
        }

        foreach (char c in s)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] Pack(byte[] nibbles)
    {
        byte[] output = new byte[nibbles.Length / 2];
        for (int i = 0; i < output.Length; i++)
        {
            output[i] = (byte)((nibbles[2 * i] << 4) | nibbles[(2 * i) + 1]);
        }

        return output;
    }

    private static byte[] Unpack(ReadOnlySpan<byte> b)
    {
        byte[] output = new byte[b.Length * 2];
        for (int i = 0; i < b.Length; i++)
        {
            output[2 * i] = (byte)(b[i] >> 4);
            output[(2 * i) + 1] = (byte)(b[i] & 0x0F);
        }

        return output;
    }

    internal static byte[] PanField(string pan)
    {
        if (!AllDigits(pan, 2, int.MaxValue))
        {
            throw new PinBlockException(PinBlockError.Pan);
        }

        string body = pan[..^1];
        if (body.Length > 12)
        {
            body = body[^12..];
        }

        byte[] n = new byte[16];
        int off = 16 - body.Length;
        for (int i = 0; i < body.Length; i++)
        {
            n[off + i] = (byte)(body[i] - '0');
        }

        return Pack(n);
    }

    internal static byte[] PanField4(string pan)
    {
        if (!AllDigits(pan, 1, 19))
        {
            throw new PinBlockException(PinBlockError.Pan);
        }

        int m = 0;
        if (pan.Length < 12)
        {
            pan = pan.PadLeft(12, '0');
        }
        else
        {
            m = pan.Length - 12;
        }

        byte[] n = new byte[32];
        n[0] = (byte)m;
        for (int i = 0; i < pan.Length; i++)
        {
            n[1 + i] = (byte)(pan[i] - '0');
        }

        return Pack(n);
    }

    private static byte[] RandomNibbles(Func<int, byte[]> rnd, int count, byte lo)
    {
        byte[] buf = rnd(count);
        byte[] output = new byte[count];
        int span = 16 - lo;
        for (int i = 0; i < count; i++)
        {
            output[i] = (byte)(lo + (buf[i] % span));
        }

        return output;
    }

    private static byte[] PinField(PinBlockFormat f, string pin, Func<int, byte[]> rnd)
    {
        byte[] n = new byte[16];
        n[0] = (byte)f;
        n[1] = (byte)pin.Length;
        for (int i = 0; i < pin.Length; i++)
        {
            n[2 + i] = (byte)(pin[i] - '0');
        }

        int fill = 14 - pin.Length;
        byte[] rest = f switch
        {
            PinBlockFormat.Iso0 or PinBlockFormat.Iso2 => Enumerable.Repeat((byte)0xF, fill).ToArray(),
            PinBlockFormat.Iso1 => RandomNibbles(rnd, fill, 0),
            PinBlockFormat.Iso3 => RandomNibbles(rnd, fill, 0xA),
            _ => Enumerable.Repeat((byte)0xA, fill).ToArray(),
        };
        rest.CopyTo(n, 2 + pin.Length);
        return Pack(n);
    }

    /// <summary>
    /// Builds the clear PIN block. <paramref name="random"/> returns n random bytes for the
    /// fill of formats 1, 3 and 4; null means a cryptographic RNG. Byte-for-byte the same
    /// consumption as the Go implementation, so a deterministic source gives identical blocks.
    /// </summary>
    public static byte[] Encode(PinBlockFormat format, string pin, string pan, Func<int, byte[]>? random = null)
    {
        ArgumentNullException.ThrowIfNull(pin);
        random ??= RandomNumberGenerator.GetBytes;
        if (!AllDigits(pin, 4, 12))
        {
            throw new PinBlockException(PinBlockError.Pin);
        }

        switch (format)
        {
            case PinBlockFormat.Iso0:
            case PinBlockFormat.Iso3:
                byte[] pf = PinField(format, pin, random);
                return KeyMaterial.Xor(pf, PanField(pan ?? ""));
            case PinBlockFormat.Iso1:
            case PinBlockFormat.Iso2:
                return PinField(format, pin, random);
            case PinBlockFormat.Iso4:
                byte[] head = PinField(format, pin, random);
                return [.. head, .. random(8)];
            default:
                throw new PinBlockException(PinBlockError.Format);
        }
    }

    /// <summary>Extracts the PIN from a clear block, validating control nibble, length, digits and fill.</summary>
    public static string Decode(PinBlockFormat format, ReadOnlySpan<byte> block, string pan)
    {
        if (format is < PinBlockFormat.Iso0 or > PinBlockFormat.Iso4)
        {
            throw new PinBlockException(PinBlockError.Format);
        }

        if (block.Length != BlockSize(format))
        {
            throw new PinBlockException(PinBlockError.Malformed);
        }

        byte[] pf = format switch
        {
            PinBlockFormat.Iso0 or PinBlockFormat.Iso3 => KeyMaterial.Xor(block, PanField(pan ?? "")),
            PinBlockFormat.Iso4 => block[..8].ToArray(),
            _ => block.ToArray(),
        };
        byte[] n = Unpack(pf);
        if (n[0] != (byte)format)
        {
            throw new PinBlockException(PinBlockError.Malformed);
        }

        int l = n[1];
        if (l is < 4 or > 12)
        {
            throw new PinBlockException(PinBlockError.Malformed);
        }

        char[] pin = new char[l];
        for (int i = 0; i < l; i++)
        {
            if (n[2 + i] > 9)
            {
                throw new PinBlockException(PinBlockError.Malformed);
            }

            pin[i] = (char)('0' + n[2 + i]);
        }

        for (int i = 2 + l; i < 16; i++)
        {
            byte v = n[i];
            bool ok = format switch
            {
                PinBlockFormat.Iso0 or PinBlockFormat.Iso2 => v == 0xF,
                PinBlockFormat.Iso3 => v >= 0xA,
                PinBlockFormat.Iso4 => v == 0xA,
                _ => true,
            };
            if (!ok)
            {
                throw new PinBlockException(PinBlockError.Malformed);
            }
        }

        return new string(pin);
    }

    /// <summary>Encodes and encrypts: TDES ECB for formats 0–3, ISO 9564 two-pass AES for format 4.</summary>
    public static byte[] Encrypt(PinBlockFormat format, ReadOnlySpan<byte> key, string pin, string pan, Func<int, byte[]>? random = null)
        => EncryptClear(format, key, Encode(format, pin, pan, random), pan);

    /// <summary>Encrypts an already encoded clear block.</summary>
    public static byte[] EncryptClear(PinBlockFormat format, ReadOnlySpan<byte> key, ReadOnlySpan<byte> clear, string pan)
    {
        if (format != PinBlockFormat.Iso4)
        {
            return KeyMaterial.EncryptEcb(key, clear);
        }

        byte[] af = PanField4(pan ?? "");
        byte[] i = KeyMaterial.EncryptAesEcb(key, clear);
        return KeyMaterial.EncryptAesEcb(key, KeyMaterial.Xor(i, af));
    }

    /// <summary>Decrypts an encrypted block to its clear block.</summary>
    public static byte[] DecryptClear(PinBlockFormat format, ReadOnlySpan<byte> key, ReadOnlySpan<byte> block, string pan)
    {
        if (block.Length != BlockSize(format))
        {
            throw new PinBlockException(PinBlockError.Malformed);
        }

        if (format != PinBlockFormat.Iso4)
        {
            return KeyMaterial.DecryptEcb(key, block);
        }

        byte[] af = PanField4(pan ?? "");
        byte[] i = KeyMaterial.DecryptAesEcb(key, block);
        return KeyMaterial.DecryptAesEcb(key, KeyMaterial.Xor(i, af));
    }

    /// <summary>Decrypts and decodes an encrypted PIN block.</summary>
    public static string Decrypt(PinBlockFormat format, ReadOnlySpan<byte> key, ReadOnlySpan<byte> block, string pan)
        => Decode(format, DecryptClear(format, key, block, pan), pan);
}
