using System.Numerics;
using System.Security.Cryptography;

namespace HsmSim.Fpe;

/// <summary>FF1 format-preserving encryption (NIST SP 800-38G) over AES. Thread-safe.</summary>
public sealed class Ff1 : IDisposable
{
    /// <summary>Radix 10.</summary>
    public const string Digits = "0123456789";

    /// <summary>Radix 36, lower case.</summary>
    public const string Alphanumeric = "0123456789abcdefghijklmnopqrstuvwxyz";

    private const int MaxLength = 256;

    private readonly Aes _aes;
    private readonly object _gate = new();
    private readonly string _alphabet;
    private readonly int[] _index = Enumerable.Repeat(-1, 128).ToArray();

    /// <summary>Creates an FF1 cipher for an AES key and an alphabet (its length is the radix).</summary>
    public Ff1(ReadOnlySpan<byte> key, string alphabet = Digits)
    {
        ArgumentNullException.ThrowIfNull(alphabet);
        if (alphabet.Length is < 2 or > 36)
        {
            throw new ArgumentException("Alphabet must have 2 to 36 distinct symbols.", nameof(alphabet));
        }

        for (int i = 0; i < alphabet.Length; i++)
        {
            char c = alphabet[i];
            if (c >= 128 || _index[c] != -1)
            {
                throw new ArgumentException("Alphabet must have 2 to 36 distinct ASCII symbols.", nameof(alphabet));
            }

            _index[c] = i;
        }

        _alphabet = alphabet;
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
        int min = 2;
        BigInteger p = BigInteger.Pow(Radix, 2);
        while (p < 1_000_000)
        {
            min++;
            p *= Radix;
        }

        MinLength = min;
    }

    /// <summary>The radix.</summary>
    public int Radix => _alphabet.Length;

    /// <summary>The shortest accepted input (domain of at least 10^6).</summary>
    public int MinLength { get; }

    private BigInteger Num(string s)
    {
        BigInteger n = BigInteger.Zero;
        foreach (char c in s)
        {
            n = (n * Radix) + _index[c];
        }

        return n;
    }

    private string Str(BigInteger n, int m)
    {
        char[] output = new char[m];
        for (int i = m - 1; i >= 0; i--)
        {
            n = BigInteger.DivRem(n, Radix, out BigInteger d);
            output[i] = _alphabet[(int)d];
        }

        return new string(output);
    }

    private byte[] Ciph(byte[] block)
    {
        lock (_gate)
        {
            return _aes.EncryptEcb(block, PaddingMode.None);
        }
    }

    private byte[] Prf(byte[] data)
    {
        byte[] y = new byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            for (int j = 0; j < 16; j++)
            {
                y[j] ^= data[i + j];
            }

            y = Ciph(y);
        }

        return y;
    }

    /// <summary>Whether every character of s is in the alphabet.</summary>
    public bool Contains(string s) => s is not null && s.All(c => c < 128 && _index[c] >= 0);

    private void Check(string x)
    {
        ArgumentNullException.ThrowIfNull(x);
        if (x.Length < MinLength || x.Length > MaxLength)
        {
            throw new ArgumentException("Input length out of range for this radix.", nameof(x));
        }

        if (!Contains(x))
        {
            throw new ArgumentException("Input contains a symbol outside the alphabet.", nameof(x));
        }
    }

    /// <summary>Encrypts x under the tweak.</summary>
    public string Encrypt(string x, ReadOnlySpan<byte> tweak) => Crypt(x, tweak.ToArray(), true);

    /// <summary>Decrypts x under the tweak.</summary>
    public string Decrypt(string x, ReadOnlySpan<byte> tweak) => Crypt(x, tweak.ToArray(), false);

    private static byte[] BigEndian(BigInteger v, int length)
    {
        byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (v.IsZero)
        {
            raw = [];
        }

        byte[] output = new byte[length];
        raw.CopyTo(output, length - raw.Length);
        return output;
    }

    private string Crypt(string x, byte[] tweak, bool encrypt)
    {
        Check(x);
        int n = x.Length;
        int t = tweak.Length;
        int u = n / 2;
        int v = n - u;
        string a = x[..u];
        string b = x[u..];

        BigInteger rv = BigInteger.Pow(Radix, v);
        long bitLength = (rv - 1).GetBitLength();
        int bb = (int)((bitLength + 7) / 8);
        int d = (4 * ((bb + 3) / 4)) + 4;

        byte[] p =
        [
            1, 2, 1, (byte)(Radix >> 16), (byte)(Radix >> 8), (byte)Radix, 10, (byte)u,
            (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n,
            (byte)(t >> 24), (byte)(t >> 16), (byte)(t >> 8), (byte)t,
        ];
        int pad = (16 - ((t + bb + 1) % 16)) % 16;
        BigInteger modU = BigInteger.Pow(Radix, u);
        BigInteger modV = rv;

        BigInteger Round(int i, string half)
        {
            byte[] q = [.. tweak, .. new byte[pad], (byte)i, .. BigEndian(Num(half), bb)];
            byte[] r = Prf([.. p, .. q]);
            List<byte> s = [.. r];
            for (int j = 1; s.Count < d; j++)
            {
                byte[] blk = (byte[])r.Clone();
                blk[12] ^= (byte)(j >> 24);
                blk[13] ^= (byte)(j >> 16);
                blk[14] ^= (byte)(j >> 8);
                blk[15] ^= (byte)j;
                s.AddRange(Ciph(blk));
            }

            return new BigInteger(s.Take(d).ToArray(), isUnsigned: true, isBigEndian: true);
        }

        static BigInteger Mod(BigInteger value, BigInteger m)
        {
            BigInteger r = value % m;
            return r.Sign < 0 ? r + m : r;
        }

        if (encrypt)
        {
            for (int i = 0; i < 10; i++)
            {
                BigInteger y = Round(i, b);
                (int m, BigInteger mod) = i % 2 == 0 ? (u, modU) : (v, modV);
                string c = Str(Mod(Num(a) + y, mod), m);
                a = b;
                b = c;
            }
        }
        else
        {
            for (int i = 9; i >= 0; i--)
            {
                BigInteger y = Round(i, a);
                (int m, BigInteger mod) = i % 2 == 0 ? (u, modU) : (v, modV);
                string c = Str(Mod(Num(b) - y, mod), m);
                b = a;
                a = c;
            }
        }

        return a + b;
    }

    /// <inheritdoc />
    public void Dispose() => _aes.Dispose();
}
