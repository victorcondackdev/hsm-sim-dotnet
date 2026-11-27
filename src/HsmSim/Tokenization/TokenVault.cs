using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using HsmSim.Fpe;

namespace HsmSim.Tokenization;

/// <summary>The three independent keys a vault needs.</summary>
/// <param name="Fpe">AES key for FF1 token generation.</param>
/// <param name="Data">AES key encrypting PANs at rest (AES-GCM).</param>
/// <param name="Mac">HMAC-SHA-256 key for the PAN index (at least 16 bytes).</param>
public sealed record VaultKeys(byte[] Fpe, byte[] Data, byte[] Mac)
{
    /// <summary>Fresh random 256-bit keys.</summary>
    public static VaultKeys Random() => new(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
}

/// <summary>
/// PAN tokenization vault: tokens keep the BIN and last four digits and fail the Luhn check.
/// PANs are stored AES-GCM encrypted and indexed by HMAC, so the same PAN always gets the same
/// token. Given the same FPE key, tokens are identical to the Go implementation's.
/// </summary>
public sealed class TokenVault : IDisposable
{
    private readonly Ff1 _ff1;
    private readonly AesGcm _gcm;
    private readonly byte[] _mac;
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _byIndex = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (byte[] Nonce, byte[] Sealed, byte[] Tag)> _byToken = new(StringComparer.Ordinal);

    /// <summary>Creates an empty vault.</summary>
    public TokenVault(VaultKeys keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Mac.Length < 16)
        {
            throw new ArgumentException("MAC key must be at least 16 bytes.", nameof(keys));
        }

        _ff1 = new Ff1(keys.Fpe, Ff1.Digits);
        _gcm = new AesGcm(keys.Data, 16);
        _mac = (byte[])keys.Mac.Clone();
    }

    /// <summary>Number of tokens.</summary>
    public int Count => _byToken.Count;

    /// <summary>Luhn check.</summary>
    public static bool Luhn(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return false;
        }

        int sum = 0;
        bool dbl = false;
        for (int i = s.Length - 1; i >= 0; i--)
        {
            char c = s[i];
            if (c is < '0' or > '9')
            {
                return false;
            }

            int d = c - '0';
            if (dbl)
            {
                d *= 2;
                if (d > 9)
                {
                    d -= 9;
                }
            }

            sum += d;
            dbl = !dbl;
        }

        return sum % 10 == 0;
    }

    /// <summary>First six and last four digits visible, the rest masked.</summary>
    public static string Mask(string pan)
    {
        ArgumentNullException.ThrowIfNull(pan);
        return pan.Length < 11 ? new string('*', pan.Length) : pan[..6] + new string('*', pan.Length - 10) + pan[^4..];
    }

    private string Index(string pan) => Convert.ToHexString(HMACSHA256.HashData(_mac, Encoding.ASCII.GetBytes(pan)));

    /// <summary>Returns the token for a PAN, creating it on first use.</summary>
    /// <exception cref="ArgumentException">The PAN is not 13–19 digits with a valid check digit.</exception>
    public string Tokenize(string pan)
    {
        if (pan is null || pan.Length is < 13 or > 19 || !Luhn(pan))
        {
            throw new ArgumentException("PAN must be 13 to 19 digits with a valid Luhn check digit.", nameof(pan));
        }

        string idx = Index(pan);
        lock (_gate)
        {
            if (_byIndex.TryGetValue(idx, out string? existing))
            {
                return existing;
            }

            string bin = pan[..6];
            string mid = pan[6..^4];
            string last = pan[^4..];
            for (int attempt = 0; attempt < 1000; attempt++)
            {
                byte[] tweak = Encoding.ASCII.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{bin}{last}/{attempt}"));
                string candidate = bin + EncryptMiddle(mid, tweak) + last;
                if (Luhn(candidate) || _byToken.ContainsKey(candidate))
                {
                    continue;
                }

                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                byte[] plain = Encoding.ASCII.GetBytes(pan);
                byte[] sealedPan = new byte[plain.Length];
                byte[] tag = new byte[16];
                _gcm.Encrypt(nonce, plain, sealedPan, tag, Encoding.ASCII.GetBytes(candidate));
                _byToken[candidate] = (nonce, sealedPan, tag);
                _byIndex[idx] = candidate;
                return candidate;
            }
        }

        throw new InvalidOperationException("Token space exhausted for this BIN and suffix.");
    }

    private string EncryptMiddle(string mid, byte[] tweak)
    {
        if (mid.Length >= _ff1.MinLength)
        {
            return _ff1.Encrypt(mid, tweak);
        }

        string enc = _ff1.Encrypt(mid.PadLeft(_ff1.MinLength, '0'), tweak);
        return enc[^mid.Length..];
    }

    /// <summary>Returns the PAN behind a token.</summary>
    /// <exception cref="KeyNotFoundException">Unknown token.</exception>
    public string Detokenize(string token)
    {
        if (token is null || token.Length is < 13 or > 19)
        {
            throw new ArgumentException("Malformed token.", nameof(token));
        }

        if (!_byToken.TryGetValue(token, out var rec))
        {
            throw new KeyNotFoundException("Unknown token.");
        }

        byte[] plain = new byte[rec.Sealed.Length];
        _gcm.Decrypt(rec.Nonce, rec.Sealed, rec.Tag, plain, Encoding.ASCII.GetBytes(token));
        return Encoding.ASCII.GetString(plain);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _ff1.Dispose();
        _gcm.Dispose();
    }
}
