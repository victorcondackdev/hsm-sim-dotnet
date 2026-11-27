using System.Security.Cryptography;
using System.Text;
using HsmSim.Keys;

namespace HsmSim.CardAuth;

/// <summary>Visa CVV/CVC and PVV. All keys are 16-byte TDES keys (key A ‖ key B).</summary>
public static class CardVerification
{
    /// <summary>Service code for CVV2/CVC2.</summary>
    public const string ServiceCvv2 = "000";

    /// <summary>Service code for Visa iCVV.</summary>
    public const string ServiceIcvv = "999";

    internal static bool AllDigits(string? s, int min, int max)
    {
        if (s is null || s.Length < min || s.Length > max)
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

    private static void Key16(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
        {
            throw new CryptographicException("Key must be 16 bytes.");
        }
    }

    /// <summary>Digits 0–9 in order, then A–F mapped to 0–5.</summary>
    internal static string Decimalize(string hex)
    {
        StringBuilder digits = new();
        StringBuilder letters = new();
        foreach (char c in hex)
        {
            if (c <= '9')
            {
                digits.Append(c);
            }
            else
            {
                letters.Append((char)('0' + (c - 'A')));
            }
        }

        return digits.Append(letters).ToString();
    }

    /// <summary>Computes a three-digit CVV for PAN, expiry (YYMM) and service code.</summary>
    /// <exception cref="ArgumentException">Malformed input.</exception>
    public static string Cvv(ReadOnlySpan<byte> key, string pan, string expiry, string serviceCode)
    {
        Key16(key);
        if (!AllDigits(pan, 12, 19) || !AllDigits(expiry, 4, 4) || !AllDigits(serviceCode, 3, 3))
        {
            throw new ArgumentException("Invalid CVV input.");
        }

        string data = (pan + expiry + serviceCode).PadRight(32, '0');
        byte[] b1 = KeyMaterial.Hex(data[..16]);
        byte[] b2 = KeyMaterial.Hex(data[16..]);
        byte[] r = KeyMaterial.EncryptEcb(key[..8], b1);
        r = KeyMaterial.EncryptEcb(key, KeyMaterial.Xor(r, b2));
        return Decimalize(KeyMaterial.ToHex(r))[..3];
    }

    /// <summary>Verifies a CVV in constant time.</summary>
    public static bool VerifyCvv(ReadOnlySpan<byte> key, string pan, string expiry, string serviceCode, string cvv)
        => FixedEquals(Cvv(key, pan, expiry, serviceCode), cvv);

    /// <summary>Computes the four-digit Visa PIN verification value.</summary>
    public static string Pvv(ReadOnlySpan<byte> key, string pan, int pvki, string pin)
    {
        Key16(key);
        if (!AllDigits(pan, 12, 19) || pvki is < 0 or > 9 || !AllDigits(pin, 4, 12))
        {
            throw new ArgumentException("Invalid PVV input.");
        }

        string body = pan[..^1];
        string tsp = body[^11..] + (char)('0' + pvki) + pin[..4];
        byte[] r = KeyMaterial.EncryptEcb(key, KeyMaterial.Hex(tsp));
        return Decimalize(KeyMaterial.ToHex(r))[..4];
    }

    /// <summary>Checks a PIN against a stored PVV.</summary>
    public static bool VerifyPvv(ReadOnlySpan<byte> key, string pan, int pvki, string pin, string pvv)
        => FixedEquals(Pvv(key, pan, pvki, pin), pvv);

    internal static bool FixedEquals(string a, string? b)
        => b is not null && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));
}

/// <summary>IBM 3624 PIN verification with offsets.</summary>
public sealed class Ibm3624
{
    /// <summary>0–9 to themselves, A–F to 0–5.</summary>
    public const string DefaultDecimalization = "0123456789012345";

    private readonly byte[] _key;

    /// <summary>Creates the scheme.</summary>
    /// <param name="key">16-byte PIN verification key.</param>
    /// <param name="decimalization">16 digits; null means <see cref="DefaultDecimalization"/>.</param>
    /// <param name="validationData">Builds 16 hex digits from the PAN; null means 'FFFF' + rightmost 12 PAN digits excluding the check digit.</param>
    public Ibm3624(ReadOnlySpan<byte> key, string? decimalization = null, Func<string, string>? validationData = null)
    {
        if (key.Length != 16)
        {
            throw new CryptographicException("Key must be 16 bytes.");
        }

        _key = key.ToArray();
        Decimalization = decimalization ?? DefaultDecimalization;
        ValidationData = validationData;
        if (!CardVerification.AllDigits(Decimalization, 16, 16))
        {
            throw new ArgumentException("Decimalization table must be 16 digits.", nameof(decimalization));
        }
    }

    /// <summary>The decimalization table.</summary>
    public string Decimalization { get; }

    /// <summary>Custom validation data builder, if any.</summary>
    public Func<string, string>? ValidationData { get; }

    private string Validation(string pan)
    {
        if (ValidationData is not null)
        {
            string v = ValidationData(pan).ToUpperInvariant();
            if (v.Length != 16 || !v.All(Uri.IsHexDigit))
            {
                throw new ArgumentException("Validation data must be 16 hex digits.");
            }

            return v;
        }

        if (!CardVerification.AllDigits(pan, 13, 19))
        {
            throw new ArgumentException("Invalid PAN.");
        }

        string body = pan[..^1];
        return "FFFF" + body[^12..];
    }

    /// <summary>The PIN the issuer assigns with offset 0.</summary>
    public string NaturalPin(string pan, int length)
    {
        if (length is < 4 or > 12)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        string h = KeyMaterial.ToHex(KeyMaterial.EncryptEcb(_key, KeyMaterial.Hex(Validation(pan))));
        char[] output = new char[length];
        for (int i = 0; i < length; i++)
        {
            output[i] = Decimalization[Convert.ToInt32(h[i].ToString(), 16)];
        }

        return new string(output);
    }

    /// <summary>offset = PIN − natural PIN, digit by digit modulo 10.</summary>
    public string Offset(string pan, string pin)
    {
        if (!CardVerification.AllDigits(pin, 4, 12))
        {
            throw new ArgumentException("Invalid PIN.");
        }

        string nat = NaturalPin(pan, pin.Length);
        char[] output = new char[pin.Length];
        for (int i = 0; i < pin.Length; i++)
        {
            output[i] = (char)('0' + (((pin[i] - '0') - (nat[i] - '0') + 10) % 10));
        }

        return new string(output);
    }

    /// <summary>Checks a PIN against a stored offset.</summary>
    public bool Verify(string pan, string pin, string offset)
    {
        ArgumentNullException.ThrowIfNull(pin);
        if (offset is null || offset.Length != pin.Length)
        {
            return false;
        }

        return CardVerification.FixedEquals(Offset(pan, pin), offset);
    }
}
