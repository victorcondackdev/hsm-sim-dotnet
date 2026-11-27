using System.Buffers.Binary;
using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace HsmSim.Wire;

/// <summary>Error codes returned by the hsm-sim-go command processor.</summary>
public static class HsmErrors
{
    /// <summary>Success.</summary>
    public const string Ok = "00";

    /// <summary>PIN, CVV or cryptogram did not verify.</summary>
    public const string VerifyFailed = "01";

    /// <summary>Invalid key type.</summary>
    public const string InvalidKeyType = "04";

    /// <summary>Key parity error.</summary>
    public const string ParityError = "10";

    /// <summary>Invalid input.</summary>
    public const string InvalidInput = "15";

    /// <summary>Decrypted PIN block is malformed.</summary>
    public const string PinBlockError = "20";

    /// <summary>Invalid PIN block format.</summary>
    public const string InvalidPinFormat = "23";

    /// <summary>Key used outside its type.</summary>
    public const string KeyUsageViolation = "27";

    /// <summary>Key token corrupt or wrapped under another LMK.</summary>
    public const string InvalidToken = "33";

    /// <summary>DUKPT error.</summary>
    public const string DukptError = "42";

    /// <summary>Command disabled.</summary>
    public const string CommandDisabled = "68";

    /// <summary>Unknown command.</summary>
    public const string UnknownCommand = "90";

    /// <summary>Internal error (also injected faults).</summary>
    public const string InternalError = "99";
}

/// <summary>An HSM response.</summary>
/// <param name="Header">Echoed request header.</param>
/// <param name="Code">Response code (command with second character incremented).</param>
/// <param name="Error">Two-digit error code.</param>
/// <param name="Fields">Positional fields.</param>
public sealed record HsmResponse(string Header, string Code, string Error, IReadOnlyList<string> Fields)
{
    /// <summary>Whether <see cref="Error"/> is "00".</summary>
    public bool IsOk => Error == HsmErrors.Ok;
}

/// <summary>Encoding of the hsm-sim wire format: 2-byte big-endian length, then ASCII.</summary>
public static class HsmWire
{
    /// <summary>The largest message accepted.</summary>
    public const int MaxMessage = 32 * 1024;

    /// <summary>The response code for a command ("CA" → "CB").</summary>
    public static string ResponseCode(string command)
    {
        ArgumentNullException.ThrowIfNull(command);
        return command.Length != 2 ? "ZZ" : string.Concat(command[0], (char)(command[1] + 1));
    }

    /// <summary>Encodes a request payload: HHHH CC [;field]...</summary>
    /// <exception cref="FormatException">Bad header/command, or a field contains ';'.</exception>
    public static byte[] EncodeRequest(string header, string command, IEnumerable<string> fields)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(fields);
        if (header.Length != 4 || command.Length != 2)
        {
            throw new FormatException("Header must be 4 and command 2 characters.");
        }

        StringBuilder sb = new(header + command);
        foreach (string f in fields)
        {
            if (f.Contains(';', StringComparison.Ordinal) || f.Contains('\0', StringComparison.Ordinal))
            {
                throw new FormatException("Fields cannot contain ';'.");
            }

            sb.Append(';').Append(f);
        }

        byte[] p = Encoding.ASCII.GetBytes(sb.ToString());
        return p.Length > MaxMessage ? throw new FormatException("Message too large.") : p;
    }

    /// <summary>Decodes a response payload: HHHH RR EE [;field]...</summary>
    public static HsmResponse DecodeResponse(ReadOnlySpan<byte> payload)
    {
        string s = Encoding.ASCII.GetString(payload);
        if (s.Length < 8)
        {
            throw new FormatException("Malformed HSM response.");
        }

        string rest = s[8..];
        string[] fields;
        if (rest.Length == 0)
        {
            fields = [];
        }
        else if (rest[0] == ';')
        {
            fields = rest[1..].Split(';');
        }
        else
        {
            throw new FormatException("Malformed HSM response.");
        }

        return new HsmResponse(s[..4], s.Substring(4, 2), s.Substring(6, 2), fields);
    }

    /// <summary>Prefixes a payload with its 2-byte length.</summary>
    public static byte[] Frame(ReadOnlySpan<byte> payload)
    {
        byte[] f = new byte[payload.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(f, (ushort)payload.Length);
        payload.CopyTo(f.AsSpan(2));
        return f;
    }
}

/// <summary>
/// A connection to an hsm-sim-go server. Requests on one client are serialized;
/// open several clients for parallelism, as with a real HSM.
/// </summary>
public sealed class HsmClient : IAsyncDisposable, IDisposable
{
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _seq;

    private HsmClient(TcpClient tcp)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
    }

    /// <summary>Connects to an HSM.</summary>
    public static async Task<HsmClient> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        TcpClient tcp = new() { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }

        return new HsmClient(tcp);
    }

    /// <summary>Sends a command and awaits its response. A cancelled call leaves the connection unusable; dispose it.</summary>
    public async Task<HsmResponse> SendAsync(string command, IEnumerable<string> fields, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _seq = (_seq + 1) % 10000;
            string header = _seq.ToString("D4", CultureInfo.InvariantCulture);
            byte[] frame = HsmWire.Frame(HsmWire.EncodeRequest(header, command, fields));
            await _stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);

            byte[] len = new byte[2];
            await _stream.ReadExactlyAsync(len, cancellationToken).ConfigureAwait(false);
            int n = BinaryPrimitives.ReadUInt16BigEndian(len);
            if (n > HsmWire.MaxMessage)
            {
                throw new FormatException("HSM response too large.");
            }

            byte[] payload = new byte[n];
            await _stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
            HsmResponse resp = HsmWire.DecodeResponse(payload);
            return resp.Header != header
                ? throw new InvalidOperationException($"HSM response header {resp.Header} for request {header}.")
                : resp;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Sends a command with positional fields.</summary>
    public Task<HsmResponse> SendAsync(string command, params string[] fields) => SendAsync(command, fields, CancellationToken.None);

    /// <inheritdoc />
    public void Dispose()
    {
        _stream.Dispose();
        _tcp.Dispose();
        _gate.Dispose();
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
