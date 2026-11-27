// An acquirer and an issuer written in .NET, talking to the hsm-sim-go server.
// The card and the PIN pad are simulated locally with the HsmSim library; every
// cryptogram they produce is verified by the Go HSM over TCP.
//
//   go run github.com/victorcondackdev/hsm-sim-go/cmd/hsm-sim@latest -addr :1500
//   dotnet run --project samples/HsmSim.Demo -- localhost 1500
using System.Globalization;
using HsmSim.CardAuth;
using HsmSim.Dukpt;
using HsmSim.Emv;
using HsmSim.Keys;
using HsmSim.PinBlocks;
using HsmSim.Wire;

const string TestKey = "0123456789ABCDEFFEDCBA9876543210";
const string Pan = "4761739001010119";
const string Pin = "2580";

string host = args.Length > 0 ? args[0] : "localhost";
int port = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : 1500;

await using HsmClient hsm = await HsmClient.ConnectAsync(host, port);

async Task<IReadOnlyList<string>> Run(string command, params string[] fields)
{
    HsmResponse r = await hsm.SendAsync(command, fields);
    if (!r.IsOk)
    {
        throw new InvalidOperationException($"{command} answered {r.Code} error {r.Error}");
    }

    return r.Fields;
}

IReadOnlyList<string> nc = await Run("NC");
Console.WriteLine($"connected to {nc[1]} (LMK KCV {nc[0]})");

Console.WriteLine("== key ceremony ==");
async Task<string> Import(string type, string hex)
{
    IReadOnlyList<string> f = await Run("A6", type, hex);
    Console.WriteLine($"  {type}  KCV {f[1]}");
    return f[0];
}

string bdk = await Import("B0", TestKey);
byte[] zpkClear = KeyMaterial.FixParity(KeyMaterial.Hex("1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A"));
string zpk = await Import("P0", KeyMaterial.ToHex(zpkClear));
string pvk = await Import("V0", TestKey);
string cvk = await Import("C0", TestKey);
string imk = await Import("E0", TestKey);

Console.WriteLine("== chip and PIN, card and PIN pad simulated in .NET ==");
Ksn ksn0 = Ksn.Parse("FFFF9876543210E00000");
var terminal = new DukptTerminal(TdesDukpt.Ipek(KeyMaterial.Hex(TestKey), ksn0), ksn0);
(Ksn ksn, byte[] pinKey) = terminal.Next(KeyUsage.Pin);
byte[] block = PinBlock.Encrypt(PinBlockFormat.Iso0, pinKey, Pin, Pan);
Console.WriteLine($"  PIN pad KSN {ksn} block {KeyMaterial.ToHex(block)}");

string zoneBlock = (await Run("G0", bdk, ksn.ToString(), KeyMaterial.ToHex(block), Pan, zpk, "00"))[0];
Console.WriteLine($"  HSM G0 -> ZPK block {zoneBlock}");
string pvv = CardVerification.Pvv(KeyMaterial.Hex(TestKey), Pan, 1, Pin);
await Run("DC", zpk, "00", zoneBlock, Pan, pvk, "1", pvv);
Console.WriteLine("  HSM DC: PIN verified");

var tx = new EmvTransaction
{
    Amount = 15990,
    TerminalCountry = 76,
    Currency = 986,
    Date = "261127",
    UnpredictableNumber = [0x11, 0x22, 0x33, 0x44],
    Aip = [0x39, 0x00],
    Atc = 0x0042,
    Iad = KeyMaterial.Hex("03A00000"),
};
byte[] mk = EmvCrypto.DeriveIccKey(KeyMaterial.Hex(TestKey), Pan, "01");
byte[] arqc = EmvCrypto.Arqc(mk, tx, CryptogramScheme.Cvn18);
Console.WriteLine($"  card ARQC {KeyMaterial.ToHex(arqc)}");
string arpc = (await Run("KQ", imk, "18", Pan, "01", KeyMaterial.ToHex(tx.Data()), tx.Atc.ToString("X4", CultureInfo.InvariantCulture), KeyMaterial.ToHex(arqc), "00"))[0];
string expected = KeyMaterial.ToHex(EmvCrypto.ArpcMethod1(EmvCrypto.SessionKey(mk, tx.Atc), arqc, "00"u8));
Console.WriteLine($"  HSM KQ: ARQC valid, ARPC {arpc} (card agrees: {arpc == expected})");

Console.WriteLine("== card not present ==");
string cvv2 = (await Run("CW", cvk, Pan, "2912", CardVerification.ServiceCvv2))[0];
Console.WriteLine($"  HSM CVV2 {cvv2}, .NET CVV2 {CardVerification.Cvv(KeyMaterial.Hex(TestKey), Pan, "2912", CardVerification.ServiceCvv2)}");
HsmResponse wrong = await hsm.SendAsync("CY", cvk, Pan, "2912", CardVerification.ServiceCvv2, "000");
Console.WriteLine($"  wrong CVV2 -> {wrong.Code} error {wrong.Error}");
return arpc == expected ? 0 : 1;
