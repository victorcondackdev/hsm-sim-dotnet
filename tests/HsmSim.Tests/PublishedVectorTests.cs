using HsmSim.CardAuth;
using HsmSim.Dukpt;
using HsmSim.Fpe;
using HsmSim.Keys;
using HsmSim.PinBlocks;

namespace HsmSim.Tests;

/// <summary>The vectors the standards publish, checked independently of the Go implementation.</summary>
public class PublishedVectorTests
{
    private const string TestKey = "0123456789ABCDEFFEDCBA9876543210";

    [Fact]
    public void TdesKcvOfTheAnsiTestKey() => Assert.Equal("08D7B4", KeyMaterial.Kcv(KeyMaterial.Hex(TestKey)));

    [Theory]
    [InlineData("", "BB1D6929E95937287FA37D129B756746")]
    [InlineData("6BC1BEE22E409F96E93D7E117393172A", "070A16B46B4D4144F79BDD9DD04A287C")]
    [InlineData("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411", "DFA66747DE9AE63030CA32611497C827")]
    public void AesCmacRfc4493(string message, string tag)
    {
        byte[] key = KeyMaterial.Hex("2B7E151628AED2A6ABF7158809CF4F3C");
        Assert.Equal(tag, KeyMaterial.ToHex(Mac.Cmac(key, KeyMaterial.Hex(message))));
    }

    [Fact]
    public void PinBlockFormat0Textbook()
    {
        byte[] b = PinBlock.Encode(PinBlockFormat.Iso0, "1234", "43219876543210987");
        Assert.Equal("0412AC89ABCDEF67", KeyMaterial.ToHex(b));
        Assert.Equal("1234", PinBlock.Decode(PinBlockFormat.Iso0, b, "43219876543210987"));
    }

    [Theory]
    [InlineData(1, "042666B49184CFA368DE9628D0397BC9", "042666B49184CF5C68DE9628D0397B36", "1B9C1845EB993A7A")]
    [InlineData(2, "C46551CEF9FD24B0AA9AD834130D3BC7", "C46551CEF9FD244FAA9AD834130D3B38", "10A01C8D02C69107")]
    public void DukptAnnexA(int counter, string transactionKey, string pinKey, string pinBlock)
    {
        byte[] bdk = KeyMaterial.Hex(TestKey);
        Ksn ksn = Ksn.Parse("FFFF9876543210E00000").WithCounter(counter);
        Assert.Equal("6AC292FAA1315B4D858AB3A3D7D5933A", KeyMaterial.ToHex(TdesDukpt.Ipek(bdk, ksn)));
        Assert.Equal(transactionKey, KeyMaterial.ToHex(TdesDukpt.Derive(bdk, ksn)));
        byte[] pk = TdesDukpt.HostKey(bdk, ksn, KeyUsage.Pin);
        Assert.Equal(pinKey, KeyMaterial.ToHex(pk));
        Assert.Equal(pinBlock, KeyMaterial.ToHex(PinBlock.Encrypt(PinBlockFormat.Iso0, pk, "1234", "4012345678909")));
    }

    [Fact]
    public void VisaCvvExample()
    {
        byte[] cvk = KeyMaterial.Hex(TestKey);
        Assert.Equal("561", CardVerification.Cvv(cvk, "4123456789012345", "8701", "101"));
        Assert.True(CardVerification.VerifyCvv(cvk, "4123456789012345", "8701", "101", "561"));
        Assert.False(CardVerification.VerifyCvv(cvk, "4123456789012345", "8701", "101", "562"));
    }

    [Theory]
    [InlineData("2B7E151628AED2A6ABF7158809CF4F3C", Ff1.Digits, "", "0123456789", "2433477484")]
    [InlineData("2B7E151628AED2A6ABF7158809CF4F3C", Ff1.Digits, "39383736353433323130", "0123456789", "6124200773")]
    [InlineData("2B7E151628AED2A6ABF7158809CF4F3C", Ff1.Alphanumeric, "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum")]
    [InlineData("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", Ff1.Digits, "", "0123456789", "6657667009")]
    public void Ff1NistSamples(string key, string alphabet, string tweak, string plain, string cipher)
    {
        using var f = new Ff1(KeyMaterial.Hex(key), alphabet);
        Assert.Equal(cipher, f.Encrypt(plain, KeyMaterial.Hex(tweak)));
        Assert.Equal(plain, f.Decrypt(cipher, KeyMaterial.Hex(tweak)));
    }
}
