using System.Security.Cryptography.X509Certificates;
using MtlsLab.Certificates;
using MtlsLab.Core;
using Xunit;

namespace MtlsLab.Tests;

public class FramingTests
{
    [Fact]
    public void FragmentationAndCoalescingPreserveExactRecordBytes()
    {
        byte[] a = [22, 3, 3, 0, 3, 1, 2, 3], b = [23, 3, 3, 0, 2, 4, 5];
        for (int split = 0; split <= a.Length + b.Length; split++)
        {
            var f = new RecordFramer(); byte[] all = [.. a, .. b];
            var result = f.Feed(all.AsSpan(0, split)).Concat(f.Feed(all.AsSpan(split))).ToArray();
            Assert.Equal(2, result.Length); Assert.Equal(a, result[0]); Assert.Equal(b, result[1]);
            Assert.Equal(0, f.BufferedBytes);
        }
    }
    [Fact]
    public void HandshakeMessagesCanCrossRecordsAndShareRecords()
    {
        var f = new HandshakeFramer();
        Assert.Empty(f.Feed([1, 0, 0, 4, 10]));
        var messages = f.Feed([11, 12, 13, 20, 0, 0, 2, 99, 98]);
        Assert.Equal(2, messages.Count);
        Assert.Equal(new byte[] { 1, 0, 0, 4, 10, 11, 12, 13 }, messages[0]);
        Assert.Equal(new byte[] { 20, 0, 0, 2, 99, 98 }, messages[1]);
    }
    [Fact]
    public void OversizedRecordsAndHandshakesAreRejected()
    {
        Assert.Throws<InvalidDataException>(() => new RecordFramer().Feed([23, 3, 3, 0xff, 0xff]));
        Assert.Throws<InvalidDataException>(() => new RecordFramer().Feed(new byte[RecordFramer.MaxBuffered + 1]));
        Assert.Throws<InvalidDataException>(() => new HandshakeFramer().Feed([1, 0xff, 0xff, 0xff]));
    }
    [Fact]
    public void CiphertextIsNeverDecodedAsHandshakePlaintext()
    {
        var r = new WireRecord(1, PeerSide.Server, [23, 3, 3, 0, 4, 1, 0, 0, 0]);
        Assert.True(r.Encrypted);
        Assert.Contains("Encrypted", r.Label);
        Assert.DoesNotContain(r.Fields, f => f.Name == "Handshake type");
    }
}

public class CertificateTests : IDisposable
{
    private readonly LabPki pki = new();
    private readonly CertificatePolicy policy = new();
    [Fact]
    public void RootIsCaAndEndpointCertificatesHaveDistinctKeysAndSerials()
    {
        var constraint = pki.Root.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(constraint.CertificateAuthority);
        Assert.True(pki.Root.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign));
        Assert.NotEqual(pki.ClientA.SerialNumber, pki.ClientB.SerialNumber);
        Assert.NotEqual(pki.ClientA.PublicKey.EncodedKeyValue.RawData, pki.ClientB.PublicKey.EncodedKeyValue.RawData);
        Assert.True(pki.ClientA.HasPrivateKey);
    }
    [Fact]
    public void ValidServerChainsToOnlyExplicitRootAndMatchesDnsSan()
    {
        var r = policy.Validate(pki.Server, [pki.Root], [pki.Root], PeerSide.Client, "localhost");
        Assert.True(r.Accepted);
        Assert.Equal(new[] { pki.Server.Subject, pki.Root.Subject }, r.ChainSubjects);
        Assert.False(policy.Validate(pki.Server, [pki.Root], [pki.IndependentRoot], PeerSide.Client, "localhost").Accepted);
        Assert.False(policy.Validate(pki.Server, [pki.Root], [pki.Root], PeerSide.Client, "wrong.example").Accepted);
    }
    [Theory]
    [InlineData("expired", "Validity period")]
    [InlineData("purpose", "Extended Key Usage")]
    public void InvalidLeafFailsSpecificDecision(string scenario, string check)
    {
        var leaf = pki.SelectClient(new(scenario))!;
        var report = policy.Validate(leaf, [pki.Root], [pki.Root], PeerSide.Server);
        Assert.False(report.Accepted);
        Assert.Contains(report.Decisions, x => x.Check == check && !x.Passed);
    }
    [Fact]
    public void CorruptIssuerSignatureCannotValidate()
    {
        var der = pki.ClientA.RawData;
        der[^1] ^= 1;
        using var corrupt = X509CertificateLoader.LoadCertificate(der);
        var report = policy.Validate(corrupt, [pki.Root], [pki.Root], PeerSide.Server);
        Assert.False(report.Accepted);
        Assert.Contains(report.Decisions, x => x.Check == "Certificate chain" && !x.Passed);
    }

    [Fact]
    public void CertificateInspectorContainsPublicDataAndNoPrivateKeyMaterial()
    {
        var view = CertificateView.From(pki.Server);
        Assert.Equal(64, view.Fingerprint.Length);
        Assert.Contains(view.Fields, f => f.Name == "Subject Alternative Name" || f.Value.Contains("localhost"));
        Assert.DoesNotContain(view.Fields, f => f.Name.Contains("private", StringComparison.OrdinalIgnoreCase));
    }
    public void Dispose() => pki.Dispose();
}
