using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MtlsLab.Core;

namespace MtlsLab.Certificates;

/// <summary>Session-owned, short-lived teaching identities. Private keys never leave process memory.</summary>
public sealed class LabPki : IDisposable
{
    private readonly List<X509Certificate2> owned = [];
    public X509Certificate2 Root { get; }
    public X509Certificate2 IndependentRoot { get; }
    public X509Certificate2 Server { get; }
    public X509Certificate2 ClientA { get; }
    public X509Certificate2 ClientB { get; }
    public X509Certificate2 IndependentClient { get; }
    public X509Certificate2 ExpiredClient { get; }
    public X509Certificate2 WrongPurposeClient { get; }
    public X509Certificate2 WrongHostnameServer { get; }
    public static string ServerAuthOid => "1.3.6.1.5.5.7.3.1";
    public static string ClientAuthOid => "1.3.6.1.5.5.7.3.2";

    public LabPki()
    {
        var now = DateTimeOffset.UtcNow;
        Root = RootCertificate("Demonstration Root CA", now);
        IndependentRoot = RootCertificate("Independent Untrusted Root CA", now);
        Server = Leaf("localhost", Root, ServerAuthOid, now.AddHours(-1), now.AddDays(7), "localhost");
        ClientA = Leaf("Client A", Root, ClientAuthOid, now.AddHours(-1), now.AddDays(7));
        ClientB = Leaf("Client B", Root, ClientAuthOid, now.AddHours(-1), now.AddDays(7));
        IndependentClient = Leaf("Independent Client", IndependentRoot, ClientAuthOid, now.AddHours(-1), now.AddDays(7));
        ExpiredClient = Leaf("Expired Client", Root, ClientAuthOid, now.AddDays(-3), now.AddDays(-1));
        WrongPurposeClient = Leaf("Wrong Purpose Client", Root, ServerAuthOid, now.AddHours(-1), now.AddDays(7));
        WrongHostnameServer = Leaf("wrong.example", Root, ServerAuthOid, now.AddHours(-1), now.AddDays(7), "wrong.example");
    }

    public X509Certificate2? SelectClient(LabOptions options) => options.ScenarioId switch
    {
        "missing" or "server-only" => null,
        "untrusted-client" or "trust-policy" => IndependentClient,
        "expired" => ExpiredClient,
        "purpose" => WrongPurposeClient,
        _ => options.UseClientB ? ClientB : ClientA
    };
    public X509Certificate2 SelectServer(LabOptions options) => options.ScenarioId == "hostname" ? WrongHostnameServer : Server;
    public X509Certificate2[] ClientTrust(LabOptions options) => [options.ScenarioId == "untrusted-server" ? IndependentRoot : Root];
    public X509Certificate2[] ServerTrust(LabOptions options) => options.ScenarioId == "trust-policy" && options.TrustIndependentClientRoot ? [Root, IndependentRoot] : [Root];
    public X509Certificate2 Issuer(X509Certificate2 leaf) => leaf.Issuer == IndependentRoot.Subject ? IndependentRoot : Root;

    private X509Certificate2 RootCertificate(string cn, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return Own(request.CreateSelfSigned(now.AddDays(-30), now.AddDays(30)));
    }

    private X509Certificate2 Leaf(string cn, X509Certificate2 issuer, string purpose, DateTimeOffset from,
        DateTimeOffset until, string? dns = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(purpose) }, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (dns is not null)
        {
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(dns);
            request.CertificateExtensions.Add(san.Build());
        }
        var serial = RandomNumberGenerator.GetBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
        using var certificate = request.Create(issuer, from, until, serial);
        return Own(certificate.CopyWithPrivateKey(key));
    }
    private X509Certificate2 Own(X509Certificate2 c) { owned.Add(c); return c; }
    public void Dispose() { foreach (var c in owned) c.Dispose(); owned.Clear(); }
}
