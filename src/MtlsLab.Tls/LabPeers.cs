using System.Security.Cryptography.X509Certificates;
using System.Text;
using MtlsLab.Core;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;
using CertificateRequest = Org.BouncyCastle.Tls.CertificateRequest;

namespace MtlsLab.Tls;

internal static class Credentials
{
    internal static readonly SignatureAndHashAlgorithm Scheme = SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);

    internal static TlsCredentialedSigner Signer(TlsContext context, X509Certificate2 leaf, X509Certificate2 root)
    {
        var crypto = (BcTlsCrypto)context.Crypto;
        var chain = new BcCertificate([], [
            new CertificateEntry(crypto.CreateCertificate(leaf.RawData), null),
            new CertificateEntry(crypto.CreateCertificate(root.RawData), null)
        ]);
        using var key = leaf.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Missing ECDSA private key.");
        // In-memory conversion only; no key bytes are logged, persisted or placed in trace events.
        var pair = DotNetUtilities.GetECDsaKeyPair(key);
        return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), crypto, pair.Private, chain, Scheme);
    }
}

internal sealed class LabClient(TlsSession session) : DefaultTlsClient(new BcTlsCrypto(new SecureRandom()))
{
    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13];
    protected override int[] GetSupportedCipherSuites() => [CipherSuite.TLS_AES_128_GCM_SHA256];
    protected override IList<int> GetSupportedGroups(IList<int> roles) => [NamedGroup.secp256r1];
    protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms() => [Credentials.Scheme];
    protected override IList<ServerName> GetSniServerNames() => [new(NameType.host_name, Encoding.ASCII.GetBytes("localhost"))];
    public override int GetMaxHandshakeMessageSize() => 65536;
    public override TlsAuthentication GetAuthentication() => new Authentication(session, m_context);
    public override void NotifyServerVersion(ProtocolVersion serverVersion)
    {
        base.NotifyServerVersion(serverVersion);
        session.Client.Version = serverVersion.ToString();
        session.Add(PeerSide.Client, "negotiation", "Server version received", session.Client.Version,
            "versions", Provenance.Callback, "AbstractTlsClient.NotifyServerVersion");
    }
    public override void NotifySelectedCipherSuite(int selectedCipherSuite)
    {
        base.NotifySelectedCipherSuite(selectedCipherSuite);
        session.Client.Cipher = RecordDecoder.CipherName(selectedCipherSuite);
        session.Add(PeerSide.Client, "negotiation", "Selected cipher suite received", session.Client.Cipher,
            "server-hello", Provenance.Callback, "AbstractTlsClient.NotifySelectedCipherSuite");
    }
    public override void NotifyHandshakeComplete() { base.NotifyHandshakeComplete(); session.Completed(PeerSide.Client, m_context.SecurityParameters); }
    public override void NotifyAlertRaised(short level, short description, string message, Exception cause) => session.Alert(PeerSide.Client, true, level, description, message);
    public override void NotifyAlertReceived(short level, short description) => session.Alert(PeerSide.Client, false, level, description, null);

    private sealed class Authentication(TlsSession session, TlsContext context) : TlsAuthentication
    {
        public void NotifyServerCertificate(TlsServerCertificate certificate) => session.ValidateCertificate(PeerSide.Client, certificate.Certificate);
        public TlsCredentials? GetClientCredentials(CertificateRequest request)
        {
            var leaf = session.Pki.SelectClient(session.Options);
            session.Add(PeerSide.Client, "credentials", "Client credential selection", leaf?.Subject ?? "No client certificate configured.", "certificate-request", Provenance.Callback, "LabPeers.Authentication.GetClientCredentials");
            if (leaf is null) return null;
            if (!request.SupportedSignatureAlgorithms.Contains(Credentials.Scheme)) return null;
            return Credentials.Signer(context, leaf, session.Pki.Issuer(leaf));
        }
    }
}

internal sealed class LabServer(TlsSession session) : DefaultTlsServer(new BcTlsCrypto(new SecureRandom()))
{
    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13];
    protected override int[] GetSupportedCipherSuites() => [CipherSuite.TLS_AES_128_GCM_SHA256];
    public override int GetMaxHandshakeMessageSize() => 65536;
    public override ProtocolVersion GetServerVersion()
    {
        var version = base.GetServerVersion();
        session.Server.Version = version.ToString();
        session.Add(PeerSide.Server, "negotiation", "Server version selected", session.Server.Version,
            "versions", Provenance.Callback, "AbstractTlsServer.GetServerVersion");
        return version;
    }
    public override int GetSelectedCipherSuite()
    {
        var suite = base.GetSelectedCipherSuite();
        session.Server.Cipher = RecordDecoder.CipherName(suite);
        session.Add(PeerSide.Server, "negotiation", "Cipher suite selected", session.Server.Cipher,
            "server-hello", Provenance.Callback, "AbstractTlsServer.GetSelectedCipherSuite");
        return suite;
    }
    public override TlsCredentials GetCredentials()
    {
        var leaf = session.Pki.SelectServer(session.Options);
        session.Add(PeerSide.Server, "credentials", "Server credential selection", leaf.Subject, "certificate", Provenance.Callback, "LabPeers.LabServer.GetCredentials");
        return Credentials.Signer(m_context, leaf, session.Pki.Root);
    }
    public override CertificateRequest? GetCertificateRequest()
    {
        if (!session.Options.RequireClientCertificate) return null;
        var authorities = session.Pki.ServerTrust(session.Options).Select(x => new X509Name(x.Subject)).ToList();
        session.Add(PeerSide.Server, "request", "Requesting a client certificate", "The server requires a signing identity from its explicit trust policy.", "certificate-request", Provenance.Callback, "LabPeers.LabServer.GetCertificateRequest");
        return new CertificateRequest([], [Credentials.Scheme], null, authorities);
    }
    public override void NotifyClientCertificate(BcCertificate certificate) => session.ValidateCertificate(PeerSide.Server, certificate);
    public override void NotifyHandshakeComplete() { base.NotifyHandshakeComplete(); session.Completed(PeerSide.Server, m_context.SecurityParameters); }
    public override void NotifyAlertRaised(short level, short description, string message, Exception cause) => session.Alert(PeerSide.Server, true, level, description, message);
    public override void NotifyAlertReceived(short level, short description) => session.Alert(PeerSide.Server, false, level, description, null);
}
