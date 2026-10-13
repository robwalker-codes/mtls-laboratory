using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MtlsLab.Certificates;

public sealed record CertificateField(string Name, string Value, string Topic);
public sealed record CertificateView(string Subject, string Fingerprint, IReadOnlyList<CertificateField> Fields)
{
    public static CertificateView From(X509Certificate2 c)
    {
        var fields = new List<CertificateField>
        {
            new("Subject", c.Subject, "certificate"), new("Issuer", c.Issuer, "path-validation"),
            new("Serial number", c.SerialNumber, "certificate"),
            new("Valid from (UTC)", c.NotBefore.ToUniversalTime().ToString("u"), "path-validation"),
            new("Valid until (UTC)", c.NotAfter.ToUniversalTime().ToString("u"), "path-validation"),
            new("Public-key algorithm", c.PublicKey.Oid.FriendlyName ?? c.PublicKey.Oid.Value ?? "Unknown", "signatures"),
            new("Public-key parameters", c.PublicKey.EncodedParameters is { } parameters ? Convert.ToHexString(parameters.RawData) : "Not available", "signatures"),
            new("Public-key bytes", c.PublicKey.EncodedKeyValue is { } keyValue ? Convert.ToHexString(keyValue.RawData) : "Not available", "signatures"),
            new("Certificate signature algorithm", c.SignatureAlgorithm.FriendlyName ?? c.SignatureAlgorithm.Value ?? "Unknown", "signatures"),
            new("SHA-256 fingerprint", Convert.ToHexString(SHA256.HashData(c.RawData)), "certificate")
        };
        foreach (var e in c.Extensions)
            fields.Add(new(e.Oid?.FriendlyName ?? e.Oid?.Value ?? "Extension", e.Format(true), e.Oid?.Value switch
            { "2.5.29.17" => "identity", "2.5.29.37" => "purpose", "2.5.29.19" => "path-validation", "2.5.29.15" => "signatures", _ => "certificate" }));
        return new(c.Subject, Convert.ToHexString(SHA256.HashData(c.RawData)), fields);
    }
}
