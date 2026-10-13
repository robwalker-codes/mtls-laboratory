using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MtlsLab.Core;

namespace MtlsLab.Certificates;

public sealed class CertificatePolicy
{
    public ValidationReport Validate(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> presentedIssuers,
        IReadOnlyList<X509Certificate2> trustAnchors, PeerSide validator, string? expectedDnsName = null)
    {
        var decisions = new List<ValidationDecision>();
        var now = DateTime.UtcNow;
        decisions.Add(new("Validity period", now >= leaf.NotBefore.ToUniversalTime() && now <= leaf.NotAfter.ToUniversalTime(),
            $"Evaluated at {now:O}; valid from {leaf.NotBefore.ToUniversalTime():O} to {leaf.NotAfter.ToUniversalTime():O}."));
        var basic = leaf.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        decisions.Add(new("Leaf constraints", basic is { CertificateAuthority: false }, "The endpoint certificate must be an explicitly non-CA leaf."));
        var usage = leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        decisions.Add(new("Key Usage", usage is not null && usage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature), "TLS 1.3 certificate authentication requires a signing key."));
        string purpose = validator == PeerSide.Client ? LabPki.ServerAuthOid : LabPki.ClientAuthOid;
        var eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        decisions.Add(new("Extended Key Usage", eku is not null && eku.EnhancedKeyUsages.Cast<Oid>().Any(x => x.Value == purpose),
            $"The laboratory requires explicit {(validator == PeerSide.Client ? "serverAuth" : "clientAuth")} ({purpose})."));

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchors.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(presentedIssuers.ToArray());
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(purpose));
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = now;
        bool built = chain.Build(leaf);
        string detail = built ? "X509Chain.Build accepted signatures, constraints, lifetime and purpose using CustomRootTrust." :
            string.Join("; ", chain.ChainStatus.Select(x => $"{x.Status}: {x.StatusInformation.Trim()}"));
        decisions.Add(new("Certificate chain", built, detail + " Revocation is not checked: the lab has no CRL or OCSP service."));
        var subjects = chain.ChainElements.Cast<X509ChainElement>().Select(x => x.Certificate.Subject).ToArray();
        var chainRoot = chain.ChainElements.Count == 0 ? null : chain.ChainElements[^1].Certificate;
        bool anchored = chainRoot is not null && trustAnchors.Any(x => x.RawData.AsSpan().SequenceEqual(chainRoot.RawData));
        decisions.Add(new("Trust anchor", anchored, anchored ? $"Chain terminates at explicitly trusted {chainRoot!.Subject}." : "The chain does not terminate at any root trusted by this endpoint."));
        if (expectedDnsName is not null)
        {
            bool matches = leaf.MatchesHostname(expectedDnsName, allowWildcards: false, allowCommonName: false);
            decisions.Add(new("DNS identity", matches, $"Compared reference identity '{expectedDnsName}' with DNS SAN only; no CN fallback and no wildcard matching in this lab."));
        }
        return new(validator, leaf.Subject, decisions.All(x => x.Passed), decisions, subjects);
    }
}
