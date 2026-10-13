namespace MtlsLab.Core;

public enum PeerSide { Client, Server }
public enum Provenance { RecordBytes, TlsImplementation, Callback, LocalState, Explanation }
public enum RecordStatus { Pending, Delivered, Rejected }
public enum LabState { Handshaking, Connected, Failed, Disposed }

public sealed record Scenario(string Id, string Title, string Configuration, string Expected, string Remedy)
{
    public static IReadOnlyList<Scenario> All { get; } = [
        new("mutual", "Successful mutual TLS", "Client A and localhost trust the demonstration root.", "Both peers authenticate; protected messaging is enabled.", "No correction needed."),
        new("server-only", "Server-authenticated TLS", "The server does not request a client certificate.", "The server is authenticated. Client identity remains unauthenticated.", "Select mutual TLS to require a client identity."),
        new("missing", "Missing client certificate", "The server requires a certificate; the client sends none.", "The server rejects the empty certificate chain.", "Select Client A or Client B with a valid certificate."),
        new("untrusted-client", "Untrusted client CA", "The client uses the independent root; the server trusts only the demonstration root.", "Client chain validation fails.", "Use a client issued by the expected root, or deliberately add the independent root in the trust-policy experiment."),
        new("expired", "Expired client certificate", "The client certificate expired yesterday; its issuer and purpose are otherwise valid.", "Certificate validity checking fails.", "Issue a new client certificate with a valid lifetime."),
        new("hostname", "Server hostname mismatch", "The client expects localhost; the server certificate has only wrong.example in its SAN.", "Server identity validation fails.", "Issue a server certificate containing the expected DNS SAN."),
        new("purpose", "Incorrect client certificate purpose", "The client presents a certificate with serverAuth EKU only.", "Client certificate purpose checking fails.", "Issue a certificate explicitly permitting clientAuth."),
        new("untrusted-server", "Untrusted server CA", "The client trusts only the independent root; the server uses the demonstration root.", "Server chain validation fails.", "Restore the intended server trust anchor."),
        new("trust-policy", "Change the trust policy", "The client uses the independent root. Choose whether the server trusts that root before starting.", "Acceptance depends on the explicit server trust configuration.", "Trusting a CA authorises it to issue identities accepted by that peer; make this decision deliberately.")
    ];
    public static Scenario Find(string id) => All.Single(x => x.Id == id);
}

public sealed record LabOptions(string ScenarioId = "mutual", bool TrustIndependentClientRoot = false, bool UseClientB = false)
{
    public Scenario Scenario => Scenario.Find(ScenarioId);
    public bool RequireClientCertificate => ScenarioId != "server-only";
}

public sealed record DecodedField(string Name, string Value, int Offset, int Length, string Topic = "records");

public sealed class WireRecord(long id, PeerSide sender, byte[] bytes)
{
    public long Id { get; } = id;
    public PeerSide Sender { get; } = sender;
    public PeerSide Receiver => Sender == PeerSide.Client ? PeerSide.Server : PeerSide.Client;
    public byte[] Bytes { get; } = bytes;
    public int ContentType => Bytes[0];
    public bool Encrypted => ContentType == 23;
    public int PayloadLength => Bytes.Length - 5;
    public RecordStatus Status { get; set; }
    public long? DeliveryOrder { get; set; }
    public string? PlaintextHandshakeSummary { get; set; }
    public string Label => ContentType switch
    {
        23 => "Encrypted TLS record",
        20 => "Compatibility ChangeCipherSpec",
        21 => "Plaintext alert",
        22 => PlaintextHandshakeSummary ?? "Plaintext handshake fragment",
        _ => $"Record type {ContentType}"
    };
    public IReadOnlyList<DecodedField> Fields => RecordDecoder.DecodeRecord(Bytes);
}

public sealed class TraceEvent
{
    public required long Sequence { get; init; }
    public required Guid SessionId { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public required PeerSide Peer { get; init; }
    public required string Kind { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; set; }
    public required string Topic { get; init; }
    public required Provenance Provenance { get; init; }
    public long? RecordId { get; init; }
    public short? HandshakeType { get; init; }
    public byte[]? EndpointBytes { get; init; }
    public string State { get; set; } = "";
    public string Outcome { get; set; } = "Observed";
    public string Source { get; init; } = "";
    public string? Direction { get; set; }
}

public sealed record ValidationDecision(string Check, bool Passed, string Detail);
public sealed record ValidationReport(PeerSide Validator, string Subject, bool Accepted,
    IReadOnlyList<ValidationDecision> Decisions, IReadOnlyList<string> ChainSubjects);
public sealed record ApplicationMessage(PeerSide Sender, string Plaintext, bool Received, long? RecordId);

public sealed class PeerSnapshot(PeerSide side)
{
    public PeerSide Side { get; } = side;
    public bool HandshakeComplete { get; set; }
    public bool PeerCertificateValidated { get; set; }
    public string State { get; set; } = "Initialised";
    public string Version { get; set; } = "Not negotiated";
    public string Cipher { get; set; } = "Not negotiated";
    public string Authentication => HandshakeComplete && PeerCertificateValidated ? "Peer authenticated" :
        PeerCertificateValidated ? "Certificate accepted; awaiting proof and Finished" : "Peer not authenticated";
}
