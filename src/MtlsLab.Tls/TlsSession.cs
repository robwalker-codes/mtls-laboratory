using System.Security.Cryptography.X509Certificates;
using System.Text;
using MtlsLab.Certificates;
using MtlsLab.Core;
using Org.BouncyCastle.Tls;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;

namespace MtlsLab.Tls;

/// <summary>A single, isolated TLS experiment. All engine access is serialised by the session gate.</summary>
public sealed class TlsSession : IDisposable
{
    public const int MaxRecords = 512;
    public const int MaxEvents = 4096;
    private readonly object gate = new();
    private readonly ObservedClientProtocol clientProtocol;
    private readonly ObservedServerProtocol serverProtocol;
    private readonly RecordFramer clientFramer = new(), serverFramer = new();
    private readonly HandshakeFramer clientHandshakeFramer = new(), serverHandshakeFramer = new();
    private readonly List<WireRecord> records = [];
    private readonly Queue<WireRecord> pending = new();
    private readonly List<TraceEvent> events = [];
    private readonly List<ValidationReport> validations = [];
    private readonly List<ApplicationMessage> messages = [];
    private long sequence, delivered;
    private long? processingRecord;
    private bool disposed;
    private int running;
    public Guid Id { get; } = Guid.NewGuid();
    public LabOptions Options { get; }
    public LabPki Pki { get; }
    public PeerSnapshot Client { get; } = new(PeerSide.Client);
    public PeerSnapshot Server { get; } = new(PeerSide.Server);
    public LabState State { get; private set; } = LabState.Handshaking;
    public string? Failure { get; private set; }
    public IReadOnlyList<WireRecord> Records { get { lock (gate) return records.ToArray(); } }
    public IReadOnlyList<TraceEvent> Events { get { lock (gate) return events.ToArray(); } }
    public IReadOnlyList<ValidationReport> Validations { get { lock (gate) return validations.ToArray(); } }
    public IReadOnlyList<ApplicationMessage> Messages { get { lock (gate) return messages.ToArray(); } }
    public int PendingCount { get { lock (gate) return pending.Count; } }
    public string NextAction { get { lock (gate) return pending.TryPeek(out var next) ? $"Deliver {next.Label} · #{next.Id}" : State == LabState.Connected ? "Send an application message" : "No pending record"; } }
    public bool CanMessage => State == LabState.Connected && Client.PeerCertificateValidated &&
        (!Options.RequireClientCertificate || Server.PeerCertificateValidated);

    public TlsSession(LabOptions? options = null)
    {
        Options = options ?? new();
        _ = Options.Scenario; // Validate configuration before invoking TLS.
        Pki = new();
        clientProtocol = new(this); serverProtocol = new(this);
        Add(PeerSide.Client, "session", "Experiment initialised", Options.Scenario.Configuration,
            "overview", Provenance.LocalState, "TlsSession..ctor");
        try
        {
            serverProtocol.Accept(new LabServer(this));
            clientProtocol.Connect(new LabClient(this));
            Client.State = clientProtocol.StateDescription;
            Server.State = serverProtocol.StateDescription;
            Drain(PeerSide.Client); Drain(PeerSide.Server);
        }
        catch { Dispose(); throw; }
    }

    /// <summary>Delivers exactly one queued record. A synchronous BC operation may produce many observations.</summary>
    public bool Next()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!pending.TryDequeue(out var record)) return false;
            processingRecord = record.Id;
            record.DeliveryOrder = ++delivered;
            Add(record.Receiver, "delivery", $"Deliver record #{record.Id}", $"{record.Sender} → {record.Receiver}: {record.Bytes.Length} bytes passed unchanged to OfferInput.",
                "records", Provenance.RecordBytes, "TlsProtocol.OfferInput");
            try
            {
                Protocol(record.Receiver).OfferInput(record.Bytes);
                record.Status = RecordStatus.Delivered;
                ReadApplication(record.Receiver);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException)
            {
                record.Status = RecordStatus.Rejected;
                Failure ??= ex.Message; State = LabState.Failed;
                var error = Add(record.Receiver, "failure", "TLS processing failed", ex.Message, "alerts", Provenance.TlsImplementation, "TlsProtocol.OfferInput");
                error.Outcome = "Failed";
            }
            finally
            {
                Drain(PeerSide.Client); Drain(PeerSide.Server);
                processingRecord = null;
            }
            if (State != LabState.Failed && Client.HandshakeComplete && Server.HandshakeComplete) State = LabState.Connected;
            return true;
        }
    }

    public async Task RunAsync(TimeSpan delay, CancellationToken cancellationToken = default, Func<Task>? onStep = null)
    {
        if (delay < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(delay));
        if (Interlocked.Exchange(ref running, 1) != 0) throw new InvalidOperationException("A run is already active.");
        try
        {
            while (!cancellationToken.IsCancellationRequested && State != LabState.Failed && PendingCount > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Next();
                if (onStep is not null) await onStep();
                // Always yield; a zero-delay run must still allow UI cancellation.
                await Task.Delay(delay == TimeSpan.Zero ? TimeSpan.FromMilliseconds(1) : delay, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally { Interlocked.Exchange(ref running, 0); }
    }

    public void Send(PeerSide sender, string text)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!CanMessage) throw new InvalidOperationException("The required peer authentication and both handshakes must complete before messaging.");
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            if (bytes.Length is 0 or > 4096) throw new ArgumentException("Enter between 1 and 4096 UTF-8 bytes.", nameof(text));
            if (records.Count >= MaxRecords - 2) throw new InvalidOperationException("Session trace is full. Reset the experiment.");
            Protocol(sender).WriteApplicationData(bytes, 0, bytes.Length);
            messages.Add(new(sender, text, false, null));
            Add(sender, "application-send", "Application plaintext submitted", text, "application-data", Provenance.LocalState, "TlsProtocol.WriteApplicationData");
            Drain(sender);
        }
    }

    private void ReadApplication(PeerSide receiver)
    {
        var p = Protocol(receiver);
        int count = p.GetAvailableInputBytes();
        if (count == 0) return;
        byte[] bytes = new byte[count];
        int read = p.ReadInput(bytes, 0, count);
        var text = Encoding.UTF8.GetString(bytes, 0, read);
        var sender = receiver == PeerSide.Client ? PeerSide.Server : PeerSide.Client;
        messages.Add(new(sender, text, true, processingRecord));
        Add(receiver, "application-receive", "Application plaintext recovered", text, "application-data", Provenance.TlsImplementation, "TlsProtocol.ReadInput");
    }

    private TlsProtocol Protocol(PeerSide side) => side == PeerSide.Client ? clientProtocol : serverProtocol;
    private void Drain(PeerSide side)
    {
        var protocol = Protocol(side);
        int available = protocol.GetAvailableOutputBytes();
        if (available == 0) return;
        if (available > RecordFramer.MaxBuffered) throw new InvalidDataException("TLS output buffer limit exceeded.");
        var bytes = new byte[available];
        int read = protocol.ReadOutput(bytes, 0, bytes.Length);
        var framer = side == PeerSide.Client ? clientFramer : serverFramer;
        foreach (byte[] framed in framer.Feed(bytes.AsSpan(0, read)))
        {
            if (records.Count >= MaxRecords) throw new InvalidDataException("Trace record limit reached; reset the experiment.");
            var record = new WireRecord(records.Count + 1, side, framed);
            records.Add(record); pending.Enqueue(record);
            var ev = Add(side, "record", $"Queued record #{record.Id}", $"{record.Label}; {record.PayloadLength} payload bytes. Awaiting explicit delivery.",
                "records", Provenance.RecordBytes, "TlsProtocol.ReadOutput", record.Id);
            ev.Direction = $"{record.Sender} → {record.Receiver}";
            if (record.ContentType == 22)
            {
                var handshakeFramer = side == PeerSide.Client ? clientHandshakeFramer : serverHandshakeFramer;
                bool continuation = handshakeFramer.BufferedBytes > 0;
                var completeMessages = handshakeFramer.Feed(framed.AsSpan(5));
                var names = string.Join(" + ", completeMessages.Select(m => RecordDecoder.HandshakeName(m[0])));
                record.PlaintextHandshakeSummary = completeMessages.Count == 0 ? "Plaintext handshake fragment" :
                    continuation || handshakeFramer.BufferedBytes > 0 ? $"Handshake fragment · completes {names}" : names;
                ev.Detail = $"{record.Label}; {record.PayloadLength} payload bytes. Awaiting explicit delivery.";
                foreach (var message in completeMessages)
                    Add(side, "plaintext-handshake", RecordDecoder.HandshakeName(message[0]), "Reassembled from actual plaintext outbound record bytes.",
                        RecordDecoder.Topic(message[0]), Provenance.RecordBytes, "TlsProtocol.ReadOutput", record.Id, message[0], message);
            }
        }
    }

    internal TraceEvent ObserveHandshake(PeerSide receiver, short type, byte[] bytes, short state)
    {
        var e = Add(receiver, "handshake", RecordDecoder.HandshakeName(type),
            "Endpoint-visible handshake bytes, after record decryption/reassembly. Associated record completes this message; earlier records may also contribute.",
            RecordDecoder.Topic(type), Provenance.TlsImplementation,
            receiver == PeerSide.Client ? "TlsClientProtocol.HandleHandshakeMessage" : "TlsServerProtocol.HandleHandshakeMessage",
            processingRecord, type, bytes);
        e.State = $"BC connection state {state}";
        return e;
    }

    internal void ValidateCertificate(PeerSide validator, BcCertificate certificate)
    {
        if (certificate.IsEmpty)
        {
            validations.Add(new(validator, "No certificate", false, [new("Certificate presence", false, "The server requires an authenticated client certificate.")], []));
            Add(validator, "validation", "Missing client certificate", "The configured client has no credential. The server rejects the empty chain.", "certificate-request", Provenance.Callback, "TlsSession.ValidateCertificate");
            throw new TlsFatalAlert(AlertDescription.certificate_required, "Client certificate required by laboratory policy.");
        }
        var certificates = certificate.GetCertificateList().Select(x => X509CertificateLoader.LoadCertificate(x.GetEncoded())).ToArray();
        try
        {
            var trust = validator == PeerSide.Client ? Pki.ClientTrust(Options) : Pki.ServerTrust(Options);
            var report = new CertificatePolicy().Validate(certificates[0], certificates.Skip(1).ToArray(), trust, validator, validator == PeerSide.Client ? "localhost" : null);
            validations.Add(report);
            foreach (var decision in report.Decisions)
            {
                var decisionTopic = decision.Check switch { "DNS identity" => "identity", "Extended Key Usage" or "Key Usage" or "Leaf constraints" => "purpose", _ => "path-validation" };
                var e = Add(validator, "validation", decision.Check, decision.Detail, decisionTopic, Provenance.Callback, "CertificatePolicy.Validate");
                e.Outcome = decision.Passed ? "Passed" : "Failed";
            }
            if (!report.Accepted)
            {
                var failed = report.Decisions.Where(x => !x.Passed).ToArray();
                short alert = failed.Any(x => x.Check == "Validity period") ? AlertDescription.certificate_expired :
                    failed.Any(x => x.Check == "Trust anchor") ? AlertDescription.unknown_ca : AlertDescription.bad_certificate;
                throw new TlsFatalAlert(alert, string.Join("; ", failed.Select(x => $"{x.Check}: {x.Detail}")));
            }
            (validator == PeerSide.Client ? Client : Server).PeerCertificateValidated = true;
        }
        finally { foreach (var c in certificates) c.Dispose(); }
    }

    internal void Completed(PeerSide side, SecurityParameters security)
    {
        var peer = side == PeerSide.Client ? Client : Server;
        peer.HandshakeComplete = true;
        peer.Version = security.NegotiatedVersion.ToString();
        peer.Cipher = RecordDecoder.CipherName(security.CipherSuite);
        Add(side, "complete", "Handshake complete", $"{peer.Version}; {peer.Cipher}. Bouncy Castle validated the required proof-of-possession and Finished messages.",
            "finished", Provenance.Callback, "TlsPeer.NotifyHandshakeComplete");
    }
    internal void Alert(PeerSide side, bool raised, short level, short description, string? detail)
    {
        if (disposed) return;
        Add(side, "alert", $"Alert {(raised ? "raised" : "received")}: {AlertDescription.GetText(description)}",
            $"{AlertLevel.GetText(level)}. {detail}", "alerts", Provenance.Callback, raised ? "TlsPeer.NotifyAlertRaised" : "TlsPeer.NotifyAlertReceived");
        if (level == AlertLevel.fatal) { State = LabState.Failed; Failure ??= $"{AlertDescription.GetText(description)}: {detail}"; }
    }

    internal TraceEvent Add(PeerSide peer, string kind, string title, string detail, string topic, Provenance provenance,
        string source, long? recordId = null, short? type = null, byte[]? endpointBytes = null)
    {
        if (events.Count >= MaxEvents) events.RemoveAt(0);
        var e = new TraceEvent { Sequence = ++sequence, SessionId = Id, Peer = peer, Kind = kind, Title = title, Detail = detail,
            Topic = topic, Provenance = provenance, RecordId = recordId ?? processingRecord, HandshakeType = type, EndpointBytes = endpointBytes, Source = source,
            State = (peer == PeerSide.Client ? Client : Server).State };
        events.Add(e); return e;
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            try { clientProtocol.Close(); } catch (IOException) { }
            try { serverProtocol.Close(); } catch (IOException) { }
            Pki.Dispose(); pending.Clear(); events.Clear(); records.Clear(); messages.Clear(); validations.Clear();
            State = LabState.Disposed;
        }
    }
}
