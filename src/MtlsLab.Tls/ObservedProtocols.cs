using MtlsLab.Core;
using Org.BouncyCastle.Tls;

namespace MtlsLab.Tls;

// Capture at the supported protected handler. ToArray does not move the stream cursor.
// The callback is associated with the record that completes the message, not necessarily
// every contributing record. Bouncy Castle owns decryption and handshake reassembly.
internal sealed class ObservedClientProtocol(TlsSession session) : TlsClientProtocol
{
    internal string StateDescription => $"BC connection state {m_connectionState}";
    protected override void HandleHandshakeMessage(short type, HandshakeMessageInput input)
    {
        var e = session.ObserveHandshake(PeerSide.Client, type, input.ToArray(), m_connectionState);
        try { base.HandleHandshakeMessage(type, input); e.Outcome = "Processed"; }
        catch { e.Outcome = "Rejected"; throw; }
        finally { e.State = $"BC connection state {m_connectionState}"; session.Client.State = e.State; }
    }
}

internal sealed class ObservedServerProtocol(TlsSession session) : TlsServerProtocol
{
    internal string StateDescription => $"BC connection state {m_connectionState}";
    protected override void HandleHandshakeMessage(short type, HandshakeMessageInput input)
    {
        var e = session.ObserveHandshake(PeerSide.Server, type, input.ToArray(), m_connectionState);
        try { base.HandleHandshakeMessage(type, input); e.Outcome = "Processed"; }
        catch { e.Outcome = "Rejected"; throw; }
        finally { e.State = $"BC connection state {m_connectionState}"; session.Server.State = e.State; }
    }
}
