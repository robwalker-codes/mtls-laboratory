using System.Text;
using MtlsLab.Core;
using MtlsLab.Tls;
using Xunit;

namespace MtlsLab.Tests;

public class TlsTests
{
    internal static void Complete(TlsSession session)
    {
        for (int i = 0; i < 100 && session.PendingCount > 0 && session.State != LabState.Failed; i++) session.Next();
    }

    [Fact]
    public void GenuineMutualTlsAndBidirectionalEncryptedMessages()
    {
        using var s = new TlsSession();
        Assert.Equal(0, s.Records.Count(x => x.Status == RecordStatus.Delivered));
        Assert.False(s.CanMessage);
        Complete(s);
        Assert.True(s.State == LabState.Connected, s.Failure);
        Assert.True(s.Client.PeerCertificateValidated);
        Assert.True(s.Server.PeerCertificateValidated);
        Assert.Equal("TLS 1.3", s.Client.Version);
        Assert.Equal("TLS_AES_128_GCM_SHA256", s.Client.Cipher);
        foreach (var side in new[] { PeerSide.Client, PeerSide.Server })
        {
            string text = $"Hello, authenticated {side} — π 🔐";
            s.Send(side, text);
            var record = s.Records.Last();
            Assert.True(record.Encrypted);
            Assert.False(record.Bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(text)) >= 0);
            Complete(s);
            Assert.Contains(s.Messages, m => m.Received && m.Sender == side && m.Plaintext == text);
        }
        Assert.Equal(2, s.Validations.Count);
        Assert.All(s.Validations, x => Assert.True(x.Accepted));
        Assert.Contains(s.Events, e => e.HandshakeType == 15 && e.Peer == PeerSide.Client && e.Outcome == "Processed");
        Assert.Contains(s.Events, e => e.HandshakeType == 15 && e.Peer == PeerSide.Server && e.Outcome == "Processed");
    }

    [Theory]
    [InlineData("missing", "Certificate presence")]
    [InlineData("untrusted-client", "Trust anchor")]
    [InlineData("expired", "Validity period")]
    [InlineData("hostname", "DNS identity")]
    [InlineData("purpose", "Extended Key Usage")]
    [InlineData("untrusted-server", "Trust anchor")]
    public void InvalidIdentityCausesRealTlsFailure(string scenario, string failedCheck)
    {
        using var s = new TlsSession(new(scenario));
        Complete(s);
        Assert.Equal(LabState.Failed, s.State);
        Assert.False(s.CanMessage);
        Assert.Contains(s.Validations.SelectMany(x => x.Decisions), x => x.Check == failedCheck && !x.Passed);
        Assert.Contains(s.Events, x => x.Kind == "alert" && x.Title.Contains("raised"));
        Assert.Throws<InvalidOperationException>(() => s.Send(PeerSide.Client, "denied"));
    }

    [Fact]
    public void ServerOnlyDoesNotClaimMutualAuthentication()
    {
        using var s = new TlsSession(new("server-only")); Complete(s);
        Assert.Equal(LabState.Connected, s.State);
        Assert.True(s.Client.PeerCertificateValidated);
        Assert.False(s.Server.PeerCertificateValidated);
        Assert.DoesNotContain(s.Events, x => x.HandshakeType == 13);
    }

    [Theory]
    [InlineData(false, LabState.Failed)]
    [InlineData(true, LabState.Connected)]
    public void ExplicitTrustChangeControlsOutcome(bool trust, LabState expected)
    {
        using var s = new TlsSession(new("trust-policy", trust)); Complete(s);
        Assert.Equal(expected, s.State);
    }

    [Fact]
    public void NextDeliversExactlyOneRecordAndPreservesQueueOrder()
    {
        using var s = new TlsSession();
        while (s.PendingCount > 0)
        {
            var next = s.Records.First(x => x.Status == RecordStatus.Pending);
            int before = s.Records.Count(x => x.DeliveryOrder is not null);
            Assert.True(s.Next());
            Assert.Equal(before + 1, s.Records.Count(x => x.DeliveryOrder is not null));
            Assert.Equal(before + 1, next.DeliveryOrder);
            if (before == 0)
            {
                Assert.Equal("TLS 1.3", s.Server.Version);
                Assert.Equal("TLS_AES_128_GCM_SHA256", s.Server.Cipher);
                Assert.False(s.Server.HandshakeComplete);
            }
            if (before == 1)
            {
                Assert.Equal("TLS 1.3", s.Client.Version);
                Assert.False(s.Client.HandshakeComplete);
            }
        }
        Assert.Equal(LabState.Connected, s.State);
    }

    [Fact]
    public async Task RunCanPauseAndResumeWithoutAdvancingOnCancelledRun()
    {
        using var s = new TlsSession();
        using var cancellation = new CancellationTokenSource();
        await s.RunAsync(TimeSpan.Zero, cancellation.Token, () => { cancellation.Cancel(); return Task.CompletedTask; });
        Assert.Single(s.Records, x => x.DeliveryOrder is not null);
        await s.RunAsync(TimeSpan.Zero, cancellation.Token);
        Assert.Single(s.Records, x => x.DeliveryOrder is not null);
        await s.RunAsync(TimeSpan.Zero);
        Assert.Equal(LabState.Connected, s.State);
    }

    [Fact]
    public void AlteredApplicationCiphertextIsRejectedBeforePlaintextRelease()
    {
        using var s = new TlsSession(); Complete(s);
        s.Send(PeerSide.Client, "This message must not be accepted after tampering.");
        var encrypted = s.Records.Last();
        encrypted.Bytes[^1] ^= 1; // Deliberately corrupt the real AEAD tag in the test transport.
        s.Next();
        Assert.Equal(LabState.Failed, s.State);
        Assert.DoesNotContain(s.Messages, x => x.Received);
        Assert.Contains(s.Events, x => x.Kind == "alert" && x.Title.Contains("bad_record_mac"));
    }

    [Fact]
    public void SessionsAndFailureRecoveryAreIndependent()
    {
        using var bad = new TlsSession(new("missing"));
        using var good = new TlsSession(new(UseClientB: true));
        Complete(bad); Complete(good);
        Assert.Equal(LabState.Failed, bad.State);
        Assert.Equal(LabState.Connected, good.State);
        Assert.NotEqual(bad.Id, good.Id);
        Assert.NotEqual(bad.Pki.Root.Thumbprint, good.Pki.Root.Thumbprint);
        Assert.Contains(good.Validations, x => x.Subject == "CN=Client B");
        bad.Dispose();
        Assert.Empty(bad.Records);
        Assert.Throws<ObjectDisposedException>(() => bad.Next());
    }
}
