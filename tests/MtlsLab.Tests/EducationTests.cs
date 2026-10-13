using MtlsLab.Core;
using MtlsLab.Education;
using MtlsLab.Tls;
using Xunit;

namespace MtlsLab.Tests;

public class EducationTests
{
    private readonly ContentCatalogue content = new();
    [Fact]
    public void RequiredCatalogueIsSubstantiveAndReferencesResolve()
    {
        string[] required = ["overview", "client-hello", "server-hello", "hello-retry", "versions", "signature-algorithms", "key-share", "encrypted-extensions", "certificate-request", "certificate", "certificate-verify", "finished", "records", "alerts", "key-schedule", "path-validation", "identity", "application-data"];
        Assert.All(required, id => Assert.True(content.Contains(id), id));
        Assert.True(content.Glossary.Count >= 30);
        Assert.Equal(content.Lessons.Count, content.Lessons.Select(x => x.Id).Distinct().Count());
        foreach (var lesson in content.Lessons)
        {
            Assert.True(lesson.Beginner.Length > 150, lesson.Id);
            Assert.True(lesson.Engineer.Length > 500, lesson.Id);
            Assert.True(lesson.Internals.Length > 500, lesson.Id);
            Assert.NotEqual(lesson.Beginner, lesson.Engineer);
            Assert.NotEqual(lesson.Engineer, lesson.Internals);
            Assert.All(lesson.Related, id => Assert.True(content.Contains(id), id));
            Assert.NotEmpty(lesson.Sources);
            Assert.All(lesson.Sources, s => { Assert.StartsWith("https://github.com/bcgit/bc-csharp/blob/" + SourceReference.Commit, s.Url); Assert.True(s.Line > 0); Assert.EndsWith(".cs", s.File); Assert.NotEmpty(s.Member); });
            Assert.All(lesson.Rfcs, r => { Assert.True(Uri.IsWellFormedUriString(r.Url, UriKind.Absolute)); Assert.Contains(r.Section, r.Url); Assert.NotEmpty(r.Title); });
            Assert.InRange(lesson.Check.CorrectIndex, 0, lesson.Check.Answers.Length - 1);
        }
        Assert.All(content.Glossary, entry => { Assert.True(content.Contains(entry.Topic)); Assert.NotEmpty(entry.Significance); Assert.NotEmpty(entry.Related); });
        Assert.All(content.Courses, c => Assert.All(c.Topics, id => Assert.True(content.Contains(id))));
    }
    [Fact]
    public void RealTraceMapsToLessonsAndInspectionDoesNotChangeExecution()
    {
        using var s = new TlsSession();
        var hello = s.Events.Single(x => x.Kind == "plaintext-handshake");
        Assert.Equal("client-hello", hello.Topic);
        var fields = RecordDecoder.DecodeHandshake(hello.EndpointBytes!);
        Assert.DoesNotContain(fields, f => f.Name == "Decoder diagnostic");
        Assert.Contains(fields, f => f.Name == "DNS server name" && f.Value == "localhost");
        Assert.Contains(fields, f => f.Name == "Supported version" && f.Value.Contains("TLS 1.3"));
        Assert.Contains(fields, f => f.Name == "Public key exchange bytes" && f.Length == 65);
        Assert.All(fields, f => Assert.InRange(f.Offset + f.Length, 0, hello.EndpointBytes!.Length));
        var before = s.Events.Count;
        foreach (var depth in Enum.GetValues<LearningDepth>()) _ = content.Get(hello.Topic).Explanation(depth);
        Assert.Equal(before, s.Events.Count);
        Assert.Equal(LabState.Handshaking, s.State);
        Assert.DoesNotContain(s.Records, x => x.DeliveryOrder is not null);
        TlsTests.Complete(s);
        Assert.All(s.Events, e => Assert.True(content.Contains(e.Topic), e.Topic));
        foreach (var e in s.Events.Where(e => e.EndpointBytes is not null))
            Assert.DoesNotContain(RecordDecoder.DecodeHandshake(e.EndpointBytes!), f => f.Name == "Decoder diagnostic");
        var encryptedHandshake = s.Events.First(e => e.HandshakeType == 15);
        Assert.Equal(Provenance.TlsImplementation, encryptedHandshake.Provenance);
        Assert.True(s.Records.Single(r => r.Id == encryptedHandshake.RecordId).Encrypted);
        Assert.DoesNotContain(s.Events, e => e.Topic == "hello-retry");
    }
}
