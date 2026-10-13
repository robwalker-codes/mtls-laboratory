using System.Reflection;
using System.Text.Json;

namespace MtlsLab.Education;

public enum LearningDepth { Beginner, Engineer, Internals }
public sealed record RfcReference(int Number, string Section, string Title, string Relevance)
{
    public string Url => $"https://www.rfc-editor.org/rfc/rfc{Number}.html#{(char.IsLetter(Section[0]) ? "appendix" : "section")}-{Section}";
}
public sealed record SourceReference(string File, string Member, int Line, string Inspect)
{
    public const string Commit = "4007498b13582d90ee1eda5d9920c324428b98b3";
    public string Url => $"https://github.com/bcgit/bc-csharp/blob/{Commit}/crypto/src/{File}#L{Line}";
}
public sealed record KnowledgeCheck(string Question, string[] Answers, int CorrectIndex, string Explanation);
public sealed record Lesson(string Id, string Title, string Definition, string Beginner, string Engineer, string Internals,
    string Purpose, string Security, string[] Fields, string[] Bindings, string[] Concepts,
    RfcReference[] Rfcs, SourceReference[] Sources, string[] Related, KnowledgeCheck Check)
{
    public string Explanation(LearningDepth depth) => depth switch
    { LearningDepth.Beginner => Beginner, LearningDepth.Internals => Internals, _ => Engineer };
}
public sealed record GlossaryEntry(string Term, string Definition, string Explanation, string Significance, string Topic, string[] Related);
public sealed record Course(string Id, string Title, string Description, string[] Topics, string Experiment);

/// <summary>Immutable, embedded teaching material; no network or language-model service is used.</summary>
public sealed class ContentCatalogue
{
    public IReadOnlyList<Lesson> Lessons { get; }
    public IReadOnlyList<GlossaryEntry> Glossary { get; }
    public IReadOnlyList<Course> Courses { get; } = [
        new("tls", "Understanding TLS", "Build a secure channel from first principles.", ["overview", "secure-channel", "client-hello", "server-hello", "key-share", "certificate", "certificate-verify", "finished", "application-data"], "Compare mutual and server-authenticated TLS. Inspect a plaintext greeting and the corresponding ciphertext."),
        new("mtls", "Understanding Mutual TLS", "Separate identity, trust and application permission.", ["mutual-tls", "certificate-request", "certificate", "path-validation", "identity", "purpose", "alerts", "authorisation"], "Run missing, untrusted and expired client experiments. Then change the explicit trust policy."),
        new("internals", "TLS Protocol Internals", "Follow binary structures into the managed implementation.", ["records", "client-hello", "versions", "signature-algorithms", "key-share", "hello-retry", "key-schedule", "encrypted-extensions", "certificate-verify", "finished", "forward-secrecy"], "Select Protocol Internals, inspect field offsets, and follow the documented breakpoint tour.")
    ];
    public ContentCatalogue()
    {
        Lessons = Read<Lesson[]>("lessons.json");
        Glossary = Read<GlossaryEntry[]>("glossary.json");
    }
    private static T Read<T>(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"MtlsLab.Education.Resources.{name}")
            ?? throw new InvalidOperationException($"Missing educational resource {name}.");
        return JsonSerializer.Deserialize<T>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    }
    public Lesson Get(string id) => Lessons.Single(x => x.Id == id);
    public bool Contains(string id) => Lessons.Any(x => x.Id == id);
}

public sealed class LearningProgress
{
    public HashSet<string> Completed { get; set; } = [];
    public Dictionary<string, int> Answers { get; set; } = [];
    public LearningDepth Depth { get; set; } = LearningDepth.Engineer;
}
