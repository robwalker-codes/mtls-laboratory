using System.Buffers.Binary;

namespace MtlsLab.Core;

/// <summary>Incremental framing only; TLS processing always belongs to Bouncy Castle.</summary>
public sealed class RecordFramer
{
    public const int MaxPayload = (1 << 14) + 256; // RFC 8446 §5.2 TLSCiphertext limit.
    public const int MaxBuffered = 1 << 20;
    private readonly List<byte> buffer = [];
    public int BufferedBytes => buffer.Count;

    public IReadOnlyList<byte[]> Feed(ReadOnlySpan<byte> input)
    {
        if (input.Length + buffer.Count > MaxBuffered) throw new InvalidDataException("Transport buffer limit exceeded.");
        foreach (var b in input) buffer.Add(b);
        var records = new List<byte[]>();
        var consumed = 0;
        while (buffer.Count - consumed >= 5)
        {
            var length = (buffer[consumed + 3] << 8) | buffer[consumed + 4];
            if (length > MaxPayload) throw new InvalidDataException("TLS record exceeds the TLS 1.3 size limit.");
            if (buffer.Count - consumed < 5 + length) break;
            records.Add(buffer.GetRange(consumed, 5 + length).ToArray());
            consumed += 5 + length;
        }
        buffer.RemoveRange(0, consumed);
        return records;
    }
}

/// <summary>Reassembles plaintext handshake messages independently of record boundaries.</summary>
public sealed class HandshakeFramer
{
    private readonly List<byte> buffer = [];
    public int BufferedBytes => buffer.Count;
    public IReadOnlyList<byte[]> Feed(ReadOnlySpan<byte> fragment)
    {
        if (buffer.Count + fragment.Length > RecordFramer.MaxBuffered) throw new InvalidDataException("Handshake buffer limit exceeded.");
        foreach (var b in fragment) buffer.Add(b);
        var messages = new List<byte[]>();
        while (buffer.Count >= 4)
        {
            var length = (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
            if (length > RecordFramer.MaxBuffered - 4) throw new InvalidDataException("Handshake message too large.");
            if (buffer.Count < length + 4) break;
            messages.Add(buffer.GetRange(0, length + 4).ToArray());
            buffer.RemoveRange(0, length + 4);
        }
        return messages;
    }
}
