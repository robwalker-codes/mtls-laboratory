using System.Buffers.Binary;
using System.Text;

namespace MtlsLab.Core;

/// <summary>Inspection of public structures only. This class never decrypts TLS records.</summary>
public static class RecordDecoder
{
    public static string HandshakeName(int type) => type switch
    {
        1 => "ClientHello", 2 => "ServerHello", 4 => "NewSessionTicket", 8 => "EncryptedExtensions",
        11 => "Certificate", 13 => "CertificateRequest", 15 => "CertificateVerify", 20 => "Finished",
        24 => "KeyUpdate", 254 => "MessageHash", _ => $"Handshake {type}"
    };
    public static string Topic(int type) => type switch
    {
        1 => "client-hello", 2 => "server-hello", 8 => "encrypted-extensions", 11 => "certificate",
        13 => "certificate-request", 15 => "certificate-verify", 20 => "finished", _ => "overview"
    };
    public static IReadOnlyList<DecodedField> DecodeRecord(byte[] bytes)
    {
        if (bytes.Length < 5) return [];
        var fields = new List<DecodedField>
        {
            new("Content type", bytes[0] switch { 20 => "20 · change_cipher_spec", 21 => "21 · alert", 22 => "22 · handshake", 23 => "23 · application_data (opaque ciphertext)", _ => bytes[0].ToString() }, 0, 1),
            new("Legacy record version", $"0x{Convert.ToHexString(bytes.AsSpan(1, 2))} (compatibility field)", 1, 2, "versions"),
            new("Payload length", BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(3, 2)).ToString(), 3, 2)
        };
        if (bytes[0] == 20) fields.Add(new("Compatibility payload", Convert.ToHexString(bytes.AsSpan(5)), 5, bytes.Length - 5));
        if (bytes[0] == 23) fields.Add(new("Encrypted fragment", "Inner content type and plaintext are hidden on the wire.", 5, bytes.Length - 5, "application-data"));
        return fields;
    }

    public static IReadOnlyList<DecodedField> DecodeHandshake(byte[] bytes)
    {
        var f = new List<DecodedField>();
        try
        {
            var c = new Cursor(bytes, f);
            int type = c.Number("Handshake type", 1, Topic(bytes[0]));
            int length = c.Number("Handshake body length", 3);
            if (length != bytes.Length - 4) throw new InvalidDataException("Incomplete handshake message.");
            if (type is 1 or 2)
            {
                c.Hex("legacy_version", 2, "versions");
                c.Hex("random", 32, "client-hello");
                c.Hex("legacy_session_id", c.Number("Session ID length", 1));
                if (type == 1)
                {
                    var end = c.Position + 2 + c.Peek16();
                    c.Number("Cipher suites byte length", 2);
                    while (c.Position < end) c.Named16("Cipher suite", CipherName, "client-hello");
                    c.Hex("Legacy compression methods", c.Number("Compression methods length", 1), "client-hello");
                }
                else
                {
                    c.Named16("Selected cipher suite", CipherName, "server-hello");
                    c.Number("Legacy compression method", 1);
                }
                DecodeExtensions(c, type);
            }
            else if (type == 8) DecodeExtensions(c, type);
            else if (type == 13)
            {
                c.Hex("Certificate request context", c.Number("Context length", 1), "certificate-request");
                DecodeExtensions(c, type);
            }
            else if (type == 15)
            {
                c.Named16("Signature scheme", SignatureName, "signature-algorithms");
                c.Hex("Signature (public proof)", c.Number("Signature byte length", 2), "certificate-verify");
            }
            else if (type == 20) c.Hex("verify_data (endpoint-visible MAC)", length, "finished");
            else if (type == 11)
            {
                c.Hex("Certificate request context", c.Number("Context length", 1), "certificate");
                var listLength = c.Number("Certificate list byte length", 3);
                var end = c.Position + listLength;
                while (c.Position < end)
                {
                    c.Hex("DER X.509 certificate", c.Number("DER certificate length", 3), "certificate");
                    c.Hex("Certificate entry extensions", c.Number("Entry extensions length", 2), "certificate");
                }
            }
            else c.Hex("Message body", length);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            f.Add(new("Decoder diagnostic", ex.Message, 0, 0));
        }
        return f;
    }

    private static void DecodeExtensions(Cursor c, int messageType)
    {
        int end = c.Position + 2 + c.Peek16();
        c.Number("Extensions byte length", 2);
        while (c.Position < end)
        {
            int type = c.Number("Extension type", 2);
            int size = c.Number("Extension length", 2);
            int stop = c.Position + size;
            var name = type switch { 0 => "server_name", 10 => "supported_groups", 13 => "signature_algorithms", 43 => "supported_versions", 51 => "key_share", 45 => "psk_key_exchange_modes", 50 => "signature_algorithms_cert", _ => $"extension_{type}" };
            var topic = type switch { 0 => "identity", 43 => "versions", 51 or 10 => "key-share", 13 or 50 => "signature-algorithms", _ => "client-hello" };
            c.Mark(name, size, topic);
            if (type == 0 && size > 0)
            {
                c.Number("Server name list length", 2, "identity");
                while (c.Position < stop)
                {
                    c.Number("Server name type", 1, "identity");
                    c.Text("DNS server name", c.Number("DNS name byte length", 2), "identity");
                }
            }
            else if (type == 43)
            {
                if (messageType == 1) c.Number("Versions byte length", 1, topic);
                while (c.Position < stop) c.Named16("Supported version", x => x == 0x0304 ? "TLS 1.3" : $"0x{x:X4}", topic);
            }
            else if (type is 10 or 13 or 50)
            {
                c.Number("List byte length", 2, topic);
                while (c.Position < stop) c.Named16(name, type == 10 ? GroupName : SignatureName, topic);
            }
            else if (type == 51)
            {
                if (messageType == 1) c.Number("Key share list byte length", 2, topic);
                while (c.Position < stop)
                {
                    c.Named16("Key share group", GroupName, topic);
                    if (c.Position < stop) c.Hex("Public key exchange bytes", c.Number("Key exchange length", 2), topic);
                }
            }
            else c.Hex(name + " data", size, topic);
            if (c.Position != stop) throw new InvalidDataException("Extension length mismatch.");
        }
        if (c.Position != end) throw new InvalidDataException("Extensions length mismatch.");
    }

    public static string CipherName(int n) => n switch { 0x1301 => "TLS_AES_128_GCM_SHA256", 0x1302 => "TLS_AES_256_GCM_SHA384", 0x1303 => "TLS_CHACHA20_POLY1305_SHA256", _ => $"0x{n:X4}" };
    public static string GroupName(int n) => n switch { 23 => "secp256r1", 24 => "secp384r1", 29 => "x25519", 30 => "x448", _ => $"0x{n:X4}" };
    public static string SignatureName(int n) => n switch { 0x0403 => "ecdsa_secp256r1_sha256", 0x0503 => "ecdsa_secp384r1_sha384", 0x0804 => "rsa_pss_rsae_sha256", 0x0807 => "ed25519", _ => $"0x{n:X4}" };

    private sealed class Cursor(byte[] data, List<DecodedField> fields)
    {
        public int Position { get; private set; }
        public int Peek16() { Ensure(2); return (data[Position] << 8) | data[Position + 1]; }
        private void Ensure(int count) { if (count < 0 || Position + count > data.Length) throw new InvalidDataException("Field extends beyond the message."); }
        public int Number(string name, int count, string topic = "records")
        {
            Ensure(count); int value = 0;
            for (int i = 0; i < count; i++) value = (value << 8) | data[Position + i];
            fields.Add(new(name, value.ToString(), Position, count, topic)); Position += count; return value;
        }
        public void Named16(string name, Func<int, string> format, string topic)
        {
            int value = Peek16(); fields.Add(new(name, $"{format(value)} · 0x{value:X4}", Position, 2, topic)); Position += 2;
        }
        public void Hex(string name, int count, string topic = "records")
        {
            Ensure(count); fields.Add(new(name, Convert.ToHexString(data.AsSpan(Position, count)), Position, count, topic)); Position += count;
        }
        public void Text(string name, int count, string topic)
        {
            Ensure(count); fields.Add(new(name, Encoding.ASCII.GetString(data, Position, count), Position, count, topic)); Position += count;
        }
        public void Mark(string name, int count, string topic) { Ensure(count); fields.Add(new(name, $"{count} bytes", Position, count, topic)); }
    }
}
