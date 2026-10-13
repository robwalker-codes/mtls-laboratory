# Security model

mTLS Laboratory is a local educational application, not a production TLS gateway, credential service or certificate authority.

## Intended boundary

The web server binds to `127.0.0.1:5080` over HTTP by default. Its control traffic is distinct from the genuine TLS channel between its two in-process peers. The default host allowlist is localhost/loopback. Do not expose this page to an untrusted network without separate web-tier HTTPS, authentication, authorisation, origin protection, resource limits and operational review. Those deployment features are not implemented here.

The laboratory accepts no arbitrary remote TLS destination, uploaded certificate, user-provided private key or external identity configuration. Each session creates its own bounded local experiment. It is not designed to isolate hostile users sharing one process.

## Keys and certificates

Demonstration roots, leaves and ECDSA keys are generated in memory per session. Normal operation writes no private key or TLS traffic secret to disk, the browser, logs or saved learning state. Certificate inspection exposes public fields only. Session disposal closes both protocols and disposes certificate handles. Managed-memory copies cannot be promised to disappear immediately; a process debugger or memory dump can expose secrets.

No system-wide certificate trust is installed. Each endpoint has a separate custom-root trust policy. Incoming public DER is validated for path, issuer signature, constraints, validity, purpose and, for the server, DNS identity. Certificate acceptance alone never establishes completed TLS authentication. Bouncy Castle verifies CertificateVerify and Finished using its actual protocol implementation.

All application messages are intentionally visible in the UI and in the in-memory trace. Send only teaching data. Trace records and decoded certificate signatures are public or endpoint-observed data; they are not private keys.

## Deliberate policy decisions

- TLS 1.3 only; AES-128-GCM/SHA-256; P-256 ECDHE and ECDSA.
- Explicit DigitalSignature KU, expected EKU and non-CA endpoint constraints.
- DNS SAN matching to the fixed reference name `localhost`; no common-name fallback or wildcard matching.
- Required client authentication rejects an empty certificate list with a genuine `certificate_required` alert.
- Server-only mode explicitly leaves client identity unauthenticated. Its greeting feature is unprivileged and grants no client-specific permission.
- Revocation is not checked. There is no CRL/OCSP service, remote issuer retrieval or production enrolment workflow.
- Adding the independent root is an explicit experiment setting applied on a fresh session, not an automatic retry fallback.
- A failed session cannot submit application messages. AEAD tampering is tested to reject data before releasing plaintext.

## Resource and web considerations

There are bounds on record length, buffering, trace size, handshake message size and submitted text. Blazor circuit retention is two minutes. This limits accidental teaching workloads, not hostile multi-user denial of service. HTTP antiforgery is enabled. Razor escapes displayed text and certificate fields. External links use `noopener noreferrer`; no third-party scripts, fonts or runtime AI services are used.

Browser-tab progress uses an ephemeral data-protection provider. It persists across reloads of the same running application but not across a process restart. It contains only lesson completion, answers and explanation depth.

## Reporting a problem

For a defect in this laboratory, report a minimal reproduction, scenario, expected/actual outcome and relevant **public** trace information to the repository maintainer. Do not include private keys, live traffic secrets, sensitive application messages or full process dumps. Follow the upstream Bouncy Castle reporting process for defects in the library itself.
