# mTLS Laboratory

A working TLS 1.3 laboratory for engineers who want to understand **what the handshake does, why it exists and where it happens in managed C#**.

Two independent Bouncy Castle TLS peers run inside one ASP.NET Core process. An inspectable memory transport queues their genuine TLS records. Release one record, watch the receiving engine process it, and explore the resulting messages, trust decisions and cryptographic explanations.

## Run

Install the **.NET 10 SDK**, clone this repository, then run from its root:

```sh
dotnet run --project src/MtlsLab.Web
```

Open the loopback HTTP address printed by the application (default `http://127.0.0.1:5080`). The normal NuGet restore supplies the dependencies. No development HTTPS certificate, administrator rights, OS certificate changes, database, JavaScript package manager, container or external TLS service is needed.

The page's local **HTTP** connection controls a separate, genuine **TLS 1.3** connection between the in-process peers. The browser does not perform the experimental handshake. Keep the web application local; remote deployment requires independent web-tier HTTPS and access control.

## A first experiment

1. Leave **Successful mutual TLS** selected and choose **Start Handshake**. The real ClientHello is queued; no record has been delivered.
2. Select the ClientHello message chip. Examine its actual random, version offer, cipher suite, SNI, signature scheme and P-256 public key share. Select a decoded field to highlight its bytes.
3. Press **Next** once. Exactly one record reaches the server. The server may synchronously create a whole response flight.
4. Continue through ServerHello and the encrypted records. The wire view remains ciphertext. A message chip labelled with a receiving endpoint exposes actual decrypted handshake bytes observed inside Bouncy Castle.
5. Open **Certificates & Trust**. Inspect each leaf and issuing root, then the independently recorded client and server validation decisions.
6. Read **CertificateVerify** and **Finished** at Engineer or Protocol Internals depth. Pin a lesson to keep it open while continuing execution.
7. Use **Run**, or keep stepping, until both peers complete. Send a greeting in either direction, inspect the protected record, then deliver it to see recovered plaintext.
8. Choose **Expired client certificate**, then **Reset** and **Run**. Inspect the failed validity decision and actual TLS alert. Messaging remains disabled.

Use **Guided Learning** to revisit captured observations without changing live cryptographic state. The three courses, 24 lessons, 48 glossary terms, knowledge checks and conceptual cryptography diagrams work offline after installation. Completion and answers persist in browser-tab session storage while the application process remains running.

## Features

- Real Bouncy Castle TLS 1.3 client/server execution; no `SslStream` alternative or mocked handshake.
- Non-blocking record delivery with Start, Next, Run, Pause, Reset and adjustable run interval.
- Incremental record framing; handshake messages may span records or share a record.
- Explicit provenance for wire bytes, endpoint instrumentation, callbacks and local state.
- In-memory P-256 PKI with independent custom root trust, lifetime, constraints, KU, EKU and DNS SAN validation.
- Nine experiments: mutual TLS, server-only TLS, missing client, untrusted client, expired client, wrong hostname, wrong purpose, untrusted server and explicit trust-policy changes.
- Actual certificate fields, chain relationships, validation diagnostics and bidirectional encrypted greeting messages.
- Three explanation depths, byte highlighting, source links pinned to the selected release and section-specific RFC references.
- Responsive, keyboard-accessible Blazor Interactive Server UI; isolated experiment state per circuit.

## Build and test

```sh
dotnet build
dotnet test
```

For CI-equivalent package resolution:

```sh
dotnet restore --locked-mode
dotnet build --no-restore --configuration Release
dotnet test --no-build --no-restore --configuration Release
```

The xUnit suite exercises real cryptography and TLS engines, valid and invalid identities, bidirectional encryption, tamper rejection, fragmented framing, record ordering, cancellation, isolation and educational mappings. The GitHub Actions workflow runs the Release checks on Linux and Windows. Hosted Actions results are separate from the local validation documented here.

## Debug the actual implementation

Start with `TlsSession.Next`, `CertificatePolicy.Validate` and the two overrides in `ObservedProtocols.cs`. Follow into Bouncy Castle's `OfferInput`, `Handle13HandshakeMessage`, `Verify13CertificateVerifyServer`, `Process13FinishedMessage` and `CompleteHandshake`.

[The debugging guide](docs/DEBUGGING.md) contains a breakpoint tour, symbol setup and a tested optional local-source project reference. Ordinary use needs only the pinned `BouncyCastle.Cryptography` 2.7.0 NuGet package.

## Design and scope

- [Architecture and observability](docs/ARCHITECTURE.md)
- [Learning guide and experiments](docs/LEARNING-GUIDE.md)
- [Source-level debugging](docs/DEBUGGING.md)
- [Security model](SECURITY.md)
- [Validation evidence and limitations](docs/VALIDATION.md)

The default is a fresh full handshake using TLS_AES_128_GCM_SHA256, P-256 ECDHE and P-256 ECDSA credentials. HelloRetryRequest is taught as a conditional branch but is not triggered by a shipped experiment. Resumption, 0-RTT, post-handshake authentication, KeyUpdate controls, revocation infrastructure and arbitrary network destinations are outside the implemented experiment set.

“Next” pauses **before record delivery**, not inside a synchronous cryptographic method. Use normal debugger breakpoints for that finer control. Traffic secrets and private keys are never displayed or written by normal laboratory operation. Received messages are intentionally visible teaching data.

New project code is [MIT licensed](LICENSE). See [third-party notices](THIRD-PARTY-NOTICES.md) for Bouncy Castle's licence.
