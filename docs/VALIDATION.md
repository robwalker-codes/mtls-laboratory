# Validation and implemented scope

Validation was performed on Linux x64 with .NET SDK 10.0.401 and BouncyCastle.Cryptography 2.7.0. No hosted GitHub Actions run, Windows execution or publication of the environment is implied by these results.

## Executed checks

- Normal NuGet restore and `dotnet build`: successful, with zero warnings and zero errors.
- Locked restore, Release build and xUnit suite: 26 passed, zero failed, zero skipped.
- Debug xUnit suite: 26 passed, zero failed, zero skipped.
- Optional local Bouncy Castle source build and integration suite: 26 passed. The source override preserved normal NuGet lockfiles.
- A clean source copy without `bin`, `obj` or Git metadata, using a separate initially empty NuGet package directory: normal restore/build and all 26 tests passed.
- The documented `dotnet run --project src/MtlsLab.Web` command started the clean source copy on the default HTTP loopback listener.
- Chromium exercised the actual Interactive Server application: initial ClientHello queuing, one-record Next, completed mutual TLS, encrypted greeting delivery and an expired-certificate failure that disabled messaging.
- Additional browser checks covered actual byte-range highlighting, lesson pinning, depth/history navigation without protocol advancement, Run/Pause/resume, separate browser sessions, the visible current record and completion/answer restoration after reload.
- Desktop and 390-pixel mobile layouts were inspected; the mobile page had no horizontal overflow. These browser runs reported no JavaScript page errors.
- All 24 lesson source references were matched to real member declarations and line positions at the pinned upstream commit. A representative pinned GitHub source page was retrieved successfully.

Browser automation was performed using the cloud's existing Chromium/Playwright tooling; it is not an application dependency or part of the xUnit suite. The GitHub Actions definition runs the package-based build/test checks on Linux and Windows once pushed.

## What the tests establish

The TLS tests instantiate the genuine client and server engines. They verify TLS 1.3 negotiation, both certificate-based identities, server-only mode, missing-client rejection, untrusted client/server roots, expiry, hostname mismatch, wrong purpose and explicit trust changes. Both directions exchange encrypted messages; altering a real record's authentication tag rejects it before plaintext is delivered.

Certificate tests validate generated roots, signing/chain relationships, distinct keys/serials, custom anchor selection, expected purpose, lifetime and DNS identity. A deliberately corrupted issuer signature fails validation.

Transport tests cover partial headers/payloads, every split boundary for representative records, multiple records per buffer, handshake messages spanning/sharing fragments, bounds, delivery order, single-record stepping, cancellation/resumption, disposal and session isolation.

Educational checks cover required topics, substantive and distinct explanation depths, glossary/course targets, question answers, source/RFC metadata, actual ClientHello field values and offsets, encrypted-record labelling and non-mutating lesson inspection. They do not pretend that an HTTP link-shape check proves remote content availability.

## Boundaries and remaining limitations

- Stepping pauses before a record delivery. Internal synchronous work needs conventional debugger breakpoints.
- Endpoint handshake associations identify the record that completes/triggers processing, not all contributing records in a fragmented message.
- One suite/group/signature combination is exposed. HelloRetryRequest is a substantial reference lesson but has no selectable triggering experiment. Resumption, 0-RTT, post-handshake authentication, KeyUpdate controls, packet capture export and arbitrary network peers are not implemented.
- Cryptography diagrams explain relationships without showing live secret values. The transcript hash and detailed secret objects require local source debugging; the UI does not export them.
- The PKI uses direct root issuance, without an intermediate-CA experiment. It supplies no revocation infrastructure or production authorisation model.
- TLS presents application bytes as a stream. The short, bounded greeting demonstration displays received chunks and is not a general message-framing protocol.
- Progress persists in browser-tab session storage while the server process runs. A server restart changes its ephemeral protection key and starts new learning state and TLS sessions.
- Live RFC Editor page requests returned HTTP 403 in the cloud, so remote HTTP reachability was not verified. The section-specific normative links are included; all authored teaching content is embedded and works offline.
- The repository started without commits. The prepared cloud configuration is a saved draft, not proof of publication or restoration into a new task.
