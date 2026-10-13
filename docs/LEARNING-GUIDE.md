# Learning guide

Choose **Engineer** for the default explanation depth. Beginner explains the security problem with less terminology; Protocol Internals adds binary layouts, transcript scope and implementation details. Changing depth or selecting a lesson never advances TLS.

## Course A — Understanding TLS

1. Read **TLS 1.3 overview** and **What a secure channel does**. Identify confidentiality, integrity, identity and transport delivery as separate responsibilities.
2. Start a successful mutual experiment. Before delivering anything, inspect ClientHello. Locate the handshake header, legacy fields, version extension, SNI and public key share. Select fields to highlight actual byte ranges.
3. Deliver ClientHello. Observe that the server produces multiple pending records in one synchronous operation. Record-level stepping is not message-level pausing.
4. Inspect ServerHello and compare its selections with the offer. Follow the public key exchange into the conceptual HKDF diagram.
5. Deliver encrypted handshake records. Compare opaque wire hex with endpoint-visible EncryptedExtensions, Certificate, CertificateVerify and Finished.
6. Inspect both completion callbacks, then send and deliver greetings in each direction. Compare sender plaintext, ciphertext and recovered receiver plaintext.

Ask yourself: which observations could a passive network observer see, and which require access to an endpoint? Why does outer type 23 not necessarily mean application data?

## Course B — Understanding Mutual TLS

1. Run **Server-authenticated TLS** and identify the missing CertificateRequest/client proof. The UI must continue to label the client unauthenticated.
2. Run **Successful mutual TLS** with Client A, then Client B. Each has a distinct key and serial number; both satisfy the same issuer/purpose policy.
3. Pin the **CertificateRequest** lesson and keep advancing. Observe that pinning affects reading, not TLS execution.
4. Inspect both custom trust stores and actual validation reports. The direct chain is leaf → issuing root; no intermediate is invented.
5. Run each failure experiment below. Record the configuration, presented subject, receiving expectation, actual failed check and actual alert.
6. Run **Change the trust policy** without the independent root and observe rejection. Explicitly add it on the server, Reset and repeat. Explain why this changes issuer trust without removing purpose, lifetime or proof checks.
7. Finish with **Authentication is not authorisation**. TLS acceptance of Client A and Client B does not itself grant equal application permissions.

| Experiment | Isolated change | Expected receiver decision | Correction |
| --- | --- | --- | --- |
| Missing client | No client credential | Reject required empty certificate chain | Select a suitable client identity |
| Untrusted client | Client signed by independent root | Reject path to an untrusted anchor | Use the intended issuer, or explicitly expand trust |
| Expired client | notAfter is yesterday | Reject validity interval | Issue a fresh, in-date credential |
| Hostname mismatch | Server SAN contains wrong.example | Reject DNS identity for localhost | Issue a certificate for the intended service |
| Incorrect purpose | Client has serverAuth only | Reject absent clientAuth purpose | Issue a suitable clientAuth certificate |
| Untrusted server | Client trust excludes server root | Reject server chain | Configure the intended server trust anchor |

Do not substitute the expected result for evidence: inspect the actual callback and status text. Run stops on the first failure; Next can still transport remaining queued records, including the generated alert.

## Course C — TLS Protocol Internals

1. Study the record header and handshake header separately. Explain why two buffering/reassembly layers exist.
2. Inspect actual ClientHello extension vectors and public point lengths. Compare the record legacy version with supported_versions.
3. Contrast cipher suite, signature scheme and named group. The single selected suite does not choose the other two.
4. Read the HelloRetryRequest lesson as a conditional path. It is not part of the default trace and no shipped scenario fabricates it.
5. Trace the HKDF schedule and the transcript boundaries used for handshake traffic, Finished and application traffic derivation. Diagram values are conceptual; live secrets are not exported.
6. Compare a CA signature, CertificateVerify and Finished. Identify the different keys, signed/MACed input and security question each answers.
7. Follow the [debugger tour](DEBUGGING.md) from `Connect` to `CompleteHandshake`, using the optional source build for reliable matching symbols.
8. Review the actual tampered-record integration test. Record authentication must fail before plaintext reaches the application.

## Reading tools

- **Information icons:** keyboard/touch-accessible details with definitions, practical significance and a lesson link.
- **Learning panel:** Overview, Message Structure, Cryptography, Certificates & Trust, Source Code and RFC Reference.
- **Pin topic:** retain the current lesson while the live selection changes. A pinned lesson may intentionally describe another selected observation; Message Structure labels this.
- **Guided Learning history:** navigate captured handshake observations backwards and forwards. It does not rewind either engine. Reset is required to repeat execution.
- **Glossary:** 48 searchable concepts with explanations, related terms, lessons and specification links.
- **Courses and knowledge checks:** mark topics complete and answer questions without signing in. Progress is stored in this browser tab for the lifetime of the running application; restarting the server resets its ephemeral protection key.

RFC and source links are external reading aids. The lesson text, field explanations, glossary, questions and diagrams are embedded in the application and remain available offline after restore/build.
