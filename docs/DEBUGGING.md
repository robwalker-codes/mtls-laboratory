# Debugging the real TLS implementation

The running library is **BouncyCastle.Cryptography 2.7.0**, release tag `release-2.7.0`, commit `4007498b13582d90ee1eda5d9920c324428b98b3`. The source references below were checked against that commit. Lines can change in another release; keep the package and source checkout aligned.

## Start in application code

Open `MtlsLab.slnx` in a .NET 10-capable C# IDE, choose `MtlsLab.Web` as the startup project and launch under its debugger. Alternatively, run `dotnet run --project src/MtlsLab.Web` and attach the managed debugger to the **MtlsLab.Web process**, not merely the `dotnet run` launcher.

Use the HTTP loopback address printed on startup. Do not configure an ASP.NET HTTPS certificate just to run these experiments.

Set these initial breakpoints:

- `TlsSession` constructor: immediately before `serverProtocol.Accept` and `clientProtocol.Connect`.
- `TlsSession.Next`: immediately before `Protocol(record.Receiver).OfferInput(record.Bytes)`.
- Both `ObservedProtocols.HandleHandshakeMessage` overrides: the supported boundary exposing reassembled endpoint-visible messages.
- `TlsSession.ValidateCertificate` and `CertificatePolicy.Validate`: the actual trust decisions.
- `TlsSession.Completed`: the two distinct completion callbacks.
- `TlsSession.Send` and `ReadApplication`: application plaintext entering/leaving TLS.

Click **Start Handshake**. Resume until it returns to the UI: ClientHello should be queued, not delivered. Press **Next** to enter the server's real record processing. A breakpoint inside that call can pause more finely than the UI transport boundary. Pausing a debugger can temporarily interrupt the Blazor connection; allow it to reconnect after resuming.

## Breakpoint tour through Bouncy Castle

All file paths below are relative to `crypto/src` in the pinned source checkout. Protected/internal members are debugging locations; application code does not call them as public APIs.

| Stage | File and verified member | What to inspect |
| --- | --- | --- |
| Client initialisation | `tls/TlsClientProtocol.cs:60`, `Connect` | Independent client context and non-blocking mode |
| ClientHello construction | `tls/TlsClientProtocol.cs:1681`, `SendClientHello` | Extension dictionary, supported capabilities and ephemeral agreement state |
| ClientHello encoding | `tls/TlsClientProtocol.cs:1875`, `SendClientHelloMessage` | Handshake header/body and transcript update |
| Server initialisation | `tls/TlsServerProtocol.cs:55`, `Accept` | Server policy and ready-to-receive state |
| Record delivery | `tls/TlsProtocol.cs:1332`, `OfferInput(byte[], int, int)` | Exact queued bytes, record buffering and processing |
| Server TLS 1.3 dispatch | `tls/TlsServerProtocol.cs:754`, `Handle13HandshakeMessage` | Handshake type and state transitions |
| Client TLS 1.3 dispatch | `tls/TlsClientProtocol.cs:119`, `Handle13HandshakeMessage` | Decrypted messages from the server flight |
| Handshake secrets | `tls/TlsUtilities.cs:1767`, `Establish13PhaseHandshake` | Key-agreement input, transcript scope and pending ciphers |
| Server certificate | `tls/TlsClientProtocol.cs:1533`, `Receive13ServerCertificate` | Parsing and callback to `NotifyServerCertificate` |
| Client certificate | `tls/TlsServerProtocol.cs:1318`, `Receive13ClientCertificate` | Parsing and callback to `NotifyClientCertificate` |
| Server key possession | `tls/TlsUtilities.cs:2358`, `Verify13CertificateVerifyServer` | Role context, transcript and public-key signature verification |
| Client key possession | `tls/TlsUtilities.cs:2345`, `Verify13CertificateVerifyClient` | The corresponding client proof |
| Finished | `tls/TlsProtocol.cs:1566`, `Process13FinishedMessage` | Expected versus received verify_data |
| Application secret phase | `tls/TlsUtilities.cs:1735`, `Establish13PhaseApplication` | Transcript through server Finished and directional application secrets |
| Completion | `tls/TlsProtocol.cs:412`, `CompleteHandshake` | State commit and callback; one invocation per peer |
| Application encryption | `tls/TlsProtocol.cs:950` and `:1030`, `WriteApplicationData` overloads | Plaintext entering record protection; follow the Span overload on modern .NET |
| Application recovery | `tls/TlsProtocol.cs:1415`, `ReadInput` | Validated plaintext made available to the application |

For a failure tour, choose **Incorrect client certificate purpose**, Reset and Run. Break in `CertificatePolicy.Validate`, observe serverAuth-only EKU failing the expected clientAuth policy, then follow `TlsFatalAlert` into `NotifyAlertRaised`. Continue with Next if you want the other endpoint to receive the queued alert.

Do not export live private scalars or traffic secrets into logs, screenshots or bug reports. The normal UI captures no such values.

## External symbols and Source Link

In Visual Studio, disable **Just My Code** for the debugging session, enable **Source Link support**, and configure the NuGet symbol server (`https://symbols.nuget.org/download/symbols`) when your environment permits it. Rider provides equivalent external-source and symbol-server settings. Inspect the debugger's Modules view to see whether the loaded Bouncy Castle DLL has matching symbols; do not assume an enabled checkbox means symbols were found.

The inspected NuGet `lib/net6.0` payload contains a DLL and XML documentation, without a PDB next to the DLL. External symbol retrieval therefore depends on a matching upstream symbol publication and access to that service. This route is not guaranteed here. The following local-source route supplies matching Debug PDBs and was exercised with the integration tests.

## Reproducible optional local-source build

This requires Git only for acquiring the dependency source. It is optional and does not change the ordinary SDK-and-NuGet prerequisites.

Use a directory outside the application checkout. A full clone avoids the version-height calculation failure that Bouncy Castle's build tooling reports for an insufficiently deep clone:

```sh
git clone https://github.com/bcgit/bc-csharp.git ../bc-csharp
git -C ../bc-csharp checkout --detach 4007498b13582d90ee1eda5d9920c324428b98b3
git -C ../bc-csharp rev-parse HEAD
```

From the mTLS Laboratory root, substitute the absolute source path appropriate to your machine:

```sh
dotnet test tests/MtlsLab.Tests -p:BouncyCastleSource=/absolute/path/to/bc-csharp -p:GitRepositoryRemoteName=origin
dotnet run --project src/MtlsLab.Web -p:BouncyCastleSource=/absolute/path/to/bc-csharp -p:GitRepositoryRemoteName=origin
```

On Windows, use an absolute Windows path and quote the entire property argument if it contains spaces, for example `"-p:BouncyCastleSource=C:\source\bc-csharp"`. The same project property selects the conditional `ProjectReference` instead of the NuGet package. No library source modification is necessary. Its compatible `net6.0` target runs under this application's .NET 10 runtime; you do not need to install the .NET 6 runtime. Standard NuGet restore obtains the reference assemblies and source-build tooling.

`GitRepositoryRemoteName=origin` points Source Link tooling at the clone's actual remote. The local build retains the upstream licence and signing configuration. `Directory.Build.props` directs application source-debug lockfiles into each project's ignored `obj` directory, preserving normal package lockfiles.

For an IDE launch that does not accept command-line MSBuild properties, set `BouncyCastleSource` and `GitRepositoryRemoteName` as environment variables before opening the solution, or supply equivalent global MSBuild properties through the IDE. Confirm in Modules that `BouncyCastle.Cryptography.dll` and its matching PDB came from the local Debug build. Add the external source project to the IDE's workspace view if useful; it is already in the build graph through the project reference.

Return to normal package operation by omitting the optional properties (and clearing any IDE environment settings):

```sh
dotnet restore --locked-mode
dotnet build
dotnet test
```

A UI pause controls record delivery. A debugger pause controls code execution. Neither is a rewind of cryptographic state: Reset creates a new experiment.
