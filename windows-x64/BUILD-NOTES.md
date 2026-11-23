# Windows runtime

The 64-bit Windows server was rebuilt from the included C++17 sources with Visual Studio 2022 x64. OpenSSL, curl, zlib and the MSVC runtime are statically linked, so the server depends only on Windows system DLLs. The separate scanner helper remains cross-compiled with LLVM-MinGW UCRT. The server listens on 127.0.0.1:8080.

Crow, Asio, SQLite and nlohmann/json are included under backend/vendor. The bundled libc++ and libunwind DLLs are required by the scanner helper. Other runtime DLLs and licence notices are retained in the package. Mozilla's public root certificate bundle is included for TLS connections from Windows. It can be refreshed from https://curl.se/docs/caextract.html.

Compiler distribution and sources: https://github.com/mstorsjo/llvm-mingw/releases/tag/20261117

MSYS2 package archives: https://repo.msys2.org/mingw/ucrt64/

MSYS2 packaging recipes and upstream source references: https://github.com/msys2/MINGW-packages

## Verification performed

The bundled server was rebuilt from the included C++17 sources with Visual Studio 2022 x64 using the static x64 Windows dependency triplet. Its imports were checked: it depends only on Windows system DLLs. Website checks use the local inspector, not Google Safe Browsing, VirusTotal or another verdict API. The focused Website Inspector CTest target passed (1/1). Live API and browser checks confirmed `https://example.org/` returned **No Known Issues Detected** with 0 points and complete inspection, while `http://example.com/` returned 8 points for unencrypted HTTP. Three repeated `https://example.com/` scans returned a consistent 0 score and HTTP 200. Definitive DNS responses with no address records now contribute a low-severity finding; timeouts and resolver failures remain unscored. The unresolved `https://www.youtube.fb/` fixture now scores 17 from brand mismatch plus missing DNS evidence, and retains an incomplete backend status. A controlled `paypa1.test` case stays at 14 points, while `paypa1-secure-login.test` combines the PayPal lookalike with login language and scores 55/100. Loopback addresses were blocked, invalid schemes were rejected, and incomplete scans remain excluded from dashboard averages.

The expanded controlled unit tests cover reliability weighting, duplicate IDs, correlated-family aggregation, independent-category corroboration, score caps, form-domain comparisons, visible URL/link destination mismatch, external-resource counts, meta-refresh observations, and urgency paired with sensitive form fields. An external password-collection form by itself scores below 50; paired with urgent account-verification language, the independent form/content evidence scores 54. Network-timeout injection, a live controlled redirect chain, and external form-page integration were not exercised in this validation run.

The native Linux build and bundled x64 Windows executable were built successfully. The Windows executable ran under Wine with a real Chromium browser. Checks covered registration, login, account isolation, URL and email results, software-source checks, private history, PDF downloads, theme persistence, account editing, password changes, session invalidation, account deletion, mobile navigation and local FAQ responses. Selected benign files were checked with a local ClamAV daemon and a temporary harmless test signature, exercising both available verdicts.

For this update the bundled Windows server and separate scanner worker ran under Wine against a real ClamAV daemon. The test drive was the only fixed drive visible to the worker and contained 57 harmless fixtures. From the browser, a confirmed complete scan finished, reported 57 files and one matching test signature, and produced a saved report. Turning the engine off exposed the recovery instructions and connection retry. Bare domains, multiple suffixes, invalid URLs, optional email sender, PDF download, settings persistence, assistant placement, authentication and account isolation also passed checks.

The local server serves the login at http://127.0.0.1:8080/. The external paid APIs were not exercised. Test accounts and fixtures are excluded from the distribution.

The packaged Windows server was also tested in Chromium under Wine with the updated URL, software, email, SMS and selected-file forms. Tests covered unfamiliar sources, publisher references and lookalikes, typo-containing refund requests, PDF export and SQLite history. A 24,585-byte PDF produced the expected SHA-256 and separate outcomes with ClamAV on and off. A harmless custom ClamAV signature produced a detection. A local Windows antimalware provider was unavailable in this environment. The AMSI fallback requires an answering provider before reporting a malware verdict.
