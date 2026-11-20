# Windows runtime

The two 64-bit Windows executables were cross-compiled from the included C++17 sources with LLVM-MinGW UCRT. The server listens on 127.0.0.1:8080.

Crow, Asio, SQLite and nlohmann/json are included under backend/vendor. OpenSSL and curl runtime libraries come from the MSYS2 UCRT64 distribution. Distributed DLLs are the Windows import dependencies of the executables and libraries. Licence notices are in licenses. Mozilla's public root certificate bundle is included for TLS connections from Windows. It can be refreshed from https://curl.se/docs/caextract.html.

Compiler distribution and sources: https://github.com/mstorsjo/llvm-mingw/releases/tag/20261117

MSYS2 package archives: https://repo.msys2.org/mingw/ucrt64/

MSYS2 packaging recipes and upstream source references: https://github.com/msys2/MINGW-packages

## Verification performed

The native Linux build and bundled x64 Windows executable were built successfully. The Windows executable ran under Wine with a real Chromium browser. Checks covered registration, login, account isolation, URL and email results, software-source checks, private history, PDF downloads, theme persistence, account editing, password changes, session invalidation, account deletion, mobile navigation and local FAQ responses. Selected benign files were checked with a local ClamAV daemon and a temporary harmless test signature, exercising both available verdicts.

For this update the bundled Windows server and separate scanner worker ran under Wine against a real ClamAV daemon. The test drive was the only fixed drive visible to the worker and contained 57 harmless fixtures. From the browser, a confirmed complete scan finished, reported 57 files and one matching test signature, and produced a saved report. Turning the engine off exposed the recovery instructions and connection retry. Bare domains, multiple suffixes, invalid URLs, optional email sender, PDF download, settings persistence, assistant placement, authentication and account isolation also passed checks.

The local server serves the login at http://127.0.0.1:8080/. The external paid APIs were not exercised. Test accounts and fixtures are excluded from the distribution.

The packaged Windows server was also tested in Chromium under Wine with the updated URL, software, email, SMS and selected-file forms. Tests covered unfamiliar sources, publisher references and lookalikes, typo-containing refund requests, PDF export and SQLite history. A 24,585-byte PDF produced the expected SHA-256 and separate outcomes with ClamAV on and off. A harmless custom ClamAV signature produced a detection. A local Windows antimalware provider was unavailable in this environment. The AMSI fallback requires an answering provider before reporting a malware verdict.
