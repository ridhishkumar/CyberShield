# CyberShield

CyberShield is a local cybersecurity workspace for Windows. A C++17 Crow server serves the HTML, CSS and JavaScript and stores each account's data in SQLite. The first screen is the CyberShield login. Register an account, then log in to open the dashboard, checkers and awareness guides.

## Run the supplied Windows x64 application

1. Extract the entire ZIP into a writable folder. Close any older CyberShield server window before starting this copy.
2. Double-click **Start CyberShield.cmd** and keep its console window open.
3. Paste **http://127.0.0.1:8080/** into your browser. The first screen is the login page. New users can choose **Register** and then log in.
4. After login, the dashboard opens with features in the left sidebar and account controls across the top. On small screens, use the menu button to open the sidebar. The Profile menu contains My Profile, Theme, Settings and Sign out.
5. Registered accounts, salted password hashes and hashed sessions are stored in **backend/database/cybershield.db** inside this extracted folder. To keep existing accounts when upgrading, stop the old server, back up its database folder, and copy that folder into the new extraction before starting the new server.
6. Press Ctrl+C in the server window when finished. The next time you start the server, the same URL and database are available.

The Windows executable is unsigned. The complete editable source is included in the ZIP. The runtime binds only to loopback. Open the site through its local server so forms, accounts and navigation can use the API. An empty database is created automatically in `backend/database/cybershield.db`. Use one local server instance per extracted project.

**Updating an existing copy.** Close the old server and extract this release in a new folder. To keep your accounts and history, copy the entire `backend/database` folder from your old copy over the starter database folder in the new copy before launching it. Keep the old folder as a backup.

## What you can do

- **Website checker** performs a bounded, local inspection of URL/domain structure, brand lookalikes (including hyphen-separated hostname tokens), system DNS answers, TLS, HTTP responses and headers, redirects, inert HTML, metadata, forms, links and resource hosts. It blocks non-public destinations, pins validated DNS answers, revalidates redirects, limits response size and scan time, and never executes site scripts. Findings include evidence, severity, reliability and weighted signal points. Correlated findings are grouped, category caps limit accumulation, and independent categories can add a bounded corroboration bonus. Brand lookalikes paired with login/account language and external password collection paired with urgent verification language receive stronger combined-evidence scores; either signal alone remains below the high-risk threshold. The separate approved-TLD policy adds 51 risk points for a domain whose final TLD is not in the configurable approved list (currently .com, .in, .org, .net, .edu, .gov, .co, .uk, .ca, .au, .de, .jp and .io); an approved TLD is not a safety verdict, and other findings still apply. Missing checks and temporary technical failures add no risk; a definitive DNS response with no address records is a low-severity, evidence-based indicator. A separate A–Z framework marks unavailable checks explicitly. **No Known Issues Detected** is not a safety guarantee. If inspection cannot complete, the report displays the score derived from evidence collected so far without an incomplete-scan status message; the backend retains the incomplete status, and these scans are excluded from the dashboard's average. No threat-intelligence service or API key is used.
- **Email checker** analyzes pasted message text locally; it does not connect to Gmail or open links. Its deterministic risk score combines urgency/manipulation (15%), link destinations (30%), sender authenticity (20%), financial/sensitive actions (20%) and content behavior (15%), with capped corroboration for independent signals. It extracts plain-text, Markdown and HTML links and reports actual hosts, mismatches and incomplete parsing. Category scores, evidence, analysis completeness and recommended action are shown separately; low risk is not proof of legitimacy. The configurable organization registry currently contains ICICI Bank. SPF, DKIM and DMARC results are treated only as claims in supplied headers and are not independently authenticated. Message bodies, subjects, sender addresses and raw headers stay out of the database.
- **SMS scam detector** analyzes pasted text locally with separate link, sender/impersonation, requested-action, urgency and context scores. It distinguishes informational mentions from active requests, extracts links without opening them, and reports risk, confidence and analysis completeness separately. Sender labels are not authenticated; the verified sender registry currently has no configured sender IDs or phone numbers. SMS permissions are not requested, and saved history omits sender values and evidence excerpts.
- **Software detector** parses the hostname and compares the applicable host/path against 64 configured publisher references. An unlisted source is unknown, not risky by itself; a known publisher domain with an unlisted path is distinguished from a matching download reference. Domain matching is case-insensitive and uses DNS-label boundaries, while shared-host references remain path-scoped. The weighted dimensions are source/domain (20%), file authenticity (25%), file characteristics (25%), redirect destination (10%), threat intelligence (10%) and publisher/brand consistency (10%); the score normalizes across checks that actually ran. High risk requires at least two independent strong signal families, except for a local antivirus detection. Declared publisher names are compared with the local product reference but do not authenticate the source or file. A configured host/path match is not live site verification and does not verify a file or every link on the site. Pasted URLs are never opened, and network redirects are not followed. Optionally select the downloaded installer (up to 200,000,000 bytes) to compute its SHA-256, inspect headers and static markers, request a local ClamAV/Windows antimalware verdict, and check Windows PE Authenticode signatures without executing the file. No file or hash is sent to an external reputation service. Threat-intelligence lookup is not configured and is reported as unavailable; incomplete evidence is shown separately from risk.
- **Device scanner** has two actions. Selected files receive a SHA-256 fingerprint, header check and a malware check through ClamAV or an available Windows AMSI provider. An explicitly enabled Windows helper can inspect accessible files across fixed drives. Both actions report engine outcomes. See the installation details below.
- **Dashboard** shows counts, recent activity, daily scan volume and daily scores from your retained records. Risk is capped at 100. Scores of 0–24 are lower risk, 25–59 suspicious and 60–100 high risk. The dashboard score is 100 minus the average numeric technical risk score. Engine-only verdicts have no numeric score. A high-risk heuristic report is counted separately from an antivirus detection.
- **History** supports search, type/date/risk filters, owned report retrieval, PDF download and confirmed deletion. Turning off history prevents future reports entering the dashboard. Immediate reports remain downloadable.
- **Awareness** contains ten beginner guides. **News** retrieves timestamped RSS headlines from The Hacker News and caches the last successful feed in memory. Category filters match terms in the publisher's text. Empty feeds show the publisher link.
- **Assistant** follows the pointer, opens on click and uses a local FAQ. Reduced-motion preferences disable tracking and idle animation. A configured AI provider can answer a question when the user opts in.
- **Profile and settings** cover profile changes, password changes, theme, notification preferences, history retention, active sessions, remote session sign-out and account deletion. The bell lists real events. Password changes invalidate all sessions. Recovery displays the installation's email-delivery status. The default installation has no reset-mail provider.

## Project map

```text
CyberShield/
  Start CyberShield.cmd       Start the bundled server for browser access
  Start-CyberShield.ps1        Build and start an editable source checkout
  windows-x64/                Server, scanner helper, runtime DLLs and notices
  frontend/
    login.html, signup.html, forgot-password.html, index.html, about.html
    website-detector.html, email-detector.html, awareness.html
    [ten individual topic pages]
    pages/                    Eleven authenticated pages
    css/style.css              Responsive layout, themes and motion
    js/                       API client and page-specific interactions
    assets/                   Shield illustration, icons, font and PDF library
  backend/
    CMakeLists.txt, vcpkg.json
    include/                  Interfaces and DSA code
    src/                      Routes, database, accounts, detection and integrations
    vendor/                   Crow, standalone Asio, JSON and SQLite sources
    database/                 User database created on first run
  local-scanner/
    include/scanner.h
    src/main.cpp, scanner.cpp  Windows worker and ClamAV communication
```

## Build from source in VS Code on Windows x64

Install Git, VS Code, Visual Studio **2022** Build Tools with the **Desktop development with C++** workload and Windows SDK, plus CMake (3.18 or newer). A Developer PowerShell for VS 2022 is convenient. In VS Code open the folder containing this README.

Check the tools and bootstrap vcpkg once. Choose a writable location for the dependency manager. The following commands assume a new folder named `cs-vcpkg` beside the project.

```powershell
git --version
cmake --version
git clone https://github.com/microsoft/vcpkg.git ..\cs-vcpkg
& ..\cs-vcpkg\bootstrap-vcpkg.bat -disableMetrics
$env:VCPKG_ROOT = (Resolve-Path ..\cs-vcpkg).Path
```

From the project root, configure and build. vcpkg installs OpenSSL and libcurl from the backend manifest. CMake compiles the bundled SQLite amalgamation and uses the bundled Crow, Asio and JSON headers. The build produces both the web server and the scanner. All first-time dependency downloads require internet access.

```powershell
cmake -S backend -B build/source -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows -DVCPKG_MANIFEST_MODE=ON
cmake --build build/source --config Release --parallel 2
& .\build\source\Release\cybershield.exe .
```

For subsequent starts use the last command or `./Start-CyberShield.ps1`. After source edits, run the build command again. Open http://127.0.0.1:8080. The frontend API base is the relative path `/api/`, so the browser sends same-origin requests. The server handles static files, JSON routes and the SQLite schema. Port 8080 must be free. The optional source build also works on Linux with a C++17 compiler, CMake, OpenSSL and libcurl development packages; full fixed-drive scanning is Windows-specific.

## Optional integrations

**ClamAV.** Install a supported ClamAV Windows release from the ClamAV project. Configure its signature updater, run `freshclam`, and configure and start `clamd` with `TCPAddr 127.0.0.1` and `TCPSocket 3310`. For the selected-file scanner's 200,000,000-byte request limit, configure `StreamMaxLength`, `MaxFileSize`, and `MaxScanSize` to at least 200 MB. ClamAV's configured limits still apply and can make a scan unavailable for a particular file. The separate full-drive helper retains its 8 MiB per-file limit. Follow the release's example configuration and installation guide. ClamAV owns signature updates and engine policies. Keep its unauthenticated TCP service on loopback. See https://docs.clamav.net/manual/Usage/Configuration.html.

The web server sends the bytes of selected files via the ClamAV INSTREAM protocol. Nothing is executed, quarantined or deleted by CyberShield. If ClamAV cannot return a verdict, Windows builds try the registered AMSI antimalware provider. When neither returns a verdict, the page reports that malware status is unknown. The report includes a header-based format, file size and SHA-256 fingerprint. A Windows executable disguised with a supported document or image extension raises a separate warning. The Software detector can also validate an embedded PE Authenticode signature with cached local Windows trust data; it does not fetch certificate revocation data. Retained reports include the fingerprint but omit the full filename and remove URL credentials, query strings and fragments. The server does not save file bytes.

The Device Scanner page supports selected-file checks only. The optional fixed-drive worker remains available for existing local integrations and requires the supplied `cybershield-scanner.exe` next to the server plus a responding ClamAV daemon. Its per-file limit is 8 MiB. Set CYBERSHIELD_LOCAL_SCANNER to 0 before starting the server if you want to disable the worker.

```powershell
& .\windows-x64\cybershield.exe .
```

The worker enumerates fixed drives with the current Windows user's permissions, skips reparse points, and streams regular files up to 8 MiB into ClamAV. It reports checked files, detections and skips/errors through a private pipe; the Device Scanner page no longer displays full-drive progress. Unreadable directories, engine settings, archive limits and excluded files limit coverage. This can take considerable time. The standalone helper also runs from a terminal and asks for confirmation. Only a local Windows installation can scan the computer on which its server runs.

**Independent reviews.** The optional Trustpilot integration is used only by the Software detector, not Website Checker. Configure `TRUSTPILOT_API_KEY` only with an authorised application and user consent; software-source hostnames may be sent to Trustpilot. Review sentiment does not affect Website Checker risk scores.

**Local Website Checker details.** The inspector makes a read-only GET request only after resolving the destination and confirming every returned address is globally routable. It pins the validated DNS answers for the request, disables automatic redirects and validates each redirect before following it. It blocks localhost, private, reserved, link-local, multicast, scoped and other non-public destinations; uses verified TLS; allows at most four redirects; caps each response body at 1 MiB and headers at 32 KiB; and stops after a 20-second scan budget. HTML is parsed as inert text only. If the destination cannot be resolved, safely contacted, or fully parsed, the report shows check coverage and does not treat the technical failure as a risk finding. This local inspection cannot determine domain age, registrar, nameservers, ownership, reputation, or whether a site is malicious when its behavior appears normal. The small local brand reference list can be incomplete. Registered-domain matching uses a conservative list of common multi-label suffixes, not a complete Public Suffix List.

The score deduplicates finding IDs, reliability-weights points, limits correlated evidence families to the strongest signal plus one quarter of the next, applies per-category caps, and adds up to 12 points when multiple independent categories each contribute at least 10 points. Missing checks never add risk. Verdict bands are **High risk** (50+), **Suspicious** (25–49), **Moderate Risk** (10–24), **Low Risk** (1–9), and **No Known Issues Detected** (0). Findings show their signal points and reliability, while the score calculation and category subtotal are reported separately. The report lists completed, unavailable, blocked and not-applicable checks; partial website scans are excluded from the dashboard's average score.

**AI.** Set `OPENAI_API_KEY` and `CYBERSHIELD_AI_MODEL` to a model your account can use with Chat Completions. When the chat's opt-in checkbox is selected, only that question and a short system instruction go to the configured endpoint. Scan contents and account records are excluded. The local FAQ remains available on provider failure. Keys stay in the server environment.

**Recovery.** Production recovery needs a mail provider, short-lived single-use hashed reset tokens, expiry checks and a verified delivery workflow. The supplied page states that recovery email is unavailable. Email addresses are read-only.

## API and storage

JSON requests use the origin serving the page. Each non-GET request requires `X-CyberShield: 1`. The file endpoint accepts raw bytes. Error responses have an `error` string and use HTTP 400, 401, 403, 404, 409, 413, 429 or 503 as appropriate. The HTTP parser can close a connection before a body over the configured limit is fully received.

| Endpoint | Purpose |
| --- | --- |
| POST /api/auth/register, /api/auth/login, /api/auth/logout | Create account, establish session, revoke session |
| GET /api/auth/me | Current account |
| POST /api/auth/forgot-password | Recovery availability |
| GET, PUT, DELETE /api/profile | Read/update own profile, delete with current password |
| POST /api/profile/change-password | Verify current password, update hash and end all sessions |
| GET, PUT /api/settings | Read/save preferences |
| GET, DELETE /api/sessions | List sessions, revoke other sessions |
| POST /api/check-url, /api/check-email, /api/check-software, /api/check-sms | Run explainable rules |
| POST /api/check-software-file?name=...&url=...&publisher=... | Combine software-source analysis with a locally scanned raw file body |
| GET /api/software-sources | List the bundled publisher references |
| POST /api/check-file | Inspect selected bytes and request a local antimalware verdict |
| GET, POST /api/device | Read own job status, submit consented full scan |
| GET /api/dashboard | Retained scan metrics and activity |
| GET /api/history, /api/history/search?q= | Owned records, latest 500 |
| DELETE /api/history | Remove own retained reports |
| GET /api/report?id= | Read an owned report and generate its PDF in the browser |
| GET /api/tips, /api/news | Educational tips, trusted publisher RSS |
| GET, PUT /api/notifications | List notices, mark read |
| POST /api/assistant | FAQ or opted-in provider response |

SQLite uses foreign keys, transactions, prepared statements, uniqueness constraints and per-user lookups. Tables are `users` (identity and password hash), `sessions` (hashed tokens and expiry), `settings` (one row per user), `scans` (summary and report) and `notices` (events and read state). Deleting a user cascades to dependent records. The local cookie is HttpOnly, SameSite=Strict and expires after eight hours. The server stores a SHA-256 hash of each 256-bit random session token. Password hashing uses OpenSSL PBKDF2-HMAC-SHA256 with a random 128-bit salt and 600,000 iterations.

Keep this loopback application on your own computer. A public deployment needs HTTPS, Secure cookies, a trusted-host configuration, transport-level limits, operational monitoring and a separate consent and deployment model for the local scanner. SQLite records are stored in your user-accessible project directory. Protect this directory and any exported reports with your OS account permissions.

## DSA contribution

See `backend/include/dsa.h` and `backend/src/detectors.cpp`.

| Concept | Where it is used | Complexity |
| --- | --- | --- |
| Vector | Accumulates findings and their weights | Amortised O(1) append, O(n) space |
| Linear search | Checks the small, reserved suspicious-domain list | O(n) domain comparisons |
| Stack | Pushes/pops open parentheses when trimming links from pasted prose | O(m) time and O(m) space for m characters |
| FIFO queue | Extracted email links are inspected in their original order | O(1) insertion/removal excluding string copy |
| Singly linked list | Queue nodes hold links with owning next pointers and a tail pointer | O(n) node storage |
| Bubble sort | Stable ordering of a small findings list by descending points | O(n²) worst case, O(n) already sorted |

## Acceptance checks for a college demonstration

1. Register two accounts. Try mismatched or short passwords, duplicate usernames and invalid emails. Try an incorrect password before signing in.
2. Check `example.com`, `example.in`, `example.org`, `example.xyz`, `example.com.fake`, `example.in.malicious.net`, and `example.co.uk` to verify exact final-label TLD handling. Also check an HTTP-to-HTTPS redirect, a malformed URL, an unreachable `.invalid` hostname, long/encoded URLs, and public-looking URLs that resolve to private or reserved addresses. Confirm each inspection step, redirect destination validation, score findings and confidence coverage. Ensure localhost/private destinations are blocked, TLS/network failures do not become risk points, and a failed scan cannot display a prior result or a safe verdict.
3. Compare a routine email with one containing “urgent” and “your password”. Check what the report retains. Paste raw headers and verify their values are labelled unverified.
4. Submit a software name, publisher and source. Review the distinction between source evidence and the antivirus engine.
5. Download a PDF. Search history by hostname and filter by type/date. Sign in as the second account and verify the first account's report ID is inaccessible.
6. Change a profile name and theme, reload, and confirm persistence. Disable future history, run a scan and check that its report remains downloadable while the saved count stays unchanged.
7. Review notification preferences, mark notifications read, inspect active sessions and revoke other sessions. Change a password and verify that existing sessions expire. Log out and request a protected page directly.
8. Confirm history clearing and account deletion using disposable accounts. Check a new account's empty dashboard.
9. Test an empty file, a file above 200,000,000 bytes, a selected benign file, and a configured ClamAV stream ceiling at or above 200 MB. Provider limits and verdict availability depend on the local installation.
10. Try phone width, keyboard navigation, reduced motion, system/light/dark themes, guide topics, FAQ chat, PDF export and news-feed unavailability.

## Dependencies and credits

Bundled source dependencies include Crow v1.2.1 (with a bounded HTTP body-buffer change in `crow/parser.h`), Asio 1.30.2, nlohmann/json 3.11.3 and SQLite 3.46.1. Client assets include jsPDF 3.0.3, Lucide icons and DM Sans. Their licence files accompany the assets and libraries. The original shield illustration, navigation and robot are local assets. No frontend package manager is required.

