# Owl Eyes (PenChecker)

Owl Eyes is a browser-based security assessment assistant for an isolated
Kali Linux and Metasploitable2/DVWA lab, plus selected public web domains.
It runs predefined CLI checks, collects
reviewable evidence, and uses a local or external language model to produce
structured reports in Vietnamese.

The backend uses Python/FastAPI. The interface uses native JavaScript and local
CSS/fonts, with no Node.js dependency or frontend build step. The default branch
is `dev`.

## Features

- **Scan workspace:** Dashboard, Scan, History, and Settings; light/dark themes,
  a scan pipeline with live status, the domain's nslookup IP and scanned
  HTTP/HTTPS origins, cancellation, raw output, and evidence inspection. Press
  feedback, navigation and tab transitions respect reduced-motion settings.
- **18 CLI integrations:** fixed commands, installed-binary checks, independent
  outcomes, bounded output/timeouts, and up to three scanner processes at once.
  DVWA web tools obtain their own verified sessions. Domain targets support all
  18 tools (web, domain, and IP tools on the nslookup-resolved address) and
  recommend five: dig, whois, cURL, OpenSSL and WhatWeb.
  Recommendation badges do not select or lock the other applicable tools.
- **Saved targets:** add/edit/delete public domains and additional allowlisted
  DVWA hosts in Settings, then select one on Dashboard. Providers are shared
  across the target list; previous scans keep their original target snapshots.
- **Adaptive collection:** after defaults, the selected model can choose reviewed
  follow-up actions for selected tools, inspect their new evidence and stop when
  sufficient. Per-run output, evidence and reasons are retained.
- **AI assessment:** Ollama or multiple saved OpenAI-compatible provider profiles.
  Findings must cite collected evidence and retain its scope. Analysis can be
  retried against saved results without running scanners again.
- **Efficient model input:** repeated observations, excerpts, and coverage metadata
  are normalized or referenced while preserving citations. Repeated successful
  research requests are reused within an analysis.
- **Report refinement and CVE research:** bounded read-only public search/NVD
  functions can support model review. Manual CVE candidates remain separate from
  findings and do not prove that a vulnerability affects the target.
- **Persistent history and exports:** SQLite retains scans, attempts, and reports
  across restarts. Reports share one HTML template and support PDF export.
- **Editable settings:** target and provider settings can change while idle;
  existing scans retain their original target. Passwords and API keys are write-only.

## Infrastructure and requirements

| Component | Requirement |
|---|---|
| Host | A machine running VMware Workstation and a modern browser |
| Scanner VM | Kali Linux with Python 3.11+, virtual-environment support, and the selected CLI binaries |
| Target VM | Metasploitable2 with DVWA available at HTTP port 80 under `/dvwa/` |
| Network | An isolated Host-only network shared by the host and both VMs; Kali also has NAT access for packages, model providers and public-domain checks |
| AI | A running Ollama service with an installed model, or a configured HTTPS OpenAI-compatible provider |

Local model memory and CPU requirements depend on the model and context size.
External analysis avoids running model weights on the Kali VM.

### Set up the lab

1. Install [VMware Workstation](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)
   on the host. Download a [Kali VM image](https://www.kali.org/get-kali/#kali-virtual-machines)
   and import it using the [Kali VMware guide](https://www.kali.org/docs/virtualization/install-vmware-guest-vm/).
2. Download and import Metasploitable2 using the
   [Rapid7 setup guide](https://docs.rapid7.com/metasploit/metasploitable-2/).
3. Connect both VMs to the same Host-only network. Give Kali a separate NAT
   adapter for package downloads and external AI/research access. Keep the
   intentionally vulnerable target on Host-only only, without a default gateway.
4. Configure the lab network as `192.168.146.0/24`, which is the application's
   current allowlist. Choose distinct, unused addresses for Kali and the target.
   The app excludes `.0`, `.1`, and `.255` from its bind/target addresses. Do not
   bridge this network to the physical LAN or enable forwarding through Kali.
5. Boot both VMs, verify their addresses/routes, and open
   `http://<TARGET_HOST_ONLY_IP>/dvwa/` to confirm the target and its login.

The subnet is a software constraint, not a record of your machine's addresses.
Use verified local values in the configuration below. The original lab target
remains available; Settings can save additional lab targets and public domains.
Public checks use Kali's Internet connection. Lab profiles retain the Host-only
allowlist, and all tool commands are constructed by the server.

## Installation

Run the application commands on Kali as a normal user. `sudo` is used only for
system package installation.

### 1. Download the project

```bash
git clone --branch dev https://github.com/Dathless/owl-eyes.git
cd owl-eyes
```

Alternatively, download the [dev source ZIP](https://github.com/Dathless/owl-eyes/archive/refs/heads/dev.zip),
extract it, and open a terminal in the extracted project directory.

### 2. Install system dependencies

Install Git, Python environment support, and the five default tools:

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip nmap curl whatweb ffuf nikto
```

To enable all optional tools, install any packages missing from your Kali image:

```bash
sudo apt install nuclei httpx-toolkit wafw00f gobuster wapiti dirb wget smbclient snmp
# Public-domain checks (reuse packages already installed):
sudo apt install bind9-dnsutils whois openssl
```

`smbclient` supplies both `smbclient` and `rpcclient`; `snmp` supplies `snmpget`.
Already installed binaries are reused. The app never installs tools, downloads
scanner templates, or accepts an uploaded binary.

Use Kali's **HTTPX Toolkit** (`httpx-toolkit`), not Python's `httpx` command.
The Nikto adapter currently requires Kali Nikto **2.6.0** and its packaged data.
Startup probes check installed versions/flags; incompatible or missing tools stay
visible but disabled. The remaining enabled tools can still be selected.

### 3. Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
```

No frontend build or browser automation package is required to run the app.

### 4. Create private configuration

On a fresh installation:

```bash
install -m 600 .env.example .env
```

Edit `.env` and replace the placeholders before starting. Preserve an existing
`.env` when upgrading.

```dotenv
APP_HOST=<KALI_HOST_ONLY_IP>
APP_PORT=8000
APP_USERNAME=labadmin
APP_PASSWORD=<UNIQUE_PASSWORD_AT_LEAST_16_CHARACTERS>
LAB_TARGET_IP=<TARGET_HOST_ONLY_IP>
LAB_TARGET_URL=http://<TARGET_HOST_ONLY_IP>/dvwa/
DVWA_USERNAME=admin
DVWA_PASSWORD=password
```

`APP_HOST` and `LAB_TARGET_IP` must be different addresses within the supported
Host-only subnet. The URL must match the configured target IP, use HTTP port 80,
and end in `/dvwa` or `/dvwa/`, without query parameters or fragments.

The application password is separate from the DVWA login. `admin` / `password`
are public DVWA lab defaults; replace them if your target uses different values.
Generate a unique application password locally, then copy it into `.env`:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(24))'
```

[.env.example](.env.example) lists all supported bootstrap settings. Never commit
`.env`, `.env.ai`, real credentials, session cookies, databases, or generated reports.

## Configure AI

Choose either provider option. The interface can start before a provider is
configured; starting a scan requires an enabled provider.

### Local Ollama

Install Ollama using its [Linux installation guide](https://docs.ollama.com/linux).
Start the service if it is not already running. For a manual foreground instance,
run `ollama serve` in another terminal.

Download a model appropriate for the VM. This example uses the published
[Qwen2.5 3B instruct tag](https://ollama.com/library/qwen2.5:3b-instruct-q4_K_M):

```bash
ollama pull qwen2.5:3b-instruct-q4_K_M
ollama list
```

Set the exact installed tag in `.env`:

```dotenv
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:3b-instruct-q4_K_M
OLLAMA_CONTEXT_TOKENS=8192
OLLAMA_NUM_THREADS=4
```

CPU-only analysis may take several minutes. Adjust the analysis deadline to your
hardware; `AI_TOTAL_TIMEOUT_SECONDS` defaults to 180. Raising the context also
raises memory requirements. The app does not download models or silently switch
providers when analysis fails.

### External provider

Start the app, then open **Settings → Provider AI → + Thêm nhà cung cấp**.
Enter a profile name, HTTPS endpoint, API key, model ID, and optional display name.
Save multiple profiles and select one for a scan or analysis retry.

HTTPS origins, custom API base URLs, and full `/chat/completions` endpoints are
supported. Set the advanced JSON-output mode and token-limit field to values the
provider supports. Legacy `OPENAI_*` configuration in `.env` remains available.

Keys are write-only; a blank key during editing keeps the saved value. Settings
save to private `.env.ai` while idle and override the corresponding `.env` fields.
Saving a profile does not call the provider. External analysis sends scrubbed
scan evidence, including lab addresses and service banners, to the selected host.

### Research and refinement

```dotenv
AI_AGENT_ENABLED=true
AI_AGENT_MAX_LOOPS=5
```

Both provider types can choose collection follow-ups through structured JSON.
The model selects fixed action IDs, never commands, flags or new destinations.
Collection allows up to five planning rounds (or the lower configured round cap),
six additional runs total, and four runs per tool including its default. Planning
shares a separate budget of up to 120 seconds, capped by the AI deadline; each
tool retains its own timeout. Cancelling also interrupts model planning.
Planning receives a compact digest (at most 3,000 bytes: each tool's state, runs
already made, response-status counts and a few distinctive facts) rather than the
full report input, so small local models can decide within that budget. An action
may carry a server-computed `evidence` reason, for example an IIS fingerprint or a
`robots.txt` that answered 200; the model still decides. A new round is skipped
when the remaining budget is shorter than the previous planning call took, and an
unavailable round records its error code, such as `provider_auth_failed`.

Both provider types can use the same bounded report research/refinement loop. Native
function calling is needed for research; unsupported tools fall back to reporting
from scan evidence. Each round reviews the latest accepted draft, optionally
requests public research, and validates a replacement against the original scan.
A later failed or rejected revision keeps the last accepted draft.

The default cap is five rounds, configurable from 1–20 in **Settings → Chung**.
All rounds and retries share the analysis deadline. More rounds can increase
latency and external-provider costs. Set `AI_AGENT_ENABLED=false` for evidence-only
analysis with no collection follow-ups; `OLLAMA_RESEARCH_ENABLED=false` disables
research for Ollama only.

Research functions use prepared public product/version, CVE, or DVWA-hardening
queries with DuckDuckGo/NVD. Target addresses, credentials, and raw scan output
are not sent to those sources. Returned links are not fetched. Research remains
advisory context and never controls scanner commands.

## Run and use

From the project root:

```bash
source .venv/bin/activate
python -m app
```

Open `http://<KALI_HOST_ONLY_IP>:8000/` in the host browser and sign in with
`APP_USERNAME` / `APP_PASSWORD`. Use your configured port if it differs from 8000.
The backend runs one Uvicorn worker without reload. Restart after code or server
configuration changes; target/provider settings saved in the UI apply while idle.

1. In **Settings → Target**, add named targets using a domain/HTTP(S) root URL,
   or a DVWA lab IP/URL. Additional lab profiles share the DVWA credentials in
   the existing form. The built-in lab target remains editable there.
2. On **Dashboard**, choose a target, enabled tools and a provider. The target
   card shows how it will be reached (domain: nslookup → one pinned public IP →
   HTTP + HTTPS when both answer; lab: Host-only HTTP/80). Domain tools display
   **Đề xuất**; the badge does not check them automatically. Expand **Thêm công
   cụ quét** for the remaining catalog, grouped as Web, Tên miền and Dịch vụ theo IP.
3. Start collection. Only one scan or analysis operation runs at a time; tool
   failures and timeouts remain independent.
4. On **Scan**, follow the pipeline (queued → collecting → analyzing → result).
   Domain scans show the resolver, pinned IP, returned addresses and scanned
   origins; tool cards mark each run's origin (`http`/`https`) or follow-up.
   Inspect the report, observations, raw output, and AI attempts.
   Evidence chips show the original excerpt and its source. Expand **Các vòng
   phân tích và lần chạy công cụ** for the agent-round timeline and run outcomes.
   Raw output groups repeated runs under their preset IDs and refreshes when
   another run finishes. Collection duration includes model planning time.
5. Cancel active work with **Dừng scan** or **Dừng tạo báo cáo**. Use
   **Phân tích lại** to retry analysis without another collection.
6. Export PDF or use **Tra cứu CVE** to review separate NVD candidates. Use
   **Thu gọn** or **Ẩn kết quả CVE** to minimize the panel; **Hiện kết quả CVE**
   reopens the saved results and expanded details without another lookup.
   **Tra cứu lại** is the separate action for updating NVD results.
7. Open **Lịch sử** to select a saved scan or open its archived HTML report.

Closing the browser does not cancel a scan. Refreshing can recover the active
view; saved history survives a backend restart. Interrupted tool runs are marked
cancelled on recovery; scans are never restarted automatically. Settings provides
General, Host, Target, AI Providers, and System panels. Host/server/scanner facts are read-only;
editing lab targets preserves the allowlist and existing scan snapshots. Deleting
a saved target preserves its historical scans. Target saves make no network calls.

## Tool catalog and scope

| Tool | Fixed purpose |
|---|---|
| dig | Public DNS A/AAAA/MX/NS/TXT/CAA; optional SOA/CAA or DNSKEY follow-up |
| whois | Registered parent domain metadata without registrar-referral recursion |
| OpenSSL | Hostname-verified TLS handshake with SNI; optional TLS 1.2/1.3 checks |
| Nmap | Lab TCP/80, or 24 reviewed TCP ports on a domain's nslookup-resolved IP |
| cURL | HTTP headers/status without redirects; optional HEAD or fixed public metadata paths |
| WhatWeb | HTTP technology fingerprints |
| ffuf | 17 DVWA paths or eight fixed general website paths; optional 11 IIS/ASP.NET paths; no recursion |
| Nikto | Limited web-server checks; CGI tests only in CGI directories that exist; other paths retain their own scope |
| Nuclei | Four bundled, reviewed HTTP templates; no template downloads or OAST |
| HTTPX Toolkit | HTTP status, title, server, and technology observations |
| Wafw00f | WAF fingerprints |
| Gobuster | Fixed DVWA or website paths with wildcard detection |
| Wapiti | Passive header, cookie-flag, and CSP checks; no crawling |
| DIRB | Fixed DVWA or website paths; no recursion, 200 ms delay |
| Wget | One HTTP response; no redirects or linked downloads; optional public HEAD |
| smbclient | Anonymous share names on the lab host's or the domain's resolved IP, TCP/445; no file access |
| rpcclient | Anonymous read-only `srvinfo` on TCP/445 |
| snmpget | Two system OIDs using `public` on UDP/161; no walk or configuration writes |

DVWA web presets normalize the configured entry to `/dvwa/` locally, avoiding a
directory-normalization redirect while retaining the original saved target URL.
Discovery includes nine classic DVWA module pages through ordinary GETs; no
payloads or form submissions are added. Reaching a module does not confirm its
vulnerability. HTTPX/Nuclei read at most 64 KiB per response, and Nikto adds a
200 ms pause between requests.

DVWA web tools verify their own session first; this does not establish sustained
access or complete module coverage. Host-service checks do not log into DVWA.
Nikto may run for 900 seconds, with a 930-second collection deadline. Tools share
bounded output, cancellation, and process-cleanup controls.

### Public domains and follow-up limits

Public profiles accept bare domains (default HTTPS) or HTTP/HTTPS root URLs on
ports 80/443. Credentials, arbitrary paths, custom ports, queries and fragments
are rejected. Before connection tools run, the app resolves the domain with
`nslookup` (system resolver only as a fallback), checks all answers, rejects
private/mixed destinations and pins one public address. Nmap, smbclient,
rpcclient and snmpget take that IP as their target. With web tools or OpenSSL
selected, it also checks whether the other standard port (80/443) answers on that
IP; if so, every web tool scans both the HTTP and HTTPS origins. Redirects remain
unfollowed. DNS and registration-only collection does not require an A/AAAA record.
All11 web tools use a restricted per-run local proxy to connect to that pinned
address while retaining the original domain URL, HTTP Host and HTTPS SNI.
It accepts only the saved origin; it is not a general browsing proxy. An upstream
connect that stalls is retried up to three times (1.5 s each) to the same pinned
address before any request byte is sent. Nmap and
OpenSSL use direct pinned connections. OpenSSL uses the HTTPS origin (saved or
alternate). SMB/RPC/SNMP results describe the IP, which may serve other domains. Public scans do not use DVWA credentials or module paths.
Path discovery uses eight fixed website paths, with no forms or payload fuzzing.
Nuclei uses only the four reviewed HTTP checks; Wapiti stays passive.
Some scanner libraries intrinsically omit TLS certificate verification; those
results retain an explicit warning in evidence and AI/report coverage. OpenSSL
independently verifies the domain certificate. Nikto's header plugin also has an
HTTP/1.0 probe without Host, which may reflect a default virtual host. Over HTTPS
it is tunneled unchanged; over HTTP the proxy forwards it with the saved Host
(`nikto_hostless_probes_sent_with_saved_host`), so that check cannot observe
default-virtual-host behavior there. A single
TLS handshake does not audit every protocol/cipher.
WHOIS looks up the registered domain: `http://php.testsparker.com/` queries
`testsparker.com`. A bundled offline Public Suffix List handles multi-label
suffixes such as `co.uk`; private hosting suffixes are excluded, so a DDNS or
hosted tenant shows its provider's registration. Results identify the queried
domain and flag parent registration metadata. Other tools keep the selected
hostname. Unknown suffixes retain the exact hostname. WHOIS may still be
unavailable, rate-limited or redacted. Install the current `requirements.lock`
before restarting; it includes the suffix parser and its bundled data.

The model can request cURL HEAD, `/robots.txt`, `/.well-known/security.txt`, DNS
SOA/CAA or DNSKEY, separate TLS 1.2/1.3 handshakes, header-only WhatWeb/Nikto,
HTTPX/Wget HEAD, detailed Nmap detection on the same reviewed web ports, or
(only after an IIS/ASP fingerprint) ffuf over 11 fixed IIS/ASP.NET paths such as
`web.config`, `trace.axd`, `elmah.axd` and `_vti_bin/`.
Metadata files are capped at
8 KiB; model excerpts are shorter and explicitly marked when truncated. No action
follows redirects, expands to a discovered host, accepts model-written syntax,
or runs a tool you did not select. Tools without a useful reviewed variant need
no repeat. Duplicate/unlisted actions are rejected. Planning failures retain the
initial evidence and continue to final analysis with a visible warning. A failed
earlier run still makes coverage partial after a successful follow-up.

Every model request is checked against its configured context window, including
instructions, output schema, tool definitions/results, repair/history and output
reserve. External provider profiles include **Dung lượng ngữ cảnh của mô hình (token)**;
the legacy equivalent is `OPENAI_CONTEXT_TOKENS`. The default is8192: enter the
actual model limit when different. Ollama keeps its configured context setting.
Compaction preserves complete citations, tool outcomes and essential limitations;
omissions stay explicit, and raw evidence remains saved. Requests whose mandatory
content cannot fit fail before dispatch. Budgeting uses a conservative UTF-8
bound rather than an exact model tokenizer, so small contexts may retain only
a limited evidence subset. The guarantee depends on an accurate configured
model window and the provider's chat/tokenization protocol.

The final report uses the combined evidence. **Phân tích lại** only regenerates
analysis; it never starts this collection loop or repeats any tool.

## Data, backups, and upgrades

| Local path | Contents |
|---|---|
| `.env` | Bootstrap configuration and credentials |
| `.env.ai` | Private saved target/general/provider overrides |
| `data/penchecker.sqlite3` | Scan history, evidence, attempts, and accepted reports |
| `reports/<scan-id>/r<revision>.html` | Versioned HTML archives |
| `reports/report.css` | Stylesheet for archived HTML |

`HISTORY_DB_PATH` and `REPORTS_DIR` can change the storage locations. Back up the
database with the backend stopped or through SQLite's online backup API. Back up
private configuration and the report archive separately; keep `report.css` with
the scan folders for offline viewing. These files may contain sensitive data.

All HTML reports use [one shared template](app/templates/report_archive.html).
Tool/model text is escaped. Failed scans may have no report; a failed analysis
retry preserves the prior accepted report. A manual CVE refresh updates its HTML
appendix even when that lookup overlaps an unsuccessful analysis retry.
**Xóa toàn bộ lịch sử** removes saved scans and managed HTML revisions while idle,
preserving configuration/profiles.

To upgrade a Git checkout, stop the backend, back up private data, and run:

```bash
git pull --ff-only origin dev
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m app
```

Preserve `.env`, `.env.ai`, the database, and reports. Recreate `.venv` when moving
the project to another machine; do not copy a virtual environment between systems.

## Limitations and troubleshooting

This is a lab assessment assistant with partial coverage. A port, banner, version,
share name, or empty result does not prove a vulnerability or prove safety.
AI validation checks structure, citations, scope, and specific unsupported claims;
human evidence review is still required. Small models may omit evidence or produce
weak prose. Real-provider quality and Windows acceptance remain separate from
offline verification. HTTP Basic access is intended for the isolated lab network.

| Symptom | Check |
|---|---|
| Invalid configuration at startup | Replace placeholders, use a unique app password of at least 16 characters, and verify the subnet/IP/URL rules. |
| Host browser cannot connect | Check the Kali Host-only address, selected port, VM network, and firewall. `/healthz` provides a basic availability check. |
| Tool is disabled | Read its version/flag/missing-binary reason; use the supported Kali package. |
| Web authentication fails | Verify DVWA availability and login values; inspect the stored tool warning. |
| Ollama times out | Check `ollama list`, service status, memory, model tag, and the analysis deadline. |
| External analysis fails | Check the HTTPS endpoint, key, model ID, JSON mode, and token-limit field. |
| No report or incomplete results | Inspect AI attempts and tool failures; retry analysis when eligible. An absent/denied SMB or SNMP service is incomplete coverage. |

## License notices

No project-wide license is declared. Bundled IBM Plex fonts include
[SIL OFL](app/static/fonts/OFL.txt); PDF fonts include the
[DejaVu notices](app/static/fonts/DejaVu-LICENSE.txt). Scanner tools, model runtimes,
and external providers have their own licenses and terms.
