# Owl Eyes (PenChecker)

A browser-based security assessment assistant for an isolated Kali Linux and
Metasploitable2/DVWA lab. Select scanners, collect evidence, review AI analysis,
and export a report from one Vietnamese interface.

The application uses FastAPI, native JavaScript modules, and local CSS/fonts.
There is no frontend build step or Node.js requirement. The default branch is
`dev`.

## What it does

- **Scan workspace:** Dashboard, Scan, and Settings with light/dark themes,
  numbered setup, responsive navigation, and keyboard controls.
- **Ten scanners:** Nmap, cURL, WhatWeb, ffuf, Nikto, Nuclei, HTTPX Toolkit,
  Wafw00f, Gobuster, and Wapiti, using fixed server-owned presets.
- **Authenticated collection:** each web tool obtains its own verified DVWA
  session. Tool outcomes, partial failures, evidence, and raw output remain visible.
- **AI analysis:** local Ollama or saved OpenAI-compatible provider profiles.
  Findings cite collected evidence; analysis can be retried without another scan.
- **Saved history:** SQLite preserves scan results, evidence, reports, and attempts
  across application restarts.
- **Reports and PDF:** structured findings, remediation, scope, coverage limits,
  observations, and cited excerpts, with Vietnamese fonts in the exported PDF.
- **CVE lookup:** correlate saved evidence with NVD records. Candidates remain
  separate from confirmed findings and do not change the AI risk assessment.

## Requirements

- Kali Linux, Python **3.11+**, and virtual-environment support.
- A Metasploitable2 VM with DVWA on an isolated Host-only network.
- Scanner packages installed on Kali; unavailable tools are disabled in the UI.
- At least one configured AI provider for analysis. Install Ollama and a model
  separately when using local analysis.

The current application allowlist is **192.168.146.0/24**. Kali and the target
must have different addresses; `.0`, `.1`, and `.255` are excluded. The target URL
must use HTTP port 80 and `/dvwa` or `/dvwa/`. Verify VM identity, addresses, and
routing before configuration. The target is fixed by the server configuration.

## Install

Clone the default branch:

```bash
git clone --branch dev https://github.com/Dathless/owl-eyes.git
cd owl-eyes
```

Install the baseline scanners and Python environment support:

```bash
sudo apt install python3-venv nmap curl whatweb ffuf nikto
```

Optional scanner packages:

```bash
sudo apt install nuclei httpx-toolkit wafw00f gobuster wapiti
```

Use the Kali **HTTPX Toolkit** package, which is different from Python's HTTPX
client. The current Nikto adapter expects Kali Nikto **2.6.0**. Capability checks
in the application report missing binaries, unsupported versions, or flags.

Create the environment and install the pinned runtime dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
```

On a fresh installation, create the private configuration:

```bash
install -m 600 .env.example .env
```

Keep an existing `.env` when upgrading. Edit the new file before starting the app.

## Configure

Set these values in `.env`, replacing the placeholders with verified lab addresses:

```dotenv
APP_HOST=<KALI_HOST_ONLY_IP>
APP_PORT=8000
APP_USERNAME=labadmin
APP_PASSWORD=<UNIQUE_PASSWORD_AT_LEAST_16_CHARACTERS>
LAB_TARGET_IP=<METASPLOITABLE_HOST_ONLY_IP>
LAB_TARGET_URL=http://<METASPLOITABLE_HOST_ONLY_IP>/dvwa/
DVWA_USERNAME=admin
DVWA_PASSWORD=password
```

`APP_HOST` and `LAB_TARGET_IP` must satisfy the allowlist above. The application
password is separate from the DVWA login. The shown DVWA credentials are the
lab defaults; use the credentials configured on your target. To generate an
application password locally:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(24))'
```

[.env.example](.env.example) documents the remaining settings. Never commit `.env`,
`.env.ai`, API keys, session cookies, scan databases, or generated reports.

### Local Ollama

Install and start Ollama separately, then pull a model suitable for your hardware.
For example:

```bash
ollama pull qwen2.5:3b-instruct-q4_K_M
```

Set the installed tag in `.env`:

```dotenv
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:3b-instruct-q4_K_M
OLLAMA_CONTEXT_TOKENS=8192
OLLAMA_NUM_THREADS=4
```

CPU-only analysis may take several minutes. Set `AI_TOTAL_TIMEOUT_SECONDS` for
your hardware; its default is 180 seconds. Check available memory before raising
the context allocation. The app does not download models or switch providers
when a request fails.

### External AI providers

After opening the app, go to **Settings → Provider AI → + Thêm nhà cung cấp**.
Enter a name, HTTPS URL, API key, model ID, and optional model display name.
Save multiple profiles and select one on Dashboard or when retrying analysis.

HTTPS origins, custom base URLs, and full `/chat/completions` endpoints are
supported. Match the advanced JSON-output and token-limit options to the provider.
Legacy `OPENAI_*` settings in `.env` also remain supported.

Keys are write-only; leaving a key blank while editing retains it. Changes apply
while the backend is idle and persist privately in `.env.ai`. Saving settings
does not call the provider. External analysis sends scrubbed evidence, including
lab addresses and service banners, to the selected host shown by the UI.

## Run

Run as a normal Kali user from the repository root:

```bash
source .venv/bin/activate
python -m app
```

Open `http://<APP_HOST>:8000/` from the host browser and sign in with
`APP_USERNAME` and `APP_PASSWORD`. If you changed `APP_PORT`, use that port.
The backend starts one Uvicorn worker without reload. Restart it after changing
application code or server settings; AI settings saved in the UI apply while idle.

### Scan and review

1. On **Dashboard**, check availability, select tools, and choose an AI provider.
   Expand **Thêm công cụ quét** to add optional scanners.
2. Choose **Bắt đầu scan**. Collection runs with up to three scanner processes;
   only one scan or analysis operation is admitted at a time.
3. On **Scan**, inspect **Report**, **Observations**, **Raw**, and **AI attempts**.
   Evidence chips open the original excerpt and source location.
4. Use **Dừng scan** or **Dừng tạo báo cáo** to cancel active work. Use
   **Phân tích lại** to analyze saved evidence without running scanners again.
5. Choose **Xuất báo cáo PDF** when a report exists. On a finished scan,
   **Tra cứu CVE** looks up NVD candidates from saved evidence.

The collection timer stops when tools finish; AI generation has a separate
status. Closing the browser does not cancel a scan. Reloading can recover the
current view, and Dashboard history opens saved results after a restart.

### Data and scope

History is stored in `data/penchecker.sqlite3` by default; `HISTORY_DB_PATH` can
change the location. Back up SQLite with the backend stopped or SQLite's online
backup API. Preserve `.env.ai` separately if keeping saved provider profiles.

AI/provider settings are editable. Target, scanner commands, network, and server
settings are read-only in the browser. AI analyzes evidence and never constructs
or executes scanner commands. Nmap checks target TCP port 80; the web tools use
bounded presets. Nikto may take up to 600 seconds, with a 630-second runner limit.

## Limits to understand

- **Review every finding against its evidence.** Validation checks structure,
  citations, scope, and certain unsupported claims; it does not prove every claim.
- **Coverage is partial.** A successful login does not establish full module
  coverage or session continuity. Timeouts and omitted evidence stay disclosed.
- **Small local models see limited input.** Ollama prioritizes complete scanner
  signals within its context budget, but may omit most of a large collection.
  Generated text can be English and remediation advice can be generic.
- **CVE candidates need verification.** A banner, version, or CVE reference does
  not establish that the target is affected.
- **Keep the deployment isolated.** Authentication uses HTTP Basic on the lab
  network. This setup is intended for the configured personal lab.

## Troubleshooting

| Symptom | Check |
|---|---|
| App exits with invalid configuration | Replace placeholders, use a unique password of at least 16 characters, and verify the address/URL rules. |
| Host browser cannot connect | Check the Kali Host-only address, port, VM adapter assignments, and firewall. |
| A tool is disabled | Read its capability reason and install the supported Kali binary/version. |
| A web tool reports authentication failure | Check DVWA credentials, target availability, and its verification warning. |
| Ollama fails or times out | Check `ollama list`, service availability, model tag, memory, and the configured analysis deadline. |
| External analysis fails | Check the saved HTTPS endpoint, model ID, key, and supported JSON/token options. |
| Report is unavailable | Inspect **AI attempts**, evidence, and partial failures; retry analysis when eligible. |

## License notices

No project-wide license is currently declared. Bundled IBM Plex fonts include
[SIL OFL](app/static/fonts/OFL.txt); PDF fonts include the
[DejaVu notices](app/static/fonts/DejaVu-LICENSE.txt). Scanner tools and AI
runtimes/providers have their own licenses and terms.
