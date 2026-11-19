# Smart Wi-Fi Security Guardian

A local-first Wi-Fi device inventory, security review and free local multi-agent AI analysis MVP. It is designed as a practical starting point for monitoring a home or small-office network that you own or are authorized to assess.

## What is implemented

- Detects the computer's active local IPv4 interface, subnet and (where available) default gateway.
- Discovers responding devices on the local subnet using Scapy ARP discovery, with Nmap and operating-system ARP-cache fallbacks.
- Stores observed devices, first/last-seen timestamps, review status and security events in a local SQLite database.
- Flags newly observed MAC addresses for user review. A new device is **not** automatically labelled malicious.
- Lets you approve, review or ignore devices.
- Provides a router hardening checklist, investigation workflow, scan history and JSON report export.
- Includes four local AI specialist agents plus a lead analyst, powered by Ollama and a locally installed Qwen model.
- AI analysis runs on your own computer; no paid API key and no cloud AI upload are required.
- The application still works for scanning and inventory when local AI is not installed.

## Important limitations

This is an MVP, not a complete intrusion detection system. Network discovery only sees devices that respond and are visible from the computer running the scan. Wi-Fi client isolation, firewalls, sleeping devices, VLANs and operating-system permissions can hide devices. MAC randomization can make a familiar phone appear as a new device.

A generic laptop cannot reliably read every router setting or block another device from Wi-Fi. The security audit is therefore a guided manual checklist. Router-level blocking and configuration inspection require a supported router API or administrator integration, which is not included in this first version.

The scan is limited to the active local IPv4 subnet and at most 1,024 addresses. Only scan networks you own or have explicit permission to assess. Do not use this tool to scan public, campus, workplace or other third-party networks without authorization.

## Enable free local AI (recommended)

The AI features use [Ollama](https://ollama.com/) to run a model locally. This is free to use; model inference runs on your computer and does not require an API key. A computer with sufficient memory is recommended (the Qwen 2.5 3B model is a relatively small starting point).

1. Install Ollama for Windows from https://ollama.com/download/windows.
2. Open a new terminal and download the model:

   ```powershell
   ollama pull qwen2.5:3b
   ```

3. Make sure Ollama is running (the Ollama app normally starts its local service automatically). Check with:

   ```powershell
   ollama list
   ```

4. Start this project using the normal steps below.
5. Open **Investigation center**. The status should say **Local AI ready**. Click **Run AI investigation**.

The investigation runs four separate specialist prompts (device context, threat triage, Wi-Fi security advice, and incident response), followed by a lead-analyst synthesis. It uses the device inventory and recent event records saved by this app. On a typical laptop it may take a few minutes.

Optional configuration:

- `GUARDIAN_AI_MODEL` changes the Ollama model name (default: `qwen2.5:3b`).
- `GUARDIAN_OLLAMA_URL` changes the local Ollama base URL (default: `http://127.0.0.1:11434`).

If Ollama is not installed or running, network discovery and inventory continue to work; only AI investigation is unavailable. AI output is advisory and can be wrong. It does not prove a device is malicious and does not automatically block devices.

## Requirements

- Windows 10/11, macOS or Linux
- Python 3.10 or newer (Python 3.12 recommended)
- A Wi-Fi or Ethernet connection
- For best discovery results: run with administrator/root privileges and install Npcap on Windows when using Scapy. Nmap is an optional fallback.

## Run on Windows (VS Code)

1. Extract the ZIP file into a folder, for example `C:\Projects\smart-wifi-security-guardian`.
2. Open VS Code → **File → Open Folder** → select that folder.
3. Open the VS Code terminal (**Terminal → New Terminal**).
4. Check Python is available:

   ```powershell
   py --version
   ```

5. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt in VS Code and run:

   ```cmd
   .venv\Scripts\activate.bat
   ```

6. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

7. Start the server:

   ```powershell
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```

8. Open this address in your browser:

   **http://127.0.0.1:8000**

9. Connect to the Wi-Fi network you own/administer, click **Scan local network**, confirm authorization, and start the scan.

### Optional: improve Windows device discovery

- Install Npcap from its official website if you want Scapy's active ARP scan to work.
- Run VS Code as Administrator when performing an authorized active ARP scan.
- Alternatively install Nmap and make sure `nmap` is available in PATH. The app will try Nmap if Scapy discovery is unavailable.
- If neither tool can perform an active scan, the app falls back to the operating system's ARP cache. That result may be incomplete.

## Run on macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

For Scapy ARP discovery, run the server with the required elevated privileges. Prefer using a dedicated virtual environment and only elevate the scan process when necessary.

## Stop the application

Return to the terminal running Uvicorn and press **Ctrl + C**.

## Data storage

The app creates `data/guardian.db` on first run. This database contains device inventory and event history. It is local to this project folder and is excluded from Git by `.gitignore`.

## Project structure

```text
smart-wifi-security-guardian/
├── backend/
│   ├── __init__.py
│   └── main.py
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── data/                  # created automatically; local database
├── requirements.txt
├── run_windows.bat
├── run_mac_linux.sh
├── .gitignore
└── README.md
```

## API endpoints

- `GET /api/status` — local network and application summary
- `GET /api/devices` — device inventory; supports `?q=` search
- `POST /api/scan` — scan the active local subnet (requires `{"confirm_authorized": true}`)
- `PATCH /api/devices/{mac}` — set status to `known`, `review` or `ignored`
- `GET /api/events` — security event history
- `GET /api/scans` — scan history
- `GET /api/audit` — manual router security checklist
- `GET /api/export` — export data as JSON
- `GET /api/ai/status` — check local Ollama/model availability
- `POST /api/ai/investigate` — run the local multi-agent AI investigation
- `GET /api/ai/reports` — retrieve saved AI reports

Interactive API documentation is available at **http://127.0.0.1:8000/docs** while the server is running.

## GitHub

After testing locally, initialize and push the project:

```bash
git init
git add .
git commit -m "Initial Smart Wi-Fi Security Guardian MVP"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/smart-wifi-security-guardian.git
git push -u origin main
```

Create an empty repository on GitHub first and replace `YOUR-USERNAME` with your GitHub username. Never commit `.venv`, `.env`, personal router details, or the local `data/guardian.db` file.
