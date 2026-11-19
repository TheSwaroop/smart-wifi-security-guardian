from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import sqlite3
import subprocess
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "guardian.db"

app = FastAPI(title="Smart Wi-Fi Security Guardian", version="1.1.0")
OLLAMA_URL = os.getenv("GUARDIAN_OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("GUARDIAN_AI_MODEL", "qwen2.5:3b")
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'review',
            notes TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            device_mac TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            network TEXT,
            devices_found INTEGER NOT NULL,
            method TEXT NOT NULL,
            note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            model TEXT NOT NULL,
            summary TEXT NOT NULL,
            agent_results TEXT NOT NULL
        );
        """)


init_db()


def add_event(severity: str, title: str, detail: str, mac: Optional[str] = None) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO events(created_at,severity,title,detail,device_mac) VALUES(?,?,?,?,?)",
            (now_iso(), severity, title, detail, mac),
        )


def local_network_info() -> dict:
    # Determine the interface used for the default route without sending traffic.
    local_ip = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("192.0.2.1", 80))  # documentation-only address; route lookup only
        local_ip = sock.getsockname()[0]
        sock.close()
    except OSError:
        pass

    interface = None
    ip_address = None
    netmask = None
    for name, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                if local_ip is None or addr.address == local_ip:
                    interface, ip_address, netmask = name, addr.address, addr.netmask
                    break
        if ip_address:
            break

    gateway = None
    try:
        for item in psutil.net_if_stats():
            pass
        # Windows and Unix expose default route differently; this is a best-effort gateway hint.
        command = ["route", "print", "-4"] if platform.system() == "Windows" else ["ip", "route", "show", "default"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        if platform.system() == "Windows":
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", result.stdout, re.M)
        else:
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            gateway = match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass

    network = None
    if ip_address and netmask:
        try:
            network = str(ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False))
        except ValueError:
            pass
    return {"interface": interface, "ip": ip_address, "netmask": netmask, "gateway": gateway, "network": network}


def hostname_for(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def discover_with_scapy(network: str) -> list[dict]:
    from scapy.all import ARP, Ether, srp  # type: ignore
    answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=3, retry=1, verbose=False)
    found = []
    for _, received in answers:
        mac = str(received.hwsrc).lower()
        ip = str(received.psrc)
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            found.append({"mac": mac, "ip": ip, "hostname": hostname_for(ip), "vendor": ""})
    return found


def discover_with_nmap(network: str) -> list[dict]:
    result = subprocess.run(["nmap", "-sn", "-oG", "-", network], capture_output=True, text=True, timeout=35)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Nmap scan failed")
    found = []
    current_ip = None
    for line in result.stdout.splitlines():
        host = re.search(r"Host: ([0-9.]+)", line)
        mac = re.search(r"MAC: ([0-9A-Fa-f:]{17})", line)
        if host:
            current_ip = host.group(1)
        if current_ip and mac:
            found.append({"mac": mac.group(1).lower(), "ip": current_ip, "hostname": hostname_for(current_ip), "vendor": ""})
    return found


def discover_from_arp_cache() -> list[dict]:
    command = ["arp", "-a"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=5)
    found = []
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
        if not match:
            continue
        ip, raw_mac = match.groups()
        mac = raw_mac.replace("-", ":").lower()
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
            continue
        found.append({"mac": mac, "ip": ip, "hostname": hostname_for(ip), "vendor": ""})
    return found


class ScanRequest(BaseModel):
    confirm_authorized: bool = False


class DeviceUpdate(BaseModel):
    status: str
    notes: Optional[str] = ""


@app.get("/")
def home():
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/status")
def status():
    info = local_network_info()
    with db() as conn:
        device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        review_count = conn.execute("SELECT COUNT(*) FROM devices WHERE status='review'").fetchone()[0]
        event_count = conn.execute("SELECT COUNT(*) FROM events WHERE severity IN ('high','medium')").fetchone()[0]
        last_scan = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {**info, "device_count": device_count, "review_count": review_count, "alert_count": event_count,
            "last_scan": dict(last_scan) if last_scan else None, "platform": platform.system()}


@app.get("/api/devices")
def devices(q: str = ""):
    with db() as conn:
        rows = conn.execute("""SELECT * FROM devices WHERE mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ?
                               ORDER BY CASE status WHEN 'review' THEN 0 ELSE 1 END, last_seen DESC""",
                            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/scan")
def scan(request: ScanRequest):
    if not request.confirm_authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to scan this network.")
    info = local_network_info()
    network = info.get("network")
    if not network:
        raise HTTPException(400, "Could not determine the active local network. Connect to Wi-Fi and try again.")
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise HTTPException(400, "The detected local network is invalid.")
    if parsed.version != 4 or parsed.num_addresses > 1024:
        raise HTTPException(400, "For safety, this MVP only scans local IPv4 networks with up to 1,024 addresses.")

    found: list[dict] = []
    method = "ARP cache"
    notes = ""
    try:
        found = discover_with_scapy(network)
        method = "Scapy ARP discovery"
    except PermissionError:
        notes = "Scapy needs administrator/root privileges; trying Nmap or the local ARP cache."
    except ImportError:
        notes = "Scapy is not installed; trying Nmap or the local ARP cache."
    except Exception as exc:
        notes = f"ARP discovery unavailable ({type(exc).__name__}); trying Nmap or the local ARP cache."

    if not found:
        try:
            found = discover_with_nmap(network)
            method = "Nmap ping scan"
        except (FileNotFoundError, subprocess.TimeoutExpired, RuntimeError) as exc:
            notes = (notes + " " if notes else "") + f"Nmap unavailable ({type(exc).__name__}); using the existing ARP cache."
            try:
                found = discover_from_arp_cache()
                method = "Operating-system ARP cache (partial results)"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                found = []

    # Restrict results to the active local subnet.
    found = [item for item in found if ipaddress.ip_address(item["ip"]) in parsed]
    unique = {item["mac"]: item for item in found}
    found = list(unique.values())
    timestamp = now_iso()
    new_count = 0
    with db() as conn:
        for item in found:
            previous = conn.execute("SELECT status, ip FROM devices WHERE mac=?", (item["mac"],)).fetchone()
            if previous is None:
                status_value = "review"
                new_count += 1
                conn.execute("""INSERT INTO devices(mac,ip,hostname,vendor,first_seen,last_seen,status)
                                VALUES(?,?,?,?,?,?,?)""",
                             (item["mac"], item["ip"], item["hostname"], item["vendor"], timestamp, timestamp, status_value))
                conn.execute("INSERT INTO events(created_at,severity,title,detail,device_mac) VALUES(?,?,?,?,?)",
                             (timestamp, "medium", "New device discovered", f"A previously unseen device responded at {item['ip']}. Verify whether you recognize it.", item["mac"]))
            else:
                conn.execute("UPDATE devices SET ip=?, hostname=CASE WHEN ?!='' THEN ? ELSE hostname END, last_seen=? WHERE mac=?",
                             (item["ip"], item["hostname"], item["hostname"], timestamp, item["mac"]))
        conn.execute("INSERT INTO scans(created_at,network,devices_found,method,note) VALUES(?,?,?,?,?)",
                     (timestamp, network, len(found), method, notes))
    return {"network": network, "found": len(found), "new_devices": new_count, "method": method,
            "note": notes, "scanned_at": timestamp,
            "message": "Scan completed. Results depend on device visibility and the discovery method."}


@app.patch("/api/devices/{mac}")
def update_device(mac: str, update: DeviceUpdate):
    if update.status not in {"known", "review", "ignored"}:
        raise HTTPException(400, "Status must be known, review, or ignored.")
    with db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac.lower(),)).fetchone()
        if row is None:
            raise HTTPException(404, "Device not found.")
        conn.execute("UPDATE devices SET status=?, notes=? WHERE mac=?", (update.status, update.notes or "", mac.lower()))
    add_event("low", "Device inventory updated", f"{row['ip']} was marked as {update.status}.", mac.lower())
    return {"ok": True}


@app.get("/api/events")
def events(limit: int = 30):
    limit = max(1, min(limit, 100))
    with db() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/scans")
def scans(limit: int = 10):
    with db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(limit, 50)),)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/audit")
def audit():
    info = local_network_info()
    return {
        "network": info,
        "checks": [
            {"name": "Wi-Fi encryption", "status": "manual", "detail": "Check the router administration page. Prefer WPA3-Personal, or WPA2-AES if WPA3 is unavailable."},
            {"name": "WPS", "status": "manual", "detail": "Disable WPS if it is not required."},
            {"name": "Router administrator password", "status": "manual", "detail": "Use a unique password; do not keep default administrator credentials."},
            {"name": "Router firmware", "status": "manual", "detail": "Check the router vendor's official update page and install supported security updates."},
            {"name": "Guest network", "status": "manual", "detail": "Use a separate guest network for visitors and untrusted IoT devices where supported."},
        ],
        "notice": "A computer connected to Wi-Fi cannot reliably read every router setting. These checks require confirmation in the router's own administration interface."
    }


@app.get("/api/export")
def export_data():
    with db() as conn:
        payload = {
            "exported_at": now_iso(),
            "devices": [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")],
            "events": [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC")],
            "scans": [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY id DESC")],
        }
    return payload


# ---- Optional free, local AI (Ollama) -------------------------------------
def ollama_request(messages: list[dict], timeout: int = 150) -> str:
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 450},
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA_URL.rstrip('/')}/api/chat", data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("message", {}).get("content", "").strip()
    except urllib.error.URLError as exc:
        raise RuntimeError("Ollama is not reachable. Install/start Ollama and download the configured model.") from exc
    except (TimeoutError, json.JSONDecodeError, KeyError) as exc:
        raise RuntimeError(f"Local AI request failed: {type(exc).__name__}") from exc


def ai_evidence_snapshot() -> dict:
    with db() as conn:
        devices_rows = conn.execute(
            "SELECT mac,ip,hostname,vendor,first_seen,last_seen,status,notes FROM devices ORDER BY last_seen DESC LIMIT 80"
        ).fetchall()
        event_rows = conn.execute(
            "SELECT created_at,severity,title,detail,device_mac FROM events ORDER BY id DESC LIMIT 25"
        ).fetchall()
        scan_row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "network": local_network_info(),
        "devices": [dict(row) for row in devices_rows],
        "recent_events": [dict(row) for row in event_rows],
        "latest_scan": dict(scan_row) if scan_row else None,
        "important_limitations": [
            "A newly observed device is not proof of malicious activity.",
            "MAC randomization can make a familiar device appear new.",
            "Network scans only show devices visible to this computer.",
            "No packet capture or router configuration access is included in this analysis."
        ]
    }


@app.get("/api/ai/status")
def ai_status():
    try:
        request = urllib.request.Request(f"{OLLAMA_URL.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
        models = [item.get("name", "") for item in data.get("models", [])]
        installed = any(name == OLLAMA_MODEL or name.startswith(OLLAMA_MODEL + ":") for name in models)
        return {"available": True, "model_installed": installed, "model": OLLAMA_MODEL,
                "provider": "Ollama (local)", "models": models}
    except Exception:
        return {"available": False, "model_installed": False, "model": OLLAMA_MODEL,
                "provider": "Ollama (local)", "models": []}


@app.post("/api/ai/investigate")
def ai_investigate():
    status_info = ai_status()
    if not status_info["available"]:
        raise HTTPException(503, "Local AI is not running. Install Ollama, start it, and try again.")
    if not status_info["model_installed"]:
        raise HTTPException(503, f"The {OLLAMA_MODEL} model is not installed. Run: ollama pull {OLLAMA_MODEL}")

    evidence = ai_evidence_snapshot()
    evidence_text = json.dumps(evidence, ensure_ascii=False, indent=2)
    agents = [
        ("Device Context Analyst", "Classify the observed inventory conservatively. Identify known, review and ignored device counts, repeated identifiers, missing data, and plausible benign explanations. Do not guess device identity from an IP address."),
        ("Threat Triage Analyst", "Review recent events and inventory for evidence-backed concerns. Separate observed facts from hypotheses. A newly seen MAC alone is not a threat. Do not invent attacks, packet activity, or malicious intent."),
        ("Wi-Fi Security Advisor", "Review the available evidence and explain what cannot be verified from a normal client device. Give practical router-hardening checks, clearly marking anything that needs manual verification."),
        ("Incident Response Advisor", "Create a prioritized, safe response checklist for the network owner. Never recommend attacking, scanning third-party systems, or blocking a device without owner confirmation and supported router integration.")
    ]
    results = []
    try:
        for name, task in agents:
            content = ollama_request([
                {"role": "system", "content": "You are a cautious home-network security analyst. Use only the supplied evidence. Be concise, factual, and understandable. Explicitly state uncertainty. Never claim a device is malicious without direct evidence."},
                {"role": "user", "content": f"Role: {name}\nTask: {task}\n\nObserved evidence (JSON):\n{evidence_text}\n\nReturn: Findings, Evidence, Limitations, Recommended next steps."}
            ])
            results.append({"agent": name, "analysis": content or "No analysis returned."})
        summary = ollama_request([
            {"role": "system", "content": "You are the lead security analyst. Synthesize specialist findings into a short report. Never upgrade a hypothesis into a fact. If evidence is insufficient, say so. Include overall assessment, confirmed observations, priority actions, and limitations."},
            {"role": "user", "content": "Specialist findings:\n" + json.dumps(results, ensure_ascii=False) + "\n\nOriginal evidence:\n" + evidence_text}
        ])
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc

    created_at = now_iso()
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO ai_reports(created_at,model,summary,agent_results) VALUES(?,?,?,?)",
            (created_at, OLLAMA_MODEL, summary, json.dumps(results, ensure_ascii=False))
        )
        report_id = cursor.lastrowid
    return {"id": report_id, "created_at": created_at, "model": OLLAMA_MODEL,
            "provider": "Ollama local", "summary": summary, "agents": results,
            "evidence_scope": {"devices_included": len(evidence["devices"]),
                               "events_included": len(evidence["recent_events"]),
                               "latest_scan": evidence["latest_scan"]}}


@app.get("/api/ai/reports")
def ai_reports(limit: int = 10):
    with db() as conn:
        rows = conn.execute("SELECT * FROM ai_reports ORDER BY id DESC LIMIT ?", (max(1, min(limit, 30)),)).fetchall()
    return [{"id": row["id"], "created_at": row["created_at"], "model": row["model"],
             "summary": row["summary"], "agents": json.loads(row["agent_results"])} for row in rows]
