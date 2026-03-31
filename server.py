#!/usr/bin/env python3
"""
NetAdmin Portal - Backend Server
Performs network discovery, device health checks, and serves the dashboard.
Requires: flask, python3-nmap (or nmap), arp-scan, net-tools
"""

import os
import re
import json
import time
import socket
import struct
import threading
import subprocess
import ipaddress
from datetime import datetime
from flask import Flask, jsonify, send_from_directory, request

app = Flask(__name__, static_folder='static')

# ─── State ────────────────────────────────────────────────────────────────────
devices_cache = {}
scan_status = {"running": False, "last_scan": None, "progress": 0}
device_lock = threading.Lock()

# ─── Utilities ────────────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=30):
    """Run a shell command and return stdout, stderr, returncode."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1

def get_local_network():
    """Determine the local network CIDR (e.g. 192.168.1.0/24)."""
    out, _, rc = run_cmd("ip route show default")
    if rc == 0:
        for line in out.splitlines():
            if "default" in line:
                parts = line.split()
                if "dev" in parts:
                    iface = parts[parts.index("dev") + 1]
                    out2, _, _ = run_cmd(f"ip -o -4 addr show dev {iface}")
                    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', out2)
                    if m:
                        net = ipaddress.IPv4Interface(m.group(1)).network
                        return str(net), iface
    # fallback
    out, _, _ = run_cmd("ip -o -4 addr show scope global")
    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', out)
    if m:
        net = ipaddress.IPv4Interface(m.group(1)).network
        return str(net), "unknown"
    return "192.168.1.0/24", "eth0"

def get_local_ip():
    """Get the local machine's IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_hostname(ip):
    """Try to reverse-resolve a hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_mac_vendor(mac):
    """Look up MAC vendor from the local OUI database or return unknown."""
    if not mac or mac == "unknown":
        return "Unknown"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    oui_file = "/usr/share/arp-scan/ieee-oui.txt"
    if not os.path.exists(oui_file):
        oui_file = "/var/lib/ieee-data/oui.txt"
    if os.path.exists(oui_file):
        try:
            with open(oui_file, "r", errors="ignore") as f:
                for line in f:
                    if line.startswith(prefix[:6]):
                        return line.split("\t", 2)[-1].strip()[:40]
        except:
            pass
    # Try nmap's mac-vendor lookup
    out, _, rc = run_cmd(f"nmap --script-help mac-prefix 2>/dev/null | head -1")
    return "Unknown Vendor"

def ping_host(ip, count=2, timeout=1):
    """Return True if host responds to ping."""
    out, _, rc = run_cmd(f"ping -c {count} -W {timeout} {ip}")
    return rc == 0

def get_open_ports(ip, ports="22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443"):
    """Quick TCP connect scan on common ports using nmap."""
    out, _, rc = run_cmd(f"nmap -T4 --open -p {ports} {ip} 2>/dev/null", timeout=20)
    open_ports = []
    for line in out.splitlines():
        m = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if m:
            open_ports.append({"port": int(m.group(1)), "service": m.group(2)})
    return open_ports

def guess_device_type(ports, hostname, vendor):
    """Heuristic device type detection."""
    services = [p["service"] for p in ports]
    port_nums = [p["port"] for p in ports]
    v = (vendor or "").lower()
    h = (hostname or "").lower()

    if 3389 in port_nums: return "Windows PC"
    if 22 in port_nums and (445 in port_nums or 139 in port_nums): return "Linux Server"
    if 80 in port_nums or 443 in port_nums:
        if any(x in v for x in ["cisco", "ubiquiti", "netgear", "tp-link", "asus", "linksys", "dlink", "d-link"]):
            return "Router/Switch"
        if any(x in h for x in ["router", "gateway", "switch", "ap", "access"]):
            return "Router/Switch"
        if any(x in v for x in ["samsung", "lg", "sony", "vizio", "roku", "amazon", "apple"]):
            return "Smart TV/Media"
        return "Web Server"
    if 22 in port_nums: return "Linux/SSH Device"
    if 53 in port_nums: return "DNS Server"
    if 445 in port_nums or 139 in port_nums: return "Windows/Samba"
    if any(x in v for x in ["apple", "hon hai", "foxconn"]):
        return "Apple Device"
    if any(x in v for x in ["samsung", "lg", "sony"]):
        return "Mobile/IoT"
    if any(x in v for x in ["raspberry", "arduino"]):
        return "SBC/IoT"
    if any(x in v for x in ["cisco", "ubiquiti", "netgear", "tp-link"]):
        return "Network Device"
    return "Unknown Device"

def get_os_guess(ip):
    """Try nmap OS detection (requires sudo for best results)."""
    # Try without sudo first (TTL-based)
    out, _, rc = run_cmd(f"nmap -O --osscan-guess {ip} 2>/dev/null", timeout=30)
    if rc == 0:
        for line in out.splitlines():
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                return line.split(":", 1)[-1].strip().split(",")[0][:60]
    # TTL-based fallback
    out, _, _ = run_cmd(f"ping -c 1 -W 1 {ip}")
    m = re.search(r'ttl=(\d+)', out, re.I)
    if m:
        ttl = int(m.group(1))
        if ttl <= 64: return "Linux/Unix (TTL≤64)"
        if ttl <= 128: return "Windows (TTL≤128)"
        if ttl <= 255: return "Cisco/Network OS"
    return "Unknown OS"

def arp_scan_network(network):
    """Discover devices using arp-scan or fallback to nmap -sn."""
    devices = {}

    # Try arp-scan first (fastest)
    out, err, rc = run_cmd(f"arp-scan --localnet 2>/dev/null || arp-scan {network} 2>/dev/null", timeout=60)
    if rc == 0 and out:
        for line in out.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:]{17})\s+(.*)', line)
            if m:
                ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
                devices[ip] = {"ip": ip, "mac": mac, "vendor": vendor[:50]}
        if devices:
            return devices

    # Fallback: nmap -sn (ping scan)
    out, _, rc = run_cmd(f"nmap -sn {network} 2>/dev/null", timeout=120)
    if rc == 0:
        current_ip = None
        for line in out.splitlines():
            ip_m = re.search(r'Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?', line)
            if ip_m:
                current_ip = ip_m.group(1)
                devices[current_ip] = {"ip": current_ip, "mac": "unknown", "vendor": "Unknown"}
            mac_m = re.search(r'MAC Address: ([\dA-Fa-f:]{17})\s+\((.*?)\)', line)
            if mac_m and current_ip:
                devices[current_ip]["mac"] = mac_m.group(1).lower()
                devices[current_ip]["vendor"] = mac_m.group(2)[:50]
        if devices:
            return devices

    # Last resort: parse local ARP table
    out, _, _ = run_cmd("arp -n")
    for line in out.splitlines():
        m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\da-fA-F:]{17})', line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            devices[ip] = {"ip": ip, "mac": mac, "vendor": get_mac_vendor(mac)}

    return devices

def enrich_device(ip, base_info):
    """Enrich a device entry with hostname, ports, OS, type."""
    info = dict(base_info)
    info["online"] = ping_host(ip)
    info["hostname"] = get_hostname(ip) or ip
    info["last_seen"] = datetime.now().isoformat()

    if info["online"]:
        info["open_ports"] = get_open_ports(ip)
        info["os_guess"] = get_os_guess(ip)
        info["device_type"] = guess_device_type(
            info["open_ports"], info["hostname"], info.get("vendor", "")
        )
        info["latency_ms"] = measure_latency(ip)
    else:
        info["open_ports"] = []
        info["os_guess"] = "Unreachable"
        info["device_type"] = base_info.get("device_type", "Unknown")
        info["latency_ms"] = None

    info["vendor"] = base_info.get("vendor") or get_mac_vendor(info.get("mac", ""))
    return info

def measure_latency(ip):
    """Measure average ping latency in ms."""
    out, _, rc = run_cmd(f"ping -c 3 -W 1 {ip}")
    if rc == 0:
        m = re.search(r'rtt min/avg/max.*?= [\d.]+/([\d.]+)/', out)
        if m:
            return float(m.group(1))
    return None

def full_scan():
    """Run a full network discovery scan."""
    global scan_status
    scan_status["running"] = True
    scan_status["progress"] = 5

    network, iface = get_local_network()
    local_ip = get_local_ip()

    scan_status["progress"] = 10
    raw_devices = arp_scan_network(network)

    # Always include self
    if local_ip not in raw_devices:
        raw_devices[local_ip] = {"ip": local_ip, "mac": get_self_mac(iface), "vendor": "This Host"}

    total = len(raw_devices)
    scan_status["progress"] = 20

    enriched = {}
    for i, (ip, base) in enumerate(raw_devices.items()):
        progress = 20 + int((i / total) * 75)
        scan_status["progress"] = progress
        enriched[ip] = enrich_device(ip, base)
        # Mark self
        if ip == local_ip:
            enriched[ip]["is_self"] = True
            enriched[ip]["vendor"] = "This Host"

    with device_lock:
        devices_cache.clear()
        devices_cache.update(enriched)

    scan_status["running"] = False
    scan_status["last_scan"] = datetime.now().isoformat()
    scan_status["progress"] = 100
    scan_status["network"] = network

def get_self_mac(iface):
    """Get this machine's MAC address."""
    out, _, _ = run_cmd(f"ip link show {iface}")
    m = re.search(r'link/ether ([\da-f:]+)', out)
    return m.group(1) if m else "00:00:00:00:00:00"

def quick_health_check():
    """Ping all known devices to update online status."""
    with device_lock:
        ips = list(devices_cache.keys())

    def check(ip):
        online = ping_host(ip, count=1, timeout=1)
        lat = measure_latency(ip) if online else None
        with device_lock:
            if ip in devices_cache:
                devices_cache[ip]["online"] = online
                devices_cache[ip]["latency_ms"] = lat
                devices_cache[ip]["last_seen"] = datetime.now().isoformat() if online else devices_cache[ip].get("last_seen")

    threads = [threading.Thread(target=check, args=(ip,)) for ip in ips]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if scan_status["running"]:
        return jsonify({"status": "already_running"}), 409
    t = threading.Thread(target=full_scan, daemon=True)
    t.start()
    return jsonify({"status": "started"})

@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scan_status)

@app.route("/api/devices")
def api_devices():
    with device_lock:
        data = list(devices_cache.values())
    return jsonify(data)

@app.route("/api/devices/<ip>")
def api_device_detail(ip):
    with device_lock:
        device = devices_cache.get(ip)
    if not device:
        return jsonify({"error": "not found"}), 404
    # Fresh detail scan
    detail = enrich_device(ip, device)
    with device_lock:
        devices_cache[ip] = detail
    return jsonify(detail)

@app.route("/api/health", methods=["POST"])
def api_health():
    t = threading.Thread(target=quick_health_check, daemon=True)
    t.start()
    return jsonify({"status": "checking"})

@app.route("/api/network")
def api_network():
    network, iface = get_local_network()
    local_ip = get_local_ip()
    return jsonify({
        "network": network,
        "interface": iface,
        "local_ip": local_ip,
        "hostname": socket.gethostname()
    })

@app.route("/api/ping")
def api_ping():
    ip = request.args.get("ip", "").strip()
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return jsonify({"error": "invalid IP"}), 400
    out, err, rc = run_cmd(f"ping -c 4 -W 2 {ip}", timeout=15)
    return jsonify({"output": out or err, "ok": rc == 0})

@app.route("/api/traceroute")
def api_traceroute():
    ip = request.args.get("ip", "").strip()
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return jsonify({"error": "invalid IP"}), 400
    out, err, rc = run_cmd(f"traceroute -m 15 -w 1 {ip} 2>&1", timeout=30)
    return jsonify({"output": out or err, "ok": rc == 0})

if __name__ == "__main__":
    print("=" * 60)
    print("  NetAdmin Portal - Starting on http://0.0.0.0:7070")
    print("=" * 60)
    # Kick off initial scan
    t = threading.Thread(target=full_scan, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=7070, debug=False, threaded=True)
