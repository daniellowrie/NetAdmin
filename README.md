# NetAdmin Portal

A lightweight, zero-dependency network administration dashboard for Linux.
Discovers devices on your local network, visualizes them on an interactive map,
and provides live health/status monitoring — all from a browser.

<img width="1614" height="723" alt="image" src="https://github.com/user-attachments/assets/d2dbe849-c57d-44bb-a7e6-9472f999db7c" />

---

## Quick Start

```bash
chmod +x install.sh
./install.sh
```

Then open **http://localhost:7070** in any browser.

---

## Features

| Feature | Details |
|---|---|
| **Auto Discovery** | ARP scan + nmap ping sweep, falls back to ARP table |
| **Network Map** | Interactive canvas: pan, zoom, drag, hover, click |
| **Hover Details** | IP, MAC, OS guess, latency, online status |
| **Click Details** | Full device analysis panel (ports, services, vendor) |
| **Health Check** | One-click ping sweep — see offline devices at a glance |
| **OS Detection** | nmap OS fingerprinting + TTL heuristic fallback |
| **Port Scan** | Common services (HTTP, SSH, RDP, SMB, DNS, etc.) |
| **Ping / Traceroute** | Run directly from the detail panel |
| **Auto Refresh** | Health check every 60 seconds, device list every 15 s |
| **Systemd Service** | Optional: auto-start on login |

---

## Requirements

The installer handles everything. On a fresh Debian/Ubuntu/Mint install it will
offer to install:

- `python3`, `python3-pip` — runtime
- `flask` (pip) — web server
- `nmap` — port scanning & OS detection  
- `arp-scan` — fast device discovery
- `traceroute` — network path tracing
- `iproute2`, `iputils-ping` — network utilities (usually pre-installed)

**No Docker. No Node.js. No databases.**

---

## Manual Launch

```bash
# From the install directory
python3 server.py

# Or via the launcher
netadmin
```

---

## File Layout

```
netadmin/
├── install.sh        ← run this first
├── server.py         ← Flask backend (network scanning)
├── static/
│   └── index.html    ← entire frontend (one file)
└── README.md
```

---

## Tips

- **Best results**: allow sudo for nmap and arp-scan (installer offers this).
- **Firewall**: portal binds to `0.0.0.0:7070` — accessible from any device on
  your network once running.
- **Large networks**: scanning a /24 takes 30–90 seconds depending on device count.
- **OS detection**: requires nmap and works best with sudo.
