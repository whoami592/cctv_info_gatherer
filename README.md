<div align="center">

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣏⠛⠻⠿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣷⣦⣤⣈⠙⠛⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⣈⠙⠻⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⡉⠛⠻⢿⣿⣷⣶⣤⣀⠀⠀
⠀⠀⠀⠉⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⢻⣍⡉⠉⣿⠇⠀
⠀⠀⠀⠀⠀⠀⠀⢹⡏⢹⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣰⣿⣿⣾⠏⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⠈⣿⠸⣯⠉⠛⠿⢿⣿⣿⣿⣿⡏⠀⠻⠿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢿⡆⢻⡄⣿⡀⠀⠀⠀⠈⠙⠛⠿⠿⠿⠿⠛⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠘⣇⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣀⣿⣴⣿⢾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣴⡶⠾⠟⠛⠋⢹⡏⠀⢹⡇⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣿⠀⠀⠀⠀⢀⣈⣿⣶⠿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⣿⣴⠶⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

# 📹 CCTV Camera Information Gathering Tool

**Inventory and fingerprint IP cameras, DVRs and NVRs on networks you own or are authorized to assess.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib%20only)-brightgreen)
![Scope](https://img.shields.io/badge/scope-private%20networks%20only-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

*Coded by **Mr Sabaz Ali Khan** — Cyber Security Engineer*

</div>

---

## ⚠️ Legal Disclaimer

This tool is intended **only** for security assessment of networks that **you own** or have **explicit written authorization** to test. Unauthorized scanning of networks or devices may be illegal in your country. The author accepts no responsibility for misuse.

To reduce the risk of misuse, the tool:

- Accepts **private (RFC1918) address ranges only**
- Limits scan size to **/22 (1024 addresses)**
- Asks for **authorization confirmation** before every scan
- Does **not** guess credentials, exploit vulnerabilities, or scan the internet

---

## ✨ Features

| Capability | Description |
|---|---|
| **ONVIF WS-Discovery** | Multicast probe to find ONVIF-compliant cameras and read their name, hardware and location scopes |
| **SSDP Discovery** | M-SEARCH to find UPnP devices and their server banners |
| **Camera Port Sweep** | Concurrent TCP check of camera/DVR-related ports (80, 443, 554, 8554, 8080, 8000, 8443, 8899, 37777, 34567, 5000, 7001, 23, 21) |
| **HTTP Banner Grabbing** | Status code, `Server` header, page title and `WWW-Authenticate` info |
| **RTSP Probing** | `OPTIONS` / `DESCRIBE` checks to see if the stream service responds and whether it requires authentication |
| **MAC Vendor Hints** | Best-effort OUI lookup (Hikvision, Dahua, Axis, Hanwha, Vivotek) using the local ARP/neighbour table |
| **Scoring Engine** | Combines all indicators into a score and flags each device as *likely camera/DVR/NVR* or *possible* |
| **Exposure Observations** | Passive findings such as Telnet/FTP open, web admin over plain HTTP, Basic auth over HTTP, RTSP without authentication |
| **Reports** | Automatic JSON and TXT report generation |

---

## 📦 Requirements

- Python **3.8+**
- **No external packages** — standard library only
- Works on Windows, Linux (including Kali) and macOS

---

## 🚀 Installation

```bash
git clone https://github.com/whoami592/cctv_info_gatherer.git
cd cctv_info_gatherer
```

No `pip install` needed.

---

## 🛠️ Usage

```bash
# Scan your local /24 network (auto-detected)
python3 cctv_info_gatherer.py

# Scan a specific private range
python3 cctv_info_gatherer.py -t 192.168.1.0/24

# Skip the interactive prompt (you confirm you are authorized)
python3 cctv_info_gatherer.py -t 192.168.1.0/24 --yes

# Tune concurrency
python3 cctv_info_gatherer.py -t 10.0.0.0/24 --threads 150 --yes
```

### Command-line options

| Option | Description | Default |
|---|---|---|
| `-t`, `--target` | CIDR range to assess, e.g. `192.168.1.0/24` | Your local `/24` |
| `--threads` | Number of concurrent threads for the port sweep | `100` |
| `--yes` | Confirms you are authorized to assess the network (skips the prompt) | Off |

---

## 🔍 How It Works

```
1. Validate target  ->  private range only, max /22
2. Discovery        ->  ONVIF WS-Discovery + SSDP (in parallel)
3. Port sweep       ->  camera-related TCP ports on every host
4. Fingerprinting   ->  HTTP / RTSP banners, MAC vendor hint, keyword matching
5. Scoring          ->  indicators are weighted into a score
6. Observations     ->  passive exposure findings (no credentials used)
7. Reporting        ->  console output + JSON + TXT report
```

### Scoring

| Indicator | Points |
|---|---|
| Responded to ONVIF WS-Discovery | +5 |
| RTSP service responding | +4 |
| Dahua (37777) / XMEye (34567) / Hikvision SDK (8000) port open | +3 each |
| MAC OUI matches a known camera vendor | +3 |
| Camera-related keywords in banners (max) | +3 |

A device with a score of **4 or more** is marked as a **likely camera/DVR/NVR**.

---

## 📄 Output

Each scan creates two files in the current directory:

```
cctv_report_YYYYMMDD_HHMMSS.json   # full structured data
cctv_report_YYYYMMDD_HHMMSS.txt    # human-readable summary
```

### Sample console output

```
192.168.1.64  [LIKELY CAMERA/DVR]  score=15
   MAC      : 44:19:B6:XX:XX:XX  (Hikvision)
   Ports    : 80/HTTP, 554/RTSP, 8000/Hikvision SDK
   HTTP 80: status=401 server=App-webs/ title=- auth=Digest realm="..."
   RTSP 554: options=200 describe=401 server=...
   ONVIF    : name=['IPC'] hardware=['DS-2CD...'] location=None
   indicator: Responded to ONVIF WS-Discovery
   indicator: RTSP service responding
   indicator: Hikvision SDK port open (8000)
   observe  : RTSP 554: authentication required (good)
```

*(Values above are illustrative.)*

---

## 🛡️ Security Observations the Tool Can Report

- Telnet (23) open — insecure management protocol
- FTP (21) open — cleartext protocol
- Web admin interface served over plain HTTP
- HTTP Basic authentication over plain HTTP (credentials exposed on the wire)
- RTSP `DESCRIBE` succeeded without authentication
- RTSP advertising Basic authentication
- ONVIF service discoverable on the LAN

> These are **observations for hardening**, not exploitation. Use them to secure your own devices: change default passwords, disable Telnet/FTP, enable HTTPS, update firmware, and isolate cameras on a separate VLAN.

---

## ⚙️ Limitations

- MAC vendor detection is a **hint only** and covers a small OUI list
- ARP data is only available for hosts on the same local segment
- Multicast discovery (ONVIF/SSDP) depends on your network allowing it
- Results are indicators, not proof — always verify manually

---

## 🤝 Contributing

Pull requests are welcome. Ideas:

- Larger OUI database
- Additional vendor fingerprints
- CSV / HTML report export
- IPv6 support

---

## 📜 License

Choose a license for your repository (for example MIT) and add a `LICENSE` file.

---

<div align="center">

**CCTV Camera Info Gathering | coded by Mr Sabaz Ali Khan (Cyber Security Engineer)**

⭐ If you find this useful, give the repo a star!

</div>
