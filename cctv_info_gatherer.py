#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CCTV Camera Information Gathering Tool
Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer

Purpose : Inventory and fingerprint IP cameras / DVR / NVR devices on a
          network YOU OWN or are AUTHORIZED to assess.
Methods : ONVIF WS-Discovery, SSDP, TCP port sweep, HTTP/RTSP banner
          grabbing, MAC-vendor hints, and basic exposure observations.
Scope   : Private (RFC1918) address ranges only. No credential guessing,
          no exploitation, no internet-wide scanning.
Deps    : Python 3.8+ standard library only.
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import uuid
from datetime import datetime

BANNER = r"""
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
"""

CREDIT = "CCTV Camera Info Gathering  |  coded by Mr Sabaz Ali Khan (Cyber Security Engineer)"

C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m",
     "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

# Ports commonly used by IP cameras / DVR / NVR
CAMERA_PORTS = {
    80: "HTTP", 443: "HTTPS", 554: "RTSP", 8554: "RTSP-alt", 8080: "HTTP-alt",
    8000: "Hikvision SDK", 8443: "HTTPS-alt", 8899: "ONVIF-alt", 37777: "Dahua DVR",
    34567: "XMEye/DVR", 5000: "HTTP-alt", 7001: "DVR-web", 23: "Telnet", 21: "FTP",
}

# Best-effort OUI hints (first 3 bytes of MAC). Not exhaustive; treat as hints only.
OUI_HINTS = {
    "44:19:B6": "Hikvision", "C0:56:E3": "Hikvision", "BC:AD:28": "Hikvision",
    "28:57:BE": "Hikvision", "3C:EF:8C": "Dahua", "4C:11:BF": "Dahua",
    "E0:50:8B": "Dahua", "00:40:8C": "Axis", "AC:CC:8E": "Axis",
    "00:09:18": "Hanwha/Samsung Techwin", "00:02:D1": "Vivotek",
}

VENDOR_KEYWORDS = [
    "hikvision", "dahua", "axis", "uniview", "reolink", "amcrest", "foscam",
    "vivotek", "hanwha", "tp-link", "tapo", "ipc", "dvr", "nvr", "webcam",
    "netcam", "onvif", "xmeye", "camera", "surveillance", "web service",
]


def info(msg): print(f"{C['c']}[*]{C['x']} {msg}")
def good(msg): print(f"{C['g']}[+]{C['x']} {msg}")
def warn(msg): print(f"{C['y']}[!]{C['x']} {msg}")
def bad(msg): print(f"{C['r']}[-]{C['x']} {msg}")


def show_banner():
    print(C["c"] + BANNER + C["x"])
    print(C["b"] + CREDIT + C["x"])
    print("-" * 78)


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is actually sent
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def resolve_targets(target):
    if target:
        net = ipaddress.ip_network(target, strict=False)
    else:
        net = ipaddress.ip_network(local_ip() + "/24", strict=False)
    if not (net.is_private and not net.is_loopback):
        raise ValueError("Only private (RFC1918) ranges are allowed by this tool.")
    if net.num_addresses > 1024:
        raise ValueError("Range too large (max /22 = 1024 addresses).")
    return net, [str(h) for h in net.hosts()]


def read_arp_table():
    """Return {ip: mac} from the local ARP/neighbour cache."""
    table = {}
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=10)
            for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})", out, re.I):
                table[ip] = mac.replace("-", ":").upper()
        else:
            try:
                out = subprocess.check_output(["ip", "neigh"], text=True, timeout=10)
                for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-f:]{17})", out, re.I):
                    table[ip] = mac.upper()
            except Exception:
                out = subprocess.check_output(["arp", "-an"], text=True, timeout=10)
                for ip, mac in re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{11,17})", out, re.I):
                    table[ip] = mac.upper()
    except Exception:
        pass
    return table


def vendor_from_mac(mac):
    return OUI_HINTS.get(mac[:8].upper()) if mac else None


# --------------------------------------------------------------------------
# Discovery protocols
# --------------------------------------------------------------------------
def onvif_discover(timeout=3.0):
    """ONVIF WS-Discovery multicast probe. Returns {ip: {xaddrs, scopes}}."""
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header><w:MessageID>uuid:%s</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
        '</d:Probe></e:Body></e:Envelope>' % uuid.uuid4()
    )
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(probe.encode(), ("239.255.255.250", 3702))
        while True:
            data, addr = s.recvfrom(65535)
            text = data.decode(errors="ignore")
            xaddrs = re.findall(r"<[\w:]*XAddrs>(.*?)</[\w:]*XAddrs>", text, re.S)
            scopes = re.findall(r"<[\w:]*Scopes>(.*?)</[\w:]*Scopes>", text, re.S)
            entry = found.setdefault(addr[0], {"xaddrs": [], "scopes": {}})
            for x in xaddrs:
                entry["xaddrs"] += x.split()
            for sc in scopes:
                for item in sc.split():
                    m = re.match(r"onvif://www\.onvif\.org/(name|hardware|location|type)/(.+)", item)
                    if m:
                        entry["scopes"].setdefault(m.group(1), []).append(m.group(2))
    except socket.timeout:
        pass
    except Exception as e:
        warn(f"ONVIF discovery error: {e}")
    finally:
        s.close()
    return found


def ssdp_discover(timeout=3.0):
    """SSDP M-SEARCH. Returns {ip: {server, location, st}}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg.encode(), ("239.255.255.250", 1900))
        while True:
            data, addr = s.recvfrom(65535)
            text = data.decode(errors="ignore")
            hdr = lambda k: (re.search(rf"^{k}:\s*(.+)$", text, re.I | re.M) or [None, ""])[1].strip()
            found.setdefault(addr[0], {"server": hdr("SERVER"),
                                       "location": hdr("LOCATION"), "st": hdr("ST")})
    except socket.timeout:
        pass
    except Exception as e:
        warn(f"SSDP error: {e}")
    finally:
        s.close()
    return found


# --------------------------------------------------------------------------
# Per-host probing
# --------------------------------------------------------------------------
def port_open(ip, port, timeout=0.7):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def sweep_host(ip):
    return ip, [p for p in CAMERA_PORTS if port_open(ip, p)]


def http_grab(ip, port, timeout=3.0):
    """Fetch '/' and extract Server header, auth realm, title."""
    res = {}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=ip)
        raw.settimeout(timeout)
        raw.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: CCTV-InfoGatherer\r\n\r\n".encode())
        data = b""
        while len(data) < 8192:
            chunk = raw.recv(4096)
            if not chunk:
                break
            data += chunk
        raw.close()
        text = data.decode(errors="ignore")
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", text)
        res["status"] = int(m.group(1)) if m else None
        for key, name in (("Server", "server"), ("WWW-Authenticate", "auth")):
            m = re.search(rf"^{key}:\s*(.+)$", text, re.I | re.M)
            if m:
                res[name] = m.group(1).strip()
        t = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if t:
            res["title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:100]
        res["https"] = port in (443, 8443)
    except Exception:
        pass
    return res


def rtsp_probe(ip, port, timeout=3.0):
    """OPTIONS + DESCRIBE on '/'. No credentials are ever sent."""
    res = {}

    def exchange(req):
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req.encode())
        data = s.recv(4096).decode(errors="ignore")
        s.close()
        return data

    base = f"rtsp://{ip}:{port}/"
    try:
        opt = exchange(f"OPTIONS {base} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CCTV-InfoGatherer\r\n\r\n")
        m = re.match(r"RTSP/\d\.\d\s+(\d+)", opt)
        res["options_status"] = int(m.group(1)) if m else None
        for key, name in (("Server", "server"), ("Public", "methods")):
            m = re.search(rf"^{key}:\s*(.+)$", opt, re.I | re.M)
            if m:
                res[name] = m.group(1).strip()
        desc = exchange(f"DESCRIBE {base} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n")
        m = re.match(r"RTSP/\d\.\d\s+(\d+)", desc)
        res["describe_status"] = int(m.group(1)) if m else None
        m = re.search(r"^WWW-Authenticate:\s*(.+)$", desc, re.I | re.M)
        if m:
            res["auth"] = m.group(1).strip()
    except Exception:
        pass
    return res


def fingerprint(ip, ports, mac, onvif, ssdp):
    dev = {"ip": ip, "mac": mac, "mac_vendor_hint": vendor_from_mac(mac),
           "open_ports": {p: CAMERA_PORTS[p] for p in ports},
           "http": {}, "rtsp": {}, "onvif": onvif.get(ip), "ssdp": ssdp.get(ip),
           "indicators": [], "observations": [], "score": 0}

    for p in ports:
        if p in (80, 443, 8080, 8443, 5000, 7001, 8000):
            g = http_grab(ip, p)
            if g:
                dev["http"][p] = g
        if p in (554, 8554):
            r = rtsp_probe(ip, p)
            if r:
                dev["rtsp"][p] = r

    # Build a text blob for keyword matching
    blob = " ".join(
        [str(v) for h in dev["http"].values() for v in h.values()]
        + [str(v) for r in dev["rtsp"].values() for v in r.values()]
        + [json.dumps(dev["onvif"] or {}), json.dumps(dev["ssdp"] or {})]
    ).lower()
    kw = sorted({k for k in VENDOR_KEYWORDS if k in blob})

    score = 0
    if dev["onvif"]:
        score += 5; dev["indicators"].append("Responded to ONVIF WS-Discovery")
    if dev["rtsp"]:
        score += 4; dev["indicators"].append("RTSP service responding")
    for p, name in ((37777, "Dahua DVR port"), (34567, "XMEye/DVR port"), (8000, "Hikvision SDK port")):
        if p in ports:
            score += 3; dev["indicators"].append(f"{name} open ({p})")
    if kw:
        score += min(len(kw), 3); dev["indicators"].append("Keywords: " + ", ".join(kw))
    if dev["mac_vendor_hint"]:
        score += 3; dev["indicators"].append(f"MAC OUI hint: {dev['mac_vendor_hint']}")
    dev["score"] = score
    dev["likely_camera"] = score >= 4

    # --- Exposure observations (passive, no credentials used) ---
    if 23 in ports:
        dev["observations"].append("Telnet (23) is open - insecure management protocol")
    if 21 in ports:
        dev["observations"].append("FTP (21) is open - cleartext protocol")
    for p, h in dev["http"].items():
        if not h.get("https") and h.get("status") in (200, 401, 403):
            dev["observations"].append(f"Web admin on {p} served over plain HTTP")
    for p, r in dev["rtsp"].items():
        if r.get("describe_status") == 200:
            dev["observations"].append(f"RTSP {p}: DESCRIBE succeeded without authentication (verify stream access control)")
        elif r.get("describe_status") == 401:
            dev["observations"].append(f"RTSP {p}: authentication required (good)")
        if "basic" in (r.get("auth") or "").lower():
            dev["observations"].append(f"RTSP {p}: Basic auth advertised (credentials are weakly protected)")
    for p, h in dev["http"].items():
        if "basic" in (h.get("auth") or "").lower() and not h.get("https"):
            dev["observations"].append(f"HTTP {p}: Basic auth over plain HTTP exposes credentials on the wire")
    if dev["onvif"] and not any("auth" in o for o in dev["observations"]):
        dev["observations"].append("ONVIF service discoverable on LAN - confirm it requires authentication")
    return dev


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_device(d):
    tag = f"{C['g']}LIKELY CAMERA/DVR{C['x']}" if d["likely_camera"] else f"{C['y']}possible{C['x']}"
    print(f"\n{C['b']}{d['ip']}{C['x']}  [{tag}]  score={d['score']}")
    if d["mac"]:
        print(f"   MAC      : {d['mac']}  ({d['mac_vendor_hint'] or 'vendor unknown'})")
    print("   Ports    : " + ", ".join(f"{p}/{n}" for p, n in d["open_ports"].items()))
    for p, h in d["http"].items():
        line = f"HTTP {p}: status={h.get('status')} server={h.get('server','-')} title={h.get('title','-')}"
        if h.get("auth"):
            line += f" auth={h['auth']}"
        print("   " + line)
    for p, r in d["rtsp"].items():
        print(f"   RTSP {p}: options={r.get('options_status')} describe={r.get('describe_status')} "
              f"server={r.get('server','-')}")
    if d["onvif"]:
        sc = d["onvif"]["scopes"]
        print(f"   ONVIF    : name={sc.get('name')} hardware={sc.get('hardware')} location={sc.get('location')}")
        for x in d["onvif"]["xaddrs"][:2]:
            print(f"              service: {x}")
    if d["ssdp"] and d["ssdp"].get("server"):
        print(f"   SSDP     : {d['ssdp']['server']}")
    for i in d["indicators"]:
        print(f"   {C['c']}indicator{C['x']}: {i}")
    for o in d["observations"]:
        print(f"   {C['y']}observe{C['x']}  : {o}")


def save_reports(meta, devices):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    jpath, tpath = f"cctv_report_{ts}.json", f"cctv_report_{ts}.txt"
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "devices": devices}, f, indent=2, default=str)
    with open(tpath, "w", encoding="utf-8") as f:
        f.write(CREDIT + "\n" + "=" * 78 + "\n")
        for k, v in meta.items():
            f.write(f"{k}: {v}\n")
        for d in devices:
            f.write(f"\n{d['ip']}  likely_camera={d['likely_camera']} score={d['score']}\n")
            f.write(f"  MAC: {d['mac']} ({d['mac_vendor_hint']})\n")
            f.write("  Ports: " + ", ".join(map(str, d["open_ports"])) + "\n")
            for i in d["indicators"]:
                f.write(f"  indicator: {i}\n")
            for o in d["observations"]:
                f.write(f"  observation: {o}\n")
    return jpath, tpath


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    show_banner()
    ap = argparse.ArgumentParser(description="CCTV camera information gathering (authorized, private networks only)")
    ap.add_argument("-t", "--target", help="CIDR to assess, e.g. 192.168.1.0/24 (default: local /24)")
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("--yes", action="store_true", help="Confirm you are authorized to assess this network")
    args = ap.parse_args()

    try:
        net, hosts = resolve_targets(args.target)
    except Exception as e:
        bad(str(e)); sys.exit(1)

    warn("Use ONLY on networks you own or have written authorization to assess.")
    if not args.yes:
        if input(f"Confirm you are authorized to assess {net}? [yes/no]: ").strip().lower() != "yes":
            bad("Authorization not confirmed. Exiting."); sys.exit(1)

    start = datetime.now()
    info(f"Target network : {net}  ({len(hosts)} hosts)")

    info("Running ONVIF WS-Discovery and SSDP ...")
    with cf.ThreadPoolExecutor(2) as ex:
        f1, f2 = ex.submit(onvif_discover), ex.submit(ssdp_discover)
        onvif, ssdp = f1.result(), f2.result()
    good(f"ONVIF responders: {len(onvif)}   SSDP responders: {len(ssdp)}")

    info(f"Sweeping {len(CAMERA_PORTS)} camera-related ports ...")
    candidates = {}
    with cf.ThreadPoolExecutor(args.threads) as ex:
        for ip, ports in ex.map(sweep_host, hosts):
            if ports:
                candidates[ip] = ports
    for ip in onvif:  # ensure ONVIF responders in range are included
        if ipaddress.ip_address(ip) in net and ip not in candidates:
            candidates[ip] = []
    good(f"Hosts with relevant services: {len(candidates)}")

    arp = read_arp_table()
    info("Fingerprinting devices ...")
    devices = []
    with cf.ThreadPoolExecutor(min(20, max(1, len(candidates)))) as ex:
        futs = [ex.submit(fingerprint, ip, ports, arp.get(ip), onvif, ssdp)
                for ip, ports in candidates.items()]
        for f in futs:
            devices.append(f.result())
    devices.sort(key=lambda d: (-d["score"], ipaddress.ip_address(d["ip"])))

    print("\n" + "=" * 78)
    print(C["b"] + "RESULTS" + C["x"])
    print("=" * 78)
    for d in devices:
        print_device(d)

    likely = sum(1 for d in devices if d["likely_camera"])
    meta = {"tool": CREDIT, "target": str(net), "started": start.isoformat(timespec="seconds"),
            "duration_s": round((datetime.now() - start).total_seconds(), 1),
            "hosts_scanned": len(hosts), "devices_listed": len(devices), "likely_cameras": likely}
    jpath, tpath = save_reports(meta, devices)
    print("\n" + "-" * 78)
    good(f"Likely cameras/DVR/NVR: {likely} of {len(devices)} devices listed")
    good(f"Reports saved: {jpath}, {tpath}")
    print(C["b"] + CREDIT + C["x"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
