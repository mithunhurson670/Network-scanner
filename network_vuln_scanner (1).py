#!/usr/bin/env python3
"""
Modular Network and Vulnerability Scanner
==========================================

Pipeline:
    1. port_scan()          -> raw TCP connect scan over a user-defined range
    2. banner_grab()        -> grabs service banners from each open port
    3. vulnerability_scan()  -> nmap -O -sV --script=vuln (OS + version + vuln NSE)
    4. generate_report()    -> writes a simple text vulnerability report to disk
    5. network_scan()       -> orchestrates the above and times the whole run

IMPORTANT / LEGAL NOTICE
-------------------------
Only run this against hosts and networks you own or have explicit,
documented authorization to test. Unauthorized port scanning and
vulnerability scanning can be illegal in many jurisdictions.

Dependencies:
    - Python standard library: socket, datetime
    - requests        (pip install requests)
    - python-nmap     (pip install python-nmap)
    - nmap            (the actual Nmap binary must be installed on the OS
                        and on PATH, e.g. `apt install nmap` / `brew install nmap`)
      NOTE: OS detection (-O) and NSE vuln scripts typically require the
      nmap binary to be run with root/administrator privileges.
"""

import socket
import sys
from datetime import datetime

# --- Optional / third-party imports guarded with error handling ------------

try:
    import requests  # noqa: F401  (kept available for modules/extensions that
                      # want to do HTTP-based enrichment, e.g. CVE lookups)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] Warning: 'requests' module not found. HTTP-based features "
          "will be disabled. Install with: pip install requests")

try:
    import nmap
    NMAP_MODULE_AVAILABLE = True
except ImportError:
    NMAP_MODULE_AVAILABLE = False
    print("[!] Warning: 'python-nmap' module not found. Vulnerability/OS "
          "scanning will be disabled. Install with: pip install python-nmap")


DEFAULT_TIMEOUT = 1  # seconds, per the socket connect scan


# ---------------------------------------------------------------------------
# 1. Port Scanner
# ---------------------------------------------------------------------------
def port_scan(target, start_port, end_port, timeout=DEFAULT_TIMEOUT):
    """
    Scan a range of TCP ports on `target` using raw socket connections.

    Returns:
        list[int]: sorted list of open ports.
    """
    open_ports = []

    print(f"\n[*] Starting port scan on {target} "
          f"(ports {start_port}-{end_port}, timeout={timeout}s)")
    print("-" * 60)

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port:>5} is OPEN")
        except socket.gaierror:
            print(f"[!] Hostname could not be resolved: {target}")
            return open_ports
        except socket.error as e:
            print(f"[!] Socket error on port {port}: {e}")
        finally:
            sock.close()

    if not open_ports:
        print("[-] No open ports found in the specified range.")
    else:
        print(f"\n[*] Scan complete. Open ports: {open_ports}")

    return open_ports


# ---------------------------------------------------------------------------
# 2. Banner Grabber
# ---------------------------------------------------------------------------
def banner_grab(target, open_ports, timeout=DEFAULT_TIMEOUT):
    """
    Attempt to grab a service banner (up to 1024 bytes) from each open port.

    Returns:
        dict[int, str]: mapping of port -> banner text (or empty string).
    """
    banners = {}

    if not open_ports:
        print("\n[*] No open ports to grab banners from.")
        return banners

    print(f"\n[*] Starting banner grab on {len(open_ports)} open port(s)")
    print("-" * 60)

    for port in open_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target, port))
            # Some services send a banner immediately on connect (FTP, SSH,
            # SMTP...). Others need a nudge; a blank request often works
            # for simple text-based protocols, but we keep it read-only
            # and non-intrusive here.
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""

            banner = data.decode("utf-8", errors="ignore").strip()

            if banner:
                banners[port] = banner
                print(f"[+] Port {port:>5} banner: {banner}")
            else:
                banners[port] = ""
                print(f"[-] Port {port:>5}: no banner returned")

        except (socket.timeout, ConnectionRefusedError) as e:
            print(f"[!] Port {port:>5}: connection failed ({e})")
        except socket.error as e:
            print(f"[!] Port {port:>5}: socket error ({e})")
        finally:
            sock.close()

    return banners


# ---------------------------------------------------------------------------
# 3. Vulnerability & OS Scanner
# ---------------------------------------------------------------------------
def vulnerability_scan(target):
    """
    Run an Nmap scan with OS detection, service/version detection, and the
    default 'vuln' NSE script category, using python-nmap.

    Returns:
        nmap.PortScanner instance (or None if unavailable/failed), for
        further programmatic inspection if needed.
    """
    print(f"\n[*] Starting vulnerability & OS scan on {target}")
    print("    (nmap arguments: -O -sV --script=vuln)")
    print("-" * 60)

    if not NMAP_MODULE_AVAILABLE:
        print("[!] Skipping vulnerability scan: python-nmap is not installed.")
        return None

    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, arguments="-O -sV --script=vuln")
    except nmap.PortScannerError as e:
        print(f"[!] Nmap scan failed: {e}")
        print("    (Is the 'nmap' binary installed and on PATH? Does this "
              "scan require root/admin privileges for -O?)")
        return None
    except Exception as e:
        print(f"[!] Unexpected error running nmap scan: {e}")
        return None

    if target not in scanner.all_hosts():
        print(f"[-] No scan results returned for {target}. "
              f"The host may be down or blocking probes.")
        return scanner

    host_data = scanner[target]

    # --- Hostnames ---
    hostnames = host_data.hostnames() if hasattr(host_data, "hostnames") else []
    print(f"\n[*] Hostnames for {target}:")
    if hostnames:
        for h in hostnames:
            name = h.get("name") or "(none)"
            h_type = h.get("type") or "unknown"
            print(f"    - {name} (type: {h_type})")
    else:
        print("    - No hostnames resolved.")

    # --- OS Detection ---
    print(f"\n[*] OS Match Results:")
    os_matches = host_data.get("osmatch", [])
    if os_matches:
        for match in os_matches:
            name = match.get("name", "Unknown")
            accuracy = match.get("accuracy", "?")
            print(f"    - {name} (Accuracy: {accuracy}%)")
    else:
        print("    - No OS matches found (requires root/admin privileges "
              "for -O to work reliably).")

    # --- Service/Version + Vulnerability Scripts per port ---
    print(f"\n[*] Service, Version & Vulnerability Details:")
    for proto in host_data.all_protocols():
        ports = sorted(host_data[proto].keys())
        for port in ports:
            port_info = host_data[proto][port]
            state = port_info.get("state", "unknown")
            service = port_info.get("name", "unknown")
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            extra = port_info.get("extrainfo", "")

            print(f"\n    Port {port}/{proto} ({state})")
            print(f"      Service: {service} {product} {version} {extra}".rstrip())

            script_output = port_info.get("script", {})
            if script_output:
                print(f"      Vulnerability script results:")
                for script_name, output in script_output.items():
                    cleaned = output.strip().replace("\n", "\n        ")
                    print(f"        [{script_name}]\n        {cleaned}")
            else:
                print(f"      No vulnerability script output for this port.")

    return scanner


# ---------------------------------------------------------------------------
# 4. Report Generator
# ---------------------------------------------------------------------------
def generate_report(target, start_port, end_port, open_ports, banners,
                     scanner, start_time, end_time, filename=None):
    """
    Write a simple, human-readable vulnerability report to a text file.

    Returns:
        str: the path to the report file that was written.
    """
    if filename is None:
        stamp = start_time.strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        filename = f"vuln_report_{safe_target}_{stamp}.txt"

    lines = []
    lines.append("=" * 70)
    lines.append("VULNERABILITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"Target:        {target}")
    lines.append(f"Port Range:    {start_port}-{end_port}")
    lines.append(f"Scan Started:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Scan Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Duration:      {end_time - start_time}")
    lines.append("")

    # --- Open ports / weak configuration section ---
    lines.append("-" * 70)
    lines.append("1. OPEN PORTS")
    lines.append("-" * 70)
    if open_ports:
        for port in open_ports:
            lines.append(f"  - Port {port}: OPEN")
    else:
        lines.append("  No open ports found in the specified range.")
    lines.append("")

    # --- Banners / outdated software versions section ---
    lines.append("-" * 70)
    lines.append("2. SERVICE BANNERS (possible outdated software versions)")
    lines.append("-" * 70)
    if banners:
        for port, banner in banners.items():
            if banner:
                lines.append(f"  - Port {port}: {banner}")
            else:
                lines.append(f"  - Port {port}: (no banner returned)")
    else:
        lines.append("  No banners collected.")
    lines.append("")

    # --- OS + vuln script section ---
    lines.append("-" * 70)
    lines.append("3. OS DETECTION & VULNERABILITY FINDINGS (nmap)")
    lines.append("-" * 70)
    if scanner is not None and target in scanner.all_hosts():
        host_data = scanner[target]

        hostnames = host_data.hostnames() if hasattr(host_data, "hostnames") else []
        if hostnames:
            lines.append("  Hostnames:")
            for h in hostnames:
                lines.append(f"    - {h.get('name') or '(none)'} "
                              f"(type: {h.get('type') or 'unknown'})")

        os_matches = host_data.get("osmatch", [])
        if os_matches:
            lines.append("  OS Matches:")
            for match in os_matches:
                lines.append(f"    - {match.get('name', 'Unknown')} "
                              f"(Accuracy: {match.get('accuracy', '?')}%)")
        else:
            lines.append("  OS Matches: none found "
                          "(requires root/admin privileges).")

        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                port_info = host_data[proto][port]
                service = port_info.get("name", "unknown")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                lines.append(f"  Port {port}/{proto}: {service} "
                              f"{product} {version}".rstrip())

                script_output = port_info.get("script", {})
                if script_output:
                    for script_name, output in script_output.items():
                        cleaned = output.strip().replace("\n", "\n      ")
                        lines.append(f"      [{script_name}] {cleaned}")
    else:
        lines.append("  No nmap results available (python-nmap missing, "
                      "nmap binary missing, or scan failed).")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[*] Report written to: {filename}")
    except OSError as e:
        print(f"[!] Failed to write report file: {e}")

    return filename


# ---------------------------------------------------------------------------
# 5. Orchestrator with Scan Execution Timer
# ---------------------------------------------------------------------------
def network_scan(target, start_port, end_port):
    """
    Runs the full pipeline: port_scan -> banner_grab -> vulnerability_scan
    -> generate_report, and times the whole operation using datetime.now().
    """
    start_time = datetime.now()
    print("=" * 60)
    print(f" Network & Vulnerability Scan")
    print(f" Target: {target}")
    print(f" Port Range: {start_port}-{end_port}")
    print(f" Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Step 1: Port scan
    open_ports = port_scan(target, start_port, end_port)

    # Step 2: Banner grab (only for open ports)
    banners = banner_grab(target, open_ports)

    # Step 3: Vulnerability & OS scan
    scanner = vulnerability_scan(target)

    # Step 4: Timing summary
    end_time = datetime.now()
    duration = end_time - start_time

    print("\n" + "=" * 60)
    print(f" Scan Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Total Duration: {duration}")
    print("=" * 60)

    # Step 5: Write the vulnerability report to disk
    generate_report(target, start_port, end_port, open_ports, banners,
                     scanner, start_time, end_time)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def get_cli_input():
    """Prompt the user for target and port range, with basic validation."""
    target = input("Enter target IP address (or hostname): ").strip()
    if not target:
        print("[!] Target cannot be empty.")
        sys.exit(1)

    try:
        # Resolve early to fail fast with a clear message.
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve target: {target}")
        sys.exit(1)

    try:
        start_port = int(input("Enter starting port: ").strip())
        end_port = int(input("Enter ending port: ").strip())
    except ValueError:
        print("[!] Ports must be integers.")
        sys.exit(1)

    if not (0 <= start_port <= 65535) or not (0 <= end_port <= 65535):
        print("[!] Ports must be in the range 0-65535.")
        sys.exit(1)

    if start_port > end_port:
        print("[!] Starting port must be <= ending port.")
        sys.exit(1)

    return target, start_port, end_port


if __name__ == "__main__":
    print("Modular Network and Vulnerability Scanner")
    print("Only scan systems you own or are explicitly authorized to test.\n")

    try:
        target_ip, start_p, end_p = get_cli_input()
        network_scan(target_ip, start_p, end_p)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
