# Network & Vulnerability Scanner (Mini Project)

A modular Python CLI tool that scans a target host for open ports, grabs
service banners, and runs an Nmap-powered OS/version/vulnerability scan —
then writes a simple text report of the findings.

## ⚠️ Legal Notice

Only run this tool against hosts and networks **you own** or have
**explicit, documented authorization** to test. Unauthorized scanning can
be illegal under laws like the U.S. Computer Fraud and Abuse Act, the UK
Computer Misuse Act, and similar legislation elsewhere.

## Features

- **Port Scanner** — raw TCP connect scan (`socket`) over a user-defined
  port range, 1-second default timeout.
- **Banner Grabber** — connects to each open port and reads up to 1024
  bytes of service banner data, useful for spotting outdated software
  versions.
- **Vulnerability & OS Scanner** — uses [`python-nmap`](https://pypi.org/project/python-nmap/)
  to run `nmap -O -sV --script=vuln`, reporting hostnames, OS matches
  (with accuracy %), service versions, and NSE vulnerability script output.
- **Report Generator** — writes a plain-text vulnerability report
  (`vuln_report_<target>_<timestamp>.txt`) summarizing everything found.
- **Scan Timer** — tracks and prints total scan duration using
  `datetime.now()`.

## Requirements

- Python 3.7+
- The [Nmap](https://nmap.org/download.html) binary installed and on your
  `PATH` (`sudo apt install nmap`, `brew install nmap`, or the Windows
  installer).
- Python packages: see [`requirements.txt`](requirements.txt)

```bash
pip install -r requirements.txt
```

## Usage

OS detection (`-O`) and the `vuln` NSE script category generally need
elevated privileges to work correctly:

```bash
sudo python3 network_vuln_scanner.py
```

You'll be prompted for:

```
Enter target IP address (or hostname): 127.0.0.1
Enter starting port: 20
Enter ending port: 100
```

The script then runs the full pipeline and prints results to the
terminal, finishing with a written report file in the current directory.

## Project Structure

```
.
├── network_vuln_scanner.py   # main script
├── requirements.txt          # Python dependencies
├── README.md
└── .gitignore
```

## Code Structure

| Function              | Purpose                                              |
|------------------------|-------------------------------------------------------|
| `port_scan()`          | TCP connect scan over the given port range           |
| `banner_grab()`        | Grabs service banners from open ports                |
| `vulnerability_scan()` | Runs `nmap -O -sV --script=vuln` via `python-nmap`    |
| `generate_report()`    | Writes a text vulnerability report to disk            |
| `network_scan()`       | Orchestrates the pipeline and times execution         |

## Expected Outcome

Hands-on experience with the fundamentals of penetration testing and
vulnerability assessment: identifying open services, spotting weak or
outdated configurations, and interpreting automated vulnerability scan
output.

## Disclaimer

This project is for educational purposes as part of a coursework
assignment. The author is not responsible for misuse of this tool.
