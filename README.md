# vuln_scanner.sh

> **For authorized penetration testing only. Never run against systems you don't own or have explicit written permission to test.**

---

## Overview

`vuln_scanner_minimal.sh` is a straightforward Bash script that scans a network with nmap, identifies live hosts, detects open services and known vulnerabilities, and prints ready-to-use attack commands for each finding. It's designed to be simple — no flags, no config files, just a target and an optional output directory.

If no live hosts are found, it stops. If no exploitable services are found after scanning, it stops. Otherwise it prints attack suggestions to the terminal and saves them to a text report.

> If you need scan modes, severity scoring, MSF RC file generation, HTML reports, CVE extraction, banner grabbing, and more — use [`vuln_scanner_advanced.sh`](./README_advanced.md) instead.

---

## Requirements

### Required
```
nmap
xmllint      (apt install libxml2-utils)
```

### Optional (commands will be printed regardless)
```
hydra        msfconsole    nikto
gobuster     sqlmap        smbclient
crackmapexec onesixtyone   showmount
redis-cli    mongo
```

> Run as **root** for SYN scan, OS detection, and full nmap NSE script capability.

---

## Installation

```bash
chmod +x vuln_scanner_minimal.sh
```

That's it.

---

## Usage

```bash
sudo ./vuln_scanner_minimal.sh <target> [output_dir]
```

| Argument | Required | Description |
|---|---|---|
| `<target>` | Yes | IP, range, or CIDR — e.g. `192.168.1.0/24`, `10.0.0.5` |
| `[output_dir]` | No | Where to save outputs. Defaults to `/tmp/vuln_scan_<timestamp>` |

### Examples

```bash
sudo ./vuln_scanner_minimal.sh 192.168.1.0/24
sudo ./vuln_scanner_minimal.sh 10.0.0.5
sudo ./vuln_scanner_minimal.sh 10.0.0.0/24 /opt/results
```

---

## How It Works

```
Phase 1 → Host discovery (nmap -sn)
           ↓ Stop if no live hosts found
Phase 2 → Deep scan: all ports, service versions, OS, vuln + banner + default NSE scripts
           ↓ Stop if nmap produces no output
Phase 3 → Parse XML results
           → Map each open port to attack suggestions
           ↓ Stop if no exploitable services found
Output  → Print results to terminal
        → Save text report to output dir
```

The scan uses `-p-` (all 65535 ports), `-T4`, `--min-rate 1000`, and `--script=vuln,banner,default` — a solid balance of speed and coverage.

---

## Output

```
/output_dir/
├── nmap_scan.xml           # Raw nmap XML output
└── attack_suggestions.txt  # Attack commands per host
```

Results are also printed to the terminal in color during the run.

---

## Covered Services

| Port(s) | Service | Attack Commands Suggested |
|---|---|---|
| 21 | FTP | Hydra brute-force, MSF anonymous check, MSF ftp_login. vsftpd 2.3.4 backdoor if version matches |
| 22 | SSH | Hydra brute-force, MSF ssh_login. CVE warning if OpenSSH + CVE found in script output |
| 23 | Telnet | Hydra brute-force, MSF telnet_login |
| 25/587/465 | SMTP | MSF smtp_enum (user enumeration), Hydra brute-force |
| 80/8080/8000/8008 | HTTP | Nikto, Gobuster, MSF http_version. SQLMap hint if SQLi detected, Apache module search if Apache detected |
| 443/8443 | HTTPS | Nikto with SSL, Gobuster with `-k`. Heartbleed MSF module if detected |
| 139/445 | SMB | MSF EternalBlue, MSF smb_login, CrackMapExec, smbclient share enum. CRITICAL flag if ms17-010 confirmed |
| 3389 | RDP | Hydra brute-force, MSF BlueKeep, MSF rdp_scanner |
| 3306 | MySQL | Hydra brute-force, MSF mysql_login, MSF mysql_hashdump |
| 5432 | PostgreSQL | Hydra brute-force, MSF postgres_login |
| 6379 | Redis | redis-cli unauthenticated ping, MSF redis_server |
| 27017/27018 | MongoDB | mongo unauthenticated check, MSF mongodb_login |
| 1433 | MSSQL | Hydra brute-force, MSF mssql_login, MSF mssql_enum |
| 161 | SNMP | onesixtyone community brute, MSF snmp_enum |
| 2049 | NFS | showmount, MSF nfsmount |
| 5900/5901 | VNC | Hydra brute-force, MSF vnc_login |
| other | Unknown | MSF search by service name, Hydra generic |

---

## Critical Detections

The script flags the following as **CRITICAL** when detected by nmap scripts:

- **vsftpd 2.3.4** — backdoor on port 21, direct shell access
- **EternalBlue (MS17-010)** — confirmed via `smb-vuln-ms17-010` script on port 445
- **Heartbleed (CVE-2014-0160)** — detected via SSL scripts on port 443/8443
- **OpenSSH CVEs** — generic warning when CVE strings appear in script output

---

## Difference vs. Advanced Version

| Feature | vuln_scanner.sh | vuln_scanner_advanced.sh |
|---|---|---|
| CLI flags | No — positional args only | Yes — full flag parser |
| Scan modes | Fixed (normal) | normal, stealth, aggressive, custom |
| Services covered | 16 | 30+ |
| Severity scoring | No | Yes (CRITICAL/HIGH/MEDIUM/LOW) |
| CVE extraction | Partial (warning only) | Full extraction + saved to file |
| Banner grabbing | No | Yes (nc, saved per port) |
| MSF RC files | No | Yes, per host |
| HTML report | No | Yes |
| OS/hostname tracking | No | Yes |
| CPE parsing | No | Yes |
| IPv6 | No | Yes |
| Wordlist config | Hardcoded filenames | Configurable via flags |

---

## License

This tool is for **authorized use only**. You are responsible for ensuring you have proper permission before scanning any target. Unauthorized use is illegal.
