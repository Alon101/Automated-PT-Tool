# Pen_Tester

A Python tool that automates the early stages of a network pentest: scanning a
target for open ports and services, testing login services for weak passwords,
and (in Full mode) mapping known vulnerabilities and public exploits. Built for
the Magen Cyber program, project ZX301.

## What it does

You give it a target, an output folder name, and a scan mode. It handles the rest:

- **Basic** — TCP and UDP scan with service versions, then weak-password testing
  on any login services it finds.
- **Full** — same as Basic, plus NSE vulnerability scripts and Searchsploit
  lookups.

Everything except the input is automated. Raw output from each tool is saved to
the output folder, a summary is printed at the end, and the folder is zipped.

## Requirements

- Python 3
- nmap, hydra, searchsploit (all come with Kali)

## Usage

```bash
sudo ./PTscriptV1.py
```

It'll ask for:

1. Target — a host or range (`192.168.1.10`, `192.168.1.0/24`)
2. Output folder name
3. Mode — basic or full
4. Wordlist — the built-in `passlist.txt` or your own file
5. Username to try against login services

## Notes on how it's built

- Tools are run through `subprocess` with the command built as a list, not a
  shell string. That way the target (which comes from user input) can't enter extra commands.
- Each tool's output is parsed once into dicts (port/service/version, and
  service/port/login/password for cracked logins). The rest of the script works
  off those instead of re-reading the raw text.
- UDP scanning uses `-Pn` so hosts that don't answer ping still get scanned, and
  is capped to the top ports so it doesn't take forever.
- Hydra runs with a 120s timeout. TELNET in particular can hang Hydra (it has no
  clean way to tell success from failure), so the timeout lets the script skip it
  and keep going instead of freezing.

## Output files

- `tcp_scan.txt`, `udp_scan.txt` — nmap output
- `hydra_<service>_<port>.txt` — Hydra output per service
- `nse_scan.txt` — NSE vuln scan (Full only)
- `searchsploit.txt` — exploit matches (Full only)
