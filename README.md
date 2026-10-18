# 41222.py - SMBv2 Protocol Exploit

Full Proof of Concept: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41222.zip

## Overview

This is a Python 3-compatible version of a Python 2 SMBv2 (Server Message Block) protocol exploit script. The original was published as part of the Exploit Database (Exploit-DB Bin-Sploits collection) as reference exploit #41222.

The script implements an SMBv2 server that can negotiate sessions, handle authentication, and trigger a known vulnerability in the Tree Connect request handling. It is intended for security research, penetration testing, and educational purposes only.

## Requirements

- Python 3.x (tested with Python 3.12)
- `socketserver` module (included in Python standard library)
- `collections` module (included in Python standard library)
- The script runs on port 445 (SMB default)

## Dependencies

- Python 3.12 or later
- No third-party packages required (uses only standard library)

> **Note:** The original Python 2 version required the `odict` third-party module. This Python 3 version uses `collections.OrderedDict` which is part of the standard library, so no additional installation is needed.

## Usage

### Windows (PowerShell)
```powershell
python 41222.py --host 192.168.1.100 --port 445
```

### Linux / WSL / macOS
```bash
python3 41222.py --host 192.168.1.100 --port 445
```

## Running Against Metasploitable 2

### Windows (PowerShell)
```powershell
python 41222_metasploitable2.py --host 192.168.200.132
```

### Linux / WSL / macOS
```bash
python3 41222_metasploitable2.py --host 192.168.200.132
```

## File Structure

- `41222.py` - Original Python 2 SMBv2 exploit (converted to Python 3)
- `41222_metasploitable2.py` - SMB PoC for Metasploitable 2 (cross-platform)
- `samba_poc.py` - Simple SMB protocol test server
- `README.md` - This file

## Cross-Platform Compatibility

This project works on:
- **Windows 10/11** (PowerShell / CMD)
- **Linux** (Ubuntu, Debian, Fedora, etc.)
- **macOS** (Big Sur and later)
- **WSL 2** (Windows Subsystem for Linux)

The scripts use only Python 3 standard library modules (`socket`, `struct`, `collections`, `datetime`, `calendar`).

## Prerequisites

- Python 3.12 or later
- No third-party packages required (uses only standard library)
- Admin/root privileges to bind to port 445

## Notes

- **For educational/research purposes only.** This script is a proof-of-concept exploit from the Exploit Database.
- **Do not run against systems you do not own or have explicit permission to test.**
- Only SMBv2 is implemented; SMBv3 and other protocol versions are not supported.
- The Metasploitable 2 VM should have ports 139 and 445 open for SMB traffic.

## Source

Original Exploit-DB entry: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41222.zip

## License

This is a proof-of-concept script from the Exploit Database. Use responsibly and only in authorized environments.