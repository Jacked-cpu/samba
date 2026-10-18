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

```bash
python3 41222.py
```

The script starts an SMBv2 server listening on port 445. It handles the following SMBv2 protocol phases:

1. **Negotiate** - Protocol negotiation (SMBv2)
2. **Session Setup** - Authentication and session establishment
3. **Tree Connect** - File/share access (triggers the vulnerability)

## How It Works

### SMBv2 Protocol Flow

The script simulates an SMBv2 server that:

1. **Negotiates Protocol** - Responds to client's SMB negotiate request with SMBv2 dialect
2. **Handles Session Setup** - Processes session setup requests and returns a security challenge
3. **Tree Connect** - Handles Tree Connect requests and triggers a buffer overflow condition

### Key Components

- `Packet` - Base packet class using OrderedDict for SMB2 header fields
- `SMBv2Header` - SMBv2 header structure
- `SMB2NegoAns` - SMBv2 Negotiate Response handler
- `SMB2Session1Data` - SMBv2 Session Setup (security challenge) handler
- `SMB2SessionAcceptData` - SMBv2 Session Accept (authentication success) handler
- `SMB2TreeData` - SMBv2 Tree Connect handler (contains the vulnerability trigger)
- `SMB2` - Main SMBv2 server handler (BaseRequestHandler)

### Vulnerability

The Tree Connect handler contains a bug (marked `#/BUG` in the original) that can be triggered by sending a specially crafted SMBv2 packet with an oversized Data field.

## Important Notes

- **For educational/research purposes only.** This script is a proof-of-concept exploit from the Exploit Database.
- **Do not run against systems you do not own or have explicit permission to test.**
- The script requires **administrator/root privileges** to bind to port 445 (the SMB default port).
- Only SMBv2 is implemented; SMBv3 and other protocol versions are not supported.

## File Contents

- `41222.py` - Python 3-compatible SMBv2 exploit script

## Source

Original Exploit-DB entry: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41222.zip

## License

This is a proof-of-concept script from the Exploit Database. Use responsibly and only in authorized environments.