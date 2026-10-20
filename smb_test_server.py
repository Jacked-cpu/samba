#!/usr/bin/env python3
"""
SMB Test Server - Simple SMB Protocol Server Implementation
===========================================================
Minimal SMB server implementation for testing SMB clients and
understanding the SMB protocol flow. Not an exploit.

This is a minimal implementation for educational/security testing purposes.
It demonstrates the basic SMB protocol handshake and request handling.

NOTICE: This is a test implementation. Use only on isolated networks.

MIT License (simplified)
"""

import socket
import struct
import os
import hashlib
import hmac
import datetime

# ============================================================================
# SMB Protocol Constants
# ============================================================================
SMB_SIGNATURE = b'\xfe\x53\x4d\x42'  # SMB Signature
SMB_PCI_SIZE = 64  # PCI (Protocol Control Information) size

# SMB Commands
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT = 0x75
SMB_COM_LOGOFF = 0x76
SMB_COM_TREE_DISCONNECT = 0x77
SMB_COM_SEARCH = 0x78
SMB_COM_READ = 0x7a
SMB_COM_WRITE = 0x7c
SMB_COM_CLOSE = 0x7d
SMB_COM_CREATE = 0x7f
SMB_COM_DELETE = 0x80

# SMB Packets
SMB_PKT = 0x00  # SMB Packet Format

# Status Codes
STATUS_OK = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0x01010001
STATUS_ACCESS_DENIED = 0xc0000022

# SMB2 Commands
SMB2_OP_LOCKING_ANDX = 0x01
SMB2_OP_CANCEL = 0x02
SMB2_OP_CLOSE = 0x03
SMB2_OP_FIND_CLOSE = 0x04
SMB2_OP_FIND_FIRST = 0x05
SMB2_OP_FIND_NEXT = 0x06
SMB2_OP_FLUSH = 0x07
SMB2_OP_LOCKING_ANDX = 0x08
SMB2_OP_READ = 0x09
SMB2_OP_READ_CANCEL = 0x0A
SMB2_OP_WRITE = 0x0B
SMB2_OP_WRITE_BRAID = 0x0C
SMB2_OP_LOCKING_ANDX = 0x0D
SMB2_OP_QUERY_INFO = 0x0E
SMB2_OP_SET_INFO = 0x0F
SMB2_OP_QUERY_FILE = 0x10
SMB2_OP_SET_FILE = 0x11
SMB2_OP_CLEAR_LOCK = 0x12
SMB2_OP_CREATE = 0x13
SMB2_OP_ECHO = 0x14
SMB2_OP_PING = 0x15
SMB2_OP_FLUSH = 0x16

# ============================================================================
# Packet Classes
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
        total_length = SMB_PCI_SIZE + 4  # header + length field
        for dialect in self.servers:
            total_length += 4 + len(dialect)
        result = struct.pack('<I', total_length)
        result += struct.pack('<I', SMB_COM_NEGOTIATE)
        result += struct.pack('>H', 0)  # error class
        result += struct.pack('H', 0)   # reserved
        result += struct.pack('H', 0)   # flags
        result += struct.pack('H', 0)   # capabilities
        result += struct.pack('I', 0)   # context counts
        result += struct.pack('I', 0)   # total count
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
        total_length = SMB_PCI_SIZE + 4
        for dialect in self.dialects:
            total_length += 4 + len(dialect)
        result = struct.pack('<I', total_length)
        result += struct.pack('<I', SMB_COM_NEGOTIATE)
        result += struct.pack('>H', 0)  # error class
        result += struct.pack('H', 0)   # reserved
        result += struct.pack('H', 0)   # flags
        result += struct.pack('H', 0)   # capabilities
        result += struct.pack('I', 0)   # context counts
        result += struct.pack('I', total_length - SMB_PCI_SIZE - 4)
        result += struct.pack('I', 0)   # aux count
        for dialect in self.dialects:
            result += struct.pack('<I', len(dialect))
            result += dialect
        result += struct.pack('B', 0)   # byte count
        return result

class SMBHeaderSMBCore:
    """SMB Header (Core Portion)"""
    def __init__(self, command, pid=12345, tid=0, offset=0):
        self.command = command
        self.pid_high = (pid >> 16) & 0xFFFF
        self.pid_low = pid & 0xFFFF
        self.pid_high2 = (pid >> 24) & 0xFF
        self.pid_low2 = (pid >> 8) & 0xFF
        self.tid = tid
        self.pid_raw = pid
        self.credit = 0
        self.flags = 0
        self.next = 0
        self.smb2_cmd = command
        self.flags2 = 0
        self.structure_size = 64
        self.pid_raw2 = pid
        self.tid2 = tid
        self.pid2 = pid
        self.session_id = 0
        self.status = 0
        self.credit_request = 0
        self.flags3 = 0
        self.reserved2 = 0
        self.sighash = 0

def create_smb_header(command, pid=12345):
    """Create an SMB header"""
    header = SMBHeader()
    header.command = command
    header.pid = pid
    header.tid = 0
    header.structure_size = 64
    header.flags2 = 0x02  # SMB2
    return header

def smb_pack(header, command, payload=b''):
    """Pack SMB header + command + payload"""
    # Full SMB header (64 bytes minimum)
    smb_header = SMBHeader()
    smb_header.command = command
    smb_header.pid = header.pid
    smb_header.tid = header.tid
    smb_header.structure_size = 64
    smb_header.flags2 = 0x02
    
    # PCI (Protocol Control Information) - first 64 bytes
    pci = struct.pack('<I', smb_header.pid)  # PID
    pci += struct.pack('<I', smb_header.pid_high)
    pci += struct.pack('<I', smb_header.pid_low)
    pci += struct.pack('<I', smb_header.pid_high2)
    pci += struct.pack('<I', smb_header.pid_low2)
    pci += struct.pack('<I', smb_header.tid)
    pci += struct.pack('<I', smb_header.credit)
    pci += struct.pack('<I', smb_header.flags)
    pci += struct.pack('<I', smb_header.next)
    pci += struct.pack('<I', smb_header.pid_raw)
    
    # SMB2 Header (if SMB2)
    if smb_header.flags2 & 0x02:
        pci += struct.pack('<I', smb_header.smb2_cmd)
        pci += struct.pack('<I', smb_header.flags2)
        pci += struct.pack('<I', smb_header.structure_size)
        pci += struct.pack('<I', smb_header.pid_raw2)
        pci += struct.pack('<I', smb_header.tid2)
        pci += struct.pack('<I', smb_header.pid2)
        pci += struct.pack('<I', smb_header.session_id)
        pci += struct.pack('<I', smb_header.status)
        pci += struct.pack('<I', smb_header.credit_request)
        pci += struct.pack('<I', smb_header.flags3)
    
    # Payload (command data)
    payload_data = struct.pack('<I', len(payload))
    payload_data += payload
    
    return pci + payload_data

# ============================================================================
# SMB Server
# ============================================================================

class SMBServer:
    """Simple SMB Protocol Server for testing"""
    
    def __init__(self, host='0.0.0.0', port=445):
        self.host = host
        self.port = port
        self.server_socket = None
        self.connections = []
        
    def start(self):
        """Start the SMB server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[*] SMB PoC Server listening on {self.host}:{self.port}")
        print(f"[*] Ready to accept connections...")
        self.accept_connections()
        
    def accept_connections(self):
        """Accept incoming connections"""
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[*] Connection from {addr[0]}:{addr[1]}")
                self.handle_client(client_socket, addr)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            self.stop()
            
    def handle_client(self, client_socket, addr):
        """Handle a client connection"""
        try:
            client_socket.settimeout(30)
            while True:
                # Receive SMB packet
                data = client_socket.recv(1024)
                if not data:
                    break
                
                # Check if it's an SMB packet
                if len(data) < 64 or data[0:4] != SMB_SIGNATURE:
                    print(f"[!] Invalid SMB packet from {addr}")
                    break
                
                # Parse the SMB header
                packet = self.parse_smb_packet(data)
                print(f"[+] Received command 0x{packet.command:02x} from {addr[0]}")
                
                # Respond based on command
                response = self.process_command(packet, client_socket)
                if response:
                    client_socket.send(response)
                    
        except socket.timeout:
            print(f"[!] Connection timeout from {addr}")
        except Exception as e:
            print(f"[!] Error handling {addr}: {e}")
        finally:
            client_socket.close()
            print(f"[*] Connection closed with {addr}")
            
    def parse_smb_packet(self, data):
        """Parse an SMB packet and return a header object"""
        header = type('Packet', (), {})()
        header.pid = struct.unpack('<I', data[0:4])[0]
        header.pid_high = struct.unpack('<I', data[4:8])[0]
        header.pid_low = struct.unpack('<I', data[8:12])[0]
        header.command = struct.unpack('<I', data[16:20])[0]
        header.tid = struct.unpack('<I', data[24:28])[0]
        header.credit = struct.unpack('<I', data[32:36])[0]
        header.flags = struct.unpack('<I', data[40:44])[0]
        header.next = struct.unpack('<I', data[48:52])[0]
        header.smb2_cmd = struct.unpack('<I', data[56:60])[0]
        
        # Get payload (after PCI)
        payload_offset = 64  # PCI size
        if data[0:4] == SMB_SIGNATURE:
            # SMB2 packet
            payload_offset = 64  # SMB2 header is 64 bytes
            # For SMB2, we need to parse more
            payload_length = struct.unpack('<I', data[60:64])[0] if len(data) > 60 else 0
        else:
            # SMB1 packet
            payload_length = struct.unpack('<I', data[40:44])[0]
        
        # Extract payload
        header.payload = data[payload_offset:64+len(payload)]
        
        return header
        
    def process_command(self, header, client_socket):
        """Process a command and return a response"""
        responses = {
            SMB_COM_NEGOTIATE: self.handle_negotiate,
            SMB_COM_SESSION_SETUP_ANDX: self.handle_session_setup,
            SMB_COM_TREE_CONNECT: self.handle_tree_connect,
            SMB_COM_LOGOFF: self.handle_logoff,
            SMB_COM_TREE_DISCONNECT: self.handle_tree_disconnect,
            SMB_COM_READ: self.handle_read,
            SMB_COM_WRITE: self.handle_write,
            SMB_COM_CLOSE: self.handle_close,
        }
        
        handler = responses.get(header.command, self.handle_unknown)
        return handler(header, client_socket)
        
    def handle_negotiate(self, header, client_socket):
        """Handle SMB Negotiate command"""
        print(f"    [SMB] Negotiate command")
        
        # Prepare negotiate response
        response = smb_pack(
            header, 
            SMB_COM_NEGOTIATE,
            b''  # Negotiate response payload (dialects handled separately)
        )
        
        # Build SMB2 negotiate response
        response = SMBNegotiateResponse().pack()
        response += b'\x00'  # Null byte for byte count
        
        print(f"    [SMB] Sent negotiate response (SMB2)")
        return response
        
    def handle_session_setup(self, header, client_socket):
        """Handle SMB Session Setup command"""
        print(f"    [SMB] Session Setup command")
        
        # Check for NTLMSSP authentication
        data = header.payload
        if data[:8] == b'NTLMSSP':
            print(f"    [SMB] NTLMSSP authentication")
            # Generate a simple challenge
            challenge = b'\x82\x21\x32\x14\x51\x46\xe2\x83' + b'\x00' * 8
            return response_session_setup_success(challenge)
        else:
            print(f"    [SMB] Basic auth")
            return response_session_setup_success(b'')
            
    def handle_tree_connect(self, header, client_socket):
        """Handle SMB Tree Connect command"""
        print(f"    [SMB] Tree Connect command")
        
        data = header.payload
        # Extract path from tree connect request
        path = data[33:65].decode('utf-16le', errors='ignore').strip('\x00')
        print(f"    [SMB] Tree Connect path: {path}")
        
        # Simple response
        return response_tree_connect_success()
        
    def handle_logoff(self, header, client_socket):
        """Handle SMB Logoff command"""
        print(f"    [SMB] Logoff command")
        return b''
        
    def handle_tree_disconnect(self, header, client_socket):
        """Handle SMB Tree Disconnect command"""
        print(f"    [SMB] Tree Disconnect command")
        return b''
        
    def handle_read(self, header, client_socket):
        """Handle SMB Read command"""
        print(f"    [SMB] Read command (offset: {struct.unpack('<Q', header.payload[0:8])[0]})")
        # Return empty file data
        return b''
        
    def handle_write(self, header, client_socket):
        """Handle SMB Write command"""
        print(f"    [SMB] Write command (offset: {struct.unpack('<Q', header.payload[0:8])[0]})")
        print(f"    [SMB] Data length: {len(header.payload)}")
        # Return success
        return b''
        
    def handle_close(self, header, client_socket):
        """Handle SMB Close command"""
        print(f"    [SMB] Close command")
        return b''
        
    def handle_unknown(self, header, client_socket):
        """Handle unknown commands"""
        print(f"    [SMB] Unknown command 0x{header.command:02x}")
        return b''
        
    def stop(self):
        """Stop the SMB server"""
        if self.server_socket:
            self.server_socket.close()
            print("[*] Server stopped")

# ============================================================================
# Response Builders
# ============================================================================

def response_session_setup_success(challenge=b''):
    """Build a session setup success response"""
    # Minimal response
    return smb_pack(
        create_smb_header(SMB_COM_SESSION_SETUP_ANDX),
        SMB_COM_SESSION_SETUP_ANDX,
        challenge
    )

def response_tree_connect_success():
    """Build a tree connect success response"""
    return smb_pack(
        create_smb_header(SMB_COM_TREE_CONNECT),
        SMB_COM_TREE_CONNECT,
        b'\x00\x00'  # Simple status
    )

def response_negotiate_success():
    """Build a negotiate success response"""
    return SMBNegotiateResponse().pack() + b'\x00'

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    import sys
    
    # Parse arguments
    host = '0.0.0.0'
    port = 445
    
    for i, arg in enumerate(sys.argv[1:]):
        if arg == '--host' or arg == '-h':
            host = sys.argv[i+2]
        elif arg == '--port' or arg == '-p':
            port = int(sys.argv[i+2])
        elif arg == '--help' or arg == '-h':
            print("Usage: smb_poc.py [options]")
            print("Options:")
            print("  --host HOST    Bind to HOST (default: 0.0.0.0)")
            print("  --port PORT    Listen on PORT (default: 445)")
            print("  --help         Show this help message")
            sys.exit(0)
    
    # Start server
    server = SMBServer(host, port)
    server.start()