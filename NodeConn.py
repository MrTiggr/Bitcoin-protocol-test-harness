#
# Originally based on ArtForz's "Half-a-node" code.
#

import asyncore
import binascii
from Crypto.Hash import SHA256
import cStringIO
import json
import random
import struct
import socket
import sys
import time

def deser_len(f):
    n = struct.unpack("<B", f.read(1))[0]
    if n == 253:
        n = struct.unpack("<H", f.read(2))[0]
    elif n == 254:
        n = struct.unpack("<I", f.read(4))[0]
    elif n == 255:
        n = struct.unpack("<Q", f.read(8))[0]
    return n

def deser_string(f):
    n = deser_len(f)
    return f.read(n)

def ser_len(n):
    if n < 253:
        return chr(n)
    elif n < 0x10000:
        return chr(253) + struct.pack("<H", n)
    elif n < 0x100000000L:
        return chr(254) + struct.pack("<I", n)
    return chr(255) + struct.pack("<Q", n)

def ser_string(s):
    return ser_len(len(s))+s

def deser_uint256(f):
    r = 0L
    for i in xrange(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r

def ser_uint256(u):
    rs = ""
    for i in xrange(8):
        rs += struct.pack("<I", u & 0xFFFFFFFFL)
        u >>= 32
    return rs

def uint256_from_str(s):
    r = 0L
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in xrange(8):
        r += t[i] << (i * 32)
    return r

def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFFL) << (8 * (nbytes - 3))
    return v

def to_json(type, value):
    if type == "string" : return value
    elif type == "x" :
        return value.encode('hex_codec')
    elif type == "u256" :
        return "%.064x"%value
    elif type in ( "i32", "u32", "i64", "u64" ): return str(value)
    elif type in ( "addr", ) : return repr(value)
    elif type in ( "tx", "txin", "txout" ) :
        return [ to_json(type, getattr(value,field)) for (field,type) in value.fields ]
    elif isinstance(type, list):
        result = []
        for (i,item) in enumerate(value):
            t = type[i%len(type)]
            if isinstance(t, tuple): # Either [ "type", "type" ] or [ ("name","type"),("name","type")]
                result.append(to_json(t[1], item))
            else:
                result.append(to_json(t, item))
        return result
    raise ValueError("unknown type: "+repr(type))
        
def from_json(type, value, callback=None):
    try:
        if type == "string" : return value
        elif type == "x" :
            return value.decode('hex_codec')
        elif type in ( "i32", "u32", "i64", "u64" ) : return int(value)
        elif type == "u256" :
            return long(value, 16)
        elif type == "addr": return CAddress.from_repr(value)
        elif type == "tx": return CTransaction.from_repr(value)
        elif type == "txin": return CTxIn.from_repr(value)
        elif type == "txout": return CTxOut.from_repr(value)
        elif isinstance(type, list):
            result = []
            for (i,item) in enumerate(value):
                t = type[i%len(type)]
                if isinstance(t, tuple):
                    result.append(from_json(t[1], item, callback))
                else:
                    result.append(from_json(t, item, callback))
            return result
        raise ValueError("unknown type: "+repr(type))
    except ValueError:
        if callback is not None:
            result = callback(type, value)
            if result is not None: return result
        raise

def serialize_val(type, value):
    if type == "string" : return ser_string(value)
    elif type == "x" : return ser_string(value)
    elif type ==  "i32" : return struct.pack("<i", int(value))
    elif type ==  "u32" : return struct.pack("<I", int(value))
    elif type ==  "i64" : return struct.pack("<q", int(value))
    elif type ==  "u64" : return struct.pack("<Q", int(value))
    elif type ==  "u256" : return ser_uint256(value)
    elif type == "addr": return value.serialize()
    elif type == "tx": return value.serialize()
    elif type == "txin": return value.serialize()
    elif type == "txout": return value.serialize()
    elif isinstance(type, list):
        result = ser_len(len(value)/len(type))
        for (i,v) in enumerate(value):
            t = type[i%len(type)]
            if isinstance(t, tuple):
                result += serialize_val(t[1], v)
            else:
                result += serialize_val(t, v)
        return result
    import pdb; pdb.set_trace()
    raise ValueError("unknown type: "+repr(type))

def deserialize_val(type, f):
    if type == "string" : return deser_string(f)
    elif type == "x" : return deser_string(f)
    elif type ==  "i32" : return struct.unpack("<i", f.read(4))[0]
    elif type ==  "u32" : return struct.unpack("<I", f.read(4))[0]
    elif type ==  "i64" : return struct.unpack("<q", f.read(8))[0]
    elif type ==  "u64" : return struct.unpack("<Q", f.read(8))[0]
    elif type ==  "u256" : return deser_uint256(f)
    elif type == "tx":
        t = CTransaction()
        t.deserialize(f)
        return t
    elif type == "txin":
        t = CTxIn()
        t.deserialize(f)
        return t
    elif type == "txout":
        t = CTxOut()
        t.deserialize(f)
        return t
    elif type == "addr":
        t = CAddress()
        t.deserialize(f)
        return t
    elif isinstance(type, list):
        result = [ ]
        n = deser_len(f)
        for i in xrange(n*len(type)):
            t = type[i%len(type)]
            if isinstance(t, tuple):
                result.append(deserialize_val(t[1], f))
            else:
                result.append(deserialize_val(t, f))
        return result
    import pdb; pdb.set_trace()
    raise ValueError("unknown type: "+repr(type))

class serializable(object):
    """ base class with common code for serializing/deserializing
        as either bitcoin binary format or JSON
    """
    def __init__(self, command, fields):
        self.command = command
        self.fields = fields

    def serialize(self):
        r = ""
        for (field, type) in self.fields:
            r += serialize_val(type, getattr(self, field))
        return r

    def deserialize(self, f):
        for (field, type) in self.fields:
            setattr(self, field, deserialize_val(type, f))

    def __repr__(self):
        f = [ to_json(type, getattr(self,field)) for (field,type) in self.fields ]
        d = { self.command : f }
        return json.dumps(d)

    def from_repr(self, string, callback=None):
        d = json.loads(string)
        if not self.command in d:
            raise ValueError("bad JSON message: "+string)
        fields = d[self.command]
        self.from_array(fields, callback)

    def from_array(self, fields, callback=None):
        for (i, value) in enumerate(fields):
            setattr(self, self.fields[i][0], from_json(self.fields[i][1], value, callback))

class CAddress(object):
    def __init__(self):
        self.nServices = 1
        self.pchReserved = "\x00" * 10 + "\xff" * 2
        self.ip = "0.0.0.0"
        self.port = 0
    def deserialize(self, f):
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.pchReserved = f.read(12)
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(">H", f.read(2))[0]
    def serialize(self):
        r = ""
        r += struct.pack("<Q", self.nServices)
        r += self.pchReserved
        r += socket.inet_aton(self.ip)
        r += struct.pack(">H", self.port)
        return r
    def __repr__(self):
        return "%i:%s:%i" % (self.nServices, self.ip, self.port)

    def from_repr(string):
        (services, ip, port) = string.split(":", 2)
        result = CAddress()
        result.services = int(services)
        result.ip = ip
        result.port = int(port)
        return result

class CTxIn(serializable):
    fields = [ ("hash","u256"), ("n","u32"), 
               ("scriptSig","x"), ("nSequence","u32"),
             ]
    def __init__(self):
        serializable.__init__(self, "txin", self.fields)
        self.hash = 0
        self.n = 0
        self.scriptSig = ""
        self.nSequence = 0

class CTxOut(serializable):
    fields = [ ("nValue","i64"), ("scriptPubKey","x"),
             ]
    def __init__(self):
        serializable.__init__(self, "txout", self.fields)
        self.nValue = 0
        self.scriptPubKey = ""

class CTransaction(serializable):
    fields = [ ("nVersion","i32"), ("vin",["txin"]),
               ("vout",["txout"]), ("nLockTime","u32"),
               ]
    def __init__(self):
        serializable.__init__(self, "tx", self.fields)
        self.nVersion = 1
        self.vin = []
        self.vout = []
        self.nLockTime = 0
        self.sha256 = None
    def calc_sha256(self):
        if self.sha256 is None:
            self.sha256 = uint256_from_str(SHA256.new(SHA256.new(self.serialize()).digest()).digest())
    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000L * 100000000L:
                return False
        return True


class msg_version(serializable):
    fields = [ ("nVersion","i32"), ("nServices","u64"),
               ("nTime", "i64"), ("addrTo", "addr"),
               ("addrFrom", "addr"), ("nNonce", "u64"),
               ("strSubVer", "string"), ("nStartingHeight", "i32"), ]
    def __init__(self, version=0):
        serializable.__init__(self, "version", self.fields)
        self.nVersion = version
        self.nServices = 1
        self.nTime = int(time.time())
        self.addrTo = CAddress()
        self.addrFrom = CAddress()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = ""
        self.nStartingHeight = -1
    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        if self.nVersion == 10300:
            self.nVersion = 300
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.nTime = struct.unpack("<q", f.read(8))[0]
        self.addrTo = CAddress()
        self.addrTo.deserialize(f)
        if self.nVersion >= 106:
            self.addrFrom = CAddress()
            self.addrFrom.deserialize(f)
            self.nNonce = struct.unpack("<Q", f.read(8))[0]
            self.strSubVer = deser_string(f)
            if self.nVersion >= 209:
                self.nStartingHeight = struct.unpack("<i", f.read(4))[0]
            else:
                self.nStartingHeight = None
        else:
            self.addrFrom = None
            self.nNonce = None
            self.strSubVer = None
            self.nStartingHeight = None

class msg_verack(serializable):
    fields = []
    def __init__(self):
        serializable.__init__(self, "verack", self.fields)

class msg_addr(serializable):
    fields = [ ("addrs",["addr"]) ]
    def __init__(self):
        serializable.__init__(self, "addr", self.fields)
        self.addrs = []

class msg_inv(serializable):
    fields = [ ("inv",["i32","u256"]) ]
    def __init__(self):
        serializable.__init__(self, "inv", self.fields)
        self.inv = []

class msg_getdata(serializable):
    fields = [ ("inv",[ "i32", "u256" ]) ]
    def __init__(self):
        serializable.__init__(self, "getdata", self.fields)
        self.inv = []

class msg_getblocks(serializable):
    fields = [ ("nVersion","i32"), ("locator",[ "u256" ]), ("hashstop", "u256") ]
    def __init__(self, version=1):
        serializable.__init__(self, "getblocks", self.fields)
        self.nVersion = version
        self.locator = []
        self.hashstop = 0L

class msg_block(serializable):
    fields = [ ("nVersion","i32"), ("hashPrevBlock","u256"), 
               ("hashMerkleRoot","u256"), ("nTime","u32"), 
               ("nBits","u32"), ("nNonce","u32"), 
               ("vtx",[ "tx" ]), ]
    def __init__(self):
        serializable.__init__(self, "block", self.fields)
        self.nVersion = 1
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.vtx = []
        self.sha256 = None

    def calc_sha256(self):
        if self.sha256 is None:
            r = ""
            r += struct.pack("<i", self.nVersion)
            r += ser_uint256(self.hashPrevBlock)
            r += ser_uint256(self.hashMerkleRoot)
            r += struct.pack("<I", self.nTime)
            r += struct.pack("<I", self.nBits)
            r += struct.pack("<I", self.nNonce)
            self.sha256 = uint256_from_str(SHA256.new(SHA256.new(r).digest()).digest())
        return self.sha256

    def is_valid(self):
        self.calc_sha256()
        target = uint256_from_compact(self.nBits)
        if self.sha256 > target:
            return False
        hashes = []
        for tx in self.vtx:
            if not tx.is_valid():
                return False
            tx.calc_sha256()
            hashes.append(ser_uint256(tx.sha256))
        while len(hashes) > 1:
            newhashes = []
            for i in xrange(0, len(hashes), 2):
                i2 = min(i+1, len(hashes)-1)
                newhashes.append(SHA256.new(SHA256.new(hashes[i] + hashes[i2]).digest()).digest())
            hashes = newhashes
        if uint256_from_str(hashes[0]) != self.hashMerkleRoot:
            return False
        return True

class msg_getheaders(serializable):
    fields = [ ("nVersion","i32"), ("locator",[ "u256" ]), ("hashstop", "u256") ]
    def __init__(self, version=1):
        serializable.__init__(self, "getheaders", self.fields)
        self.nVersion = version
        self.locator = []
        self.hashstop = 0L

class msg_headers(serializable):
    fields = [ ("nVersion","i32"), ("hashPrevBlock","u256"), 
               ("hashMerkleRoot","u256"), ("nTime","u32"), 
               ("nBits","u32"), ("nNonce","u32"), 
               ("vtx",[ "tx" ]), ]
    def __init__(self):
        serializable.__init__(self, "headers", self.fields)
        self.nVersion = 1
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.vtx = []

class msg_tx(serializable):
    fields = [ ("tx","tx") ]
    def __init__(self):
        serializable.__init__(self, "tx", self.fields)
        self.tx = CTransaction()

class msg_getaddr(serializable):
    fields = []
    def __init__(self):
        serializable.__init__(self, "getaddr", self.fields)

# Unsupported pay-by-ip stuff:
#msg_checkorder
#msg_submitorder
#msg_reply

class msg_ping(serializable):
    fields = []
    def __init__(self):
        serializable.__init__(self, "ping", self.fields)



class NodeConn(asyncore.dispatcher):
    """Handle a connection to a bitcoin-speaking node"""
    messagemap = {
        "version": msg_version,
        "verack": msg_verack,
        "addr": msg_addr,
        "inv": msg_inv,
        "getdata": msg_getdata,
        "getblocks": msg_getblocks,
        "getheaders": msg_getheaders,
        "tx": msg_tx,
        "block": msg_block,
        "headers": msg_headers,
        "getaddr": msg_getaddr,
        "ping": msg_ping
    }
    def __init__(self, dstaddr, dstport, version, testnet, recv_callback):
        asyncore.dispatcher.__init__(self)
        self.dstaddr = dstaddr
        self.dstport = dstport
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sendbuf = ""
        self.recvbuf = ""
        self.recv_callback = recv_callback
        self.ver_send = version
        self.ver_recv = 0
        self.state = "connecting"
        self.verbose = False
        self.handshaking = False
        if not testnet:
            self.message_header = b'\xf9\xbe\xb4\xd9'
            self.genesis_value = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fL
        else:
            self.message_header = b'\xfa\xbf\xb5\xda'
            self.genesis_value = 0x00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008L

        try:
            self.connect((dstaddr, dstport))
        except:
            self.handle_close()

    def version_handshake(self):
        t = msg_version(self.ver_send)
        t.addrTo.ip = self.dstaddr
        t.addrTo.port = self.dstport
        t.addrFrom.ip = "0.0.0.0"
        t.addrFrom.port = 0
        t.nStartingHeight = -1
        self.send_message(t)
        self.handshaking = True

    def handle_connect(self):
        self.state = "connected"

    def handle_close(self):
        self.state = "closed"
        self.recvbuf = ""
        self.sendbuf = ""
        try:
            self.close()
        except:
            pass
    def handle_read(self):
        try:
            t = self.recv(8192)
        except:
            self.handle_close()
            return
        if len(t) == 0:
            self.handle_close()
            return
        self.recvbuf += t
        self.got_data()
    def readable(self):
        return True
    def writable(self):
        return (len(self.sendbuf) > 0)
    def handle_write(self):
        try:
            sent = self.send(self.sendbuf)
        except:
            self.handle_close()
            return
        self.sendbuf = self.sendbuf[sent:]
    def got_data(self):
        while True:
            if len(self.recvbuf) < 4:
                return
            if self.recvbuf[:4] != self.message_header:
                raise ValueError("got garbage %s" % repr(self.recvbuf))
            if self.ver_recv < 209:
                if len(self.recvbuf) < 4 + 12 + 4:
                    return
                command = self.recvbuf[4:4+12].split("\x00", 1)[0]
                msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
                checksum = None
                if len(self.recvbuf) < 4 + 12 + 4 + msglen:
                    return
                msg = self.recvbuf[4+12+4:4+12+4+msglen]
                self.recvbuf = self.recvbuf[4+12+4+msglen:]
            else:
                if len(self.recvbuf) < 4 + 12 + 4 + 4:
                    return
                command = self.recvbuf[4:4+12].split("\x00", 1)[0]
                msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
                checksum = self.recvbuf[4+12+4:4+12+4+4]
                if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
                    return
                msg = self.recvbuf[4+12+4+4:4+12+4+4+msglen]
                th = SHA256.new(msg).digest()
                h = SHA256.new(th).digest()
                if checksum != h[:4]:
                    raise ValueError("got bad checksum %s" % repr(self.recvbuf))
                self.recvbuf = self.recvbuf[4+12+4+4+msglen:]
            if command in self.messagemap:
                f = cStringIO.StringIO(msg)
                t = self.messagemap[command]()
                t.deserialize(f)
                self.got_message(t)
            else:
                raise ValueError("UNKNOWN COMMAND "+command+repr(msg))

    def replace_magic_constants(self, type, value):
        if type == "u256" and value == "__GENESIS__":
            return self.genesis_value
        return None

    def send_message(self, message):
        if self.state == "closed":
            return
        if self.verbose:
            print "send %s" % repr(message)
        if hasattr(message, 'serialize'): # msg_ object
            command = message.command
            data = message.serialize()
        else:
            # JSON string or dictionary with JSON-encoded values in it:
            if not isinstance(message, dict): # JSON { "message" : [ fields ] }
                message = json.loads(message)
            command = message.keys()[0]
            obj = self.messagemap[command]()
            obj.from_array(message[command], self.replace_magic_constants)
            data = obj.serialize()

        tmsg = self.message_header
        tmsg += bytes(command)
        tmsg += b"\x00" * (12 - len(command))
        tmsg += struct.pack("<I", len(data))
        if self.ver_recv >= 209:
            th = SHA256.new(data).digest()
            h = SHA256.new(th).digest()
            tmsg += h[:4]
        tmsg += data
        self.sendbuf += tmsg

    def got_message(self, message):
        if self.verbose:
            print "recv %s" % repr(message)
        
        if self.handshaking:
            if message.command == "version":
                self.ver_send = min(self.ver_send, message.nVersion)
                if message.nVersion < 209:
                    self.ver_recv = self.ver_send
                else:
                    self.send_message(msg_verack())
            elif message.command == "verack":
                self.ver_recv = self.ver_send
                self.handshaking = False

        self.recv_callback(self, message)
