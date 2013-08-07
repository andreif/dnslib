# coding=utf-8
import random
import socket

from .bimap import Bimap
from .bit import get_bits, set_bits
from .buffer import DNSBuffer
from .label import DNSLabel
from .utils import colonized, base64chunked, ts2str, hexchunked, calc_tag

__all__ = 'QTYPE CLASS QR RCODE OPCODE DNSRecord DNSHeader DNSBuffer'.split()

# TODO: redo Bitmap as Enum, move all enums to a separate module
# TODO: this is probably overkill:
QR = Bimap({0: 'QUERY', 1: 'RESPONSE'})

CLASS = Bimap({ 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'})
OPCODE = Bimap({ 0:'QUERY', 1:'IQUERY', 2:'STATUS', 5:'UPDATE' })

# TODO: rename to RRTYPE, TYPE or smth, check RFC
QTYPE = Bimap({1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
                16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
                28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
                37:'CERT', 39:'DNAME', 41:'OPT', 42:'APL', 43:'DS',
                44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
                48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
                55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR',
                252:'AXFR', 255:'*', 32768:'TA', 32769:'DLV'})
RCODE = Bimap({ 0:'None', 1:'Format Error', 2:'Server failure',
                 3:'Name Error', 4:'Not Implemented', 5:'Refused', 6:'YXDOMAIN',
                 7:'YXRRSET', 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'})


# TODO: move to enum
def ensure_rtype(x):
    if isinstance(x, type) and issubclass(x, RD):
        x = x.__name__
    if isinstance(x, basestring):
        x = QTYPE[x]
    return x


class DNSError(Exception):
    pass


# TODO: rename to DNSMessage
class DNSRecord(object):

    @classmethod
    def parse(cls,packet):
        """
        Parse DNS packet data and return DNSRecord instance
        """
        buffer = DNSBuffer(packet)
        header = DNSHeader.parse(buffer)
        questions = []
        rr = []
        ns = []
        ar = []
        for i in range(header.q):
            questions.append(DNSQuestion.parse(buffer))
        for i in range(header.a):
            rr.append(RR.parse(buffer))
        for i in range(header.ns):
            ns.append(RR.parse(buffer))
        for i in range(header.ar):
            ar.append(RR.parse(buffer))
        return cls(header,questions,rr,ns=ns,ar=ar, packet=packet)

    def __init__(self,header=None,questions=None,rr=None,ns=None,ar=None, packet=None):
        self.packet = packet
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.rr = rr or []
        self.ns = ns or []
        self.ar = ar or []
        self.set_header_qa()

    def add_question(self,q):
        self.questions.append(q)
        self.set_header_qa()

    def add_answer(self,rr):
        self.rr.append(rr)
        self.set_header_qa()

    def add_ns(self,ns):
        self.ns.append(ns)
        self.set_header_qa()

    def add_ar(self,ar):
        self.ar.append(ar)
        self.set_header_qa()

    def has(self, rtype):
        rtype = ensure_rtype(rtype)
        rrs = self.rr + self.ns + self.ar
        for rr in rrs:
            if rr.rtype == rtype:
                return True

    def set_header_qa(self):
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.ns = len(self.ns)
        self.header.ar = len(self.ar)

    # Shortcut to get first question
    def get_q(self):
        return self.questions[0]
    q = property(get_q)

    # Shortcut to get first answer
    def get_a(self):
        return self.rr[0]
    a = property(get_a)

    def pack(self):
        self.set_header_qa()
        buffer = DNSBuffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for ns in self.ns:
            ns.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

    def send(self,dest,port=53):
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto(self.pack(),(dest,port))
        response,server = sock.recvfrom(8192)
        sock.close()
        return DNSRecord.parse(response)
        
    def __str__(self):
        sections = [ str(self.header) ]
        sections.extend([str(q) for q in self.questions])
        sections.extend([str(rr) for rr in self.rr])
        sections.extend([str(rr) for rr in self.ns])
        sections.extend([str(rr) for rr in self.ar])
        return "\n".join(sections)


class DNSHeader(object):

    @classmethod
    def parse(cls,buffer):
        (id,bitmap,q,a,ns,ar) = buffer.unpack("!HHHHHH")
        return cls(id,bitmap,q,a,ns,ar)

    def __init__(self,id=None,bitmap=None,q=0,a=0,ns=0,ar=0,**args):
        if id is None:
            self.id = random.randint(0,65535)
        else:
            self.id = id 
        if bitmap is None:
            self.bitmap = 0
            self.rd = 1
        else:
            self.bitmap = bitmap
        self.q = q
        self.a = a
        self.ns = ns
        self.ar = ar
        for k,v in args.items():
            if k.lower() == "qr":
                self.qr = v
            elif k.lower() == "opcode":
                self.opcode = v
            elif k.lower() == "aa":
                self.aa = v
            elif k.lower() == "tc":
                self.tc = v
            elif k.lower() == "rd":
                self.rd = v
            elif k.lower() == "ra":
                self.ra = v
            elif k.lower() == "rcode":
                self.rcode = v
    
    def get_qr(self):
        return get_bits(self.bitmap,15)

    def set_qr(self,val):
        self.bitmap = set_bits(self.bitmap,val,15)

    qr = property(get_qr,set_qr)

    def get_opcode(self):
        return get_bits(self.bitmap,11,4)

    def set_opcode(self,val):
        self.bitmap = set_bits(self.bitmap,val,11,4)

    opcode = property(get_opcode,set_opcode)

    def get_aa(self):
        return get_bits(self.bitmap,10)

    def set_aa(self,val):
        self.bitmap = set_bits(self.bitmap,val,10)

    aa = property(get_aa,set_aa)
        
    def get_tc(self):
        return get_bits(self.bitmap,9)

    def set_tc(self,val):
        self.bitmap = set_bits(self.bitmap,val,9)

    tc = property(get_tc,set_tc)
        
    def get_rd(self):
        return get_bits(self.bitmap,8)

    def set_rd(self,val):
        self.bitmap = set_bits(self.bitmap,val,8)

    rd = property(get_rd,set_rd)
        
    def get_ra(self):
        return get_bits(self.bitmap,7)

    def set_ra(self,val):
        self.bitmap = set_bits(self.bitmap,val,7)

    ra = property(get_ra,set_ra)

    def get_rcode(self):
        return get_bits(self.bitmap,0,4)

    def set_rcode(self,val):
        self.bitmap = set_bits(self.bitmap,val,0,4)

    rcode = property(get_rcode,set_rcode)

    def pack(self,buffer):
        buffer.pack("!HHHHHH",self.id,self.bitmap,self.q,self.a,self.ns,self.ar)

    def __str__(self):
        f = [ self.aa and 'AA', 
              self.tc and 'TC', 
              self.rd and 'RD', 
              self.ra and 'RA' ] 
        if OPCODE[self.opcode] == 'UPDATE':
            f1='zo'
            f2='pr'
            f3='up'
            f4='ad'
        else:
            f1='q'
            f2='a'
            f3='ns'
            f4='ar'
        return "<DNS Header: id=0x%x type=%s opcode=%s flags=%s " \
                            "rcode=%s %s=%d %s=%d %s=%d %s=%d>" % ( 
                    self.id,
                    QR[self.qr],
                    OPCODE[self.opcode],
                    ",".join(filter(None,f)),
                    RCODE[self.rcode],
                    f1, self.q, f2, self.a, f3, self.ns, f4, self.ar )


class DNSQuestion(object):
    
    @classmethod
    def parse(cls,buffer):
        qname = buffer.decode_name()
        qtype,qclass = buffer.unpack("!HH")
        return cls(qname,qtype,qclass)

    def __init__(self,qname=[],qtype=1,qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def set_qname(self, qname):
        self._qname = DNSLabel(qname)

    def get_qname(self):
        return self._qname

    qname = property(get_qname,set_qname)

    def pack(self,buffer):
        buffer.encode_name(self.qname)
        buffer.pack("!HH",self.qtype,self.qclass)

    def __str__(self):
        return "<DNS Question: %r qtype=%s qclass=%s>" % (
                    self.qname, QTYPE[self.qtype], CLASS[self.qclass])
            
class EDNSOption(object):

    def __init__(self,code,data):
        self.code = code
        self.data = data

    def __str__(self):
        return "<EDNS Option: Code=%d Data=%s>" % (self.code,self.data)


class RR(object):

    @classmethod
    def parse(cls,buffer):
        rname = buffer.decode_name()
        rtype,rclass,ttl,rdlength = buffer.unpack("!HHIH")
        if rtype == QTYPE.OPT:
            rdata = OPT.parse(buffer, rdlength)
            do = (ttl >> 15) & 1
            return OptRR(udp_payload=rclass, do=do, rdata=rdata)
        else:
            if rdlength:
                rdata = globals().get(QTYPE[rtype], RD).parse(buffer,rdlength)
            else:
                rdata = ''
            return cls(rname, rtype, rclass, ttl, rdata)

    def __init__(self, rname=[], rtype=None, rclass=1, ttl=0, rdata=None):
        self.rname = rname
        if issubclass(type(rdata), RD):
            self.rtype = ensure_rtype(type(rdata))
        else:
            self.rtype = ensure_rtype(rtype)
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def set_rname(self,rname):
        self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self, buffer, allow_cache=True):
        buffer.encode_name(self.rname, allow_cache=allow_cache)
        buffer.pack("!HHI",self.rtype,self.rclass,self.ttl)
        rdlength_ptr = buffer.offset
        buffer.pack("!H",0)
        start = buffer.offset
        self.rdata.pack(buffer, allow_cache=allow_cache)
        end = buffer.offset
        buffer.update(rdlength_ptr,"!H",end-start)

    def packed(self):
        b = DNSBuffer()
        self.pack(b)
        return b.data

    def __str__(self):
        return "<DNS RR: %r rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
                    self.rname, QTYPE[self.rtype], CLASS[self.rclass], 
                    self.ttl, self.rdata)

    def __repr__(self):
        return super(self.__class__, self).__repr__().replace('.RR', '.RR ' + QTYPE[self.rtype])


class OptRR(RR):

    def __init__(self, udp_payload=4096, do=1, rdata=None):
        self.rname = ''
        self.rtype = QTYPE.OPT
        self.rclass = udp_payload
        self.ttl = do << 15
        self.rdata = rdata

    @property
    def flag_do(self):
        return (self.ttl >> 15) & 1

    @property
    def udp_payload(self):
        return self.rclass

    def __str__(self):
        return ("<DNS OPT RR: EDNS(0) rtype=OPT pl=%s DO=%d options=%s>\n%s" % (
            self.rclass, self.flag_do, len(self.rdata.options), str(self.rdata))).strip()


# TODO: rename to RDATA
class RD(object):

    @classmethod
    def parse(cls,buffer,length):
        data = buffer.get(length)
        return cls(data)

    def __init__(self,data=""):
        self.data = data

    def pack(self, buffer, allow_cache=True):
        buffer.append(self.data)

    def __str__(self):
        return self.data.encode("hex")

    def packed(self):
        buf = DNSBuffer()
        self.pack(buf)
        return buf.data


class TXT(RD):

    @classmethod
    def parse(cls,buffer,length):
        (txtlength,) = buffer.unpack("!B")
        # First byte is TXT length (not in RFC?)
        if txtlength < length:
            data = buffer.get(txtlength)
        else:
            raise DNSError("Invalid TXT record: length (%d) > RD length (%d)" % 
                                    (txtlength,length))
        return cls(data)

    def pack(self, buffer, allow_cache=True):
        if len(self.data) > 255:
            raise DNSError("TXT record too long: %s" % self.data)
        buffer.pack("!B",len(self.data))
        buffer.append(self.data)

    def __str__(self):
        return str(self.data)


class A(RD):

    @classmethod
    def parse(cls,buffer,length):
        ip = buffer.unpack("!BBBB")
        data = "%d.%d.%d.%d" % ip
        return cls(data)

    def pack(self, buffer, allow_cache=True):
        buffer.pack('!BBBB', *map(int, str(self.data).split('.')))

    def __str__(self):
        return str(self.data)


class AAAA(RD):

    """
        Basic support for AAAA record - assumes IPv6 address data is presented
        as a simple tuple of 16 bytes
    """
 
    @classmethod
    def parse(cls,buffer,length):
        data = buffer.unpack("!16B")
        return cls(data)
 
    def pack(self, buffer, allow_cache=True):
        buffer.pack("!16B",*self.data)

    def __str__(self):
        hexes = map('{:02x}'.format, self.data)
        return ':'.join([''.join(hexes[i:i+2]) for i in xrange(0, len(hexes), 2)])

class MX(RD):

    @classmethod
    def parse(cls,buffer,length):
        (preference,) = buffer.unpack("!H")
        mx = buffer.decode_name()
        return cls(mx,preference)

    def __init__(self,mx=[],preference=10):
        self.mx = mx
        self.preference = preference

    def set_mx(self,mx):
        self._mx = DNSLabel(mx)

    def get_mx(self):
        return self._mx

    mx = property(get_mx,set_mx)

    def pack(self, buffer, allow_cache=True):
        buffer.pack("!H",self.preference)
        buffer.encode_name(self.mx, allow_cache=allow_cache)
        
    def __str__(self):
        return "%d:%s" % (self.preference,self.mx)

class CNAME(RD):
        
    @classmethod
    def parse(cls,buffer,length):
        label = buffer.decode_name()
        return cls(label)

    def __init__(self,label=[]):
        self.label = label

    def set_label(self,label):
        self._label = DNSLabel(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self, buffer, allow_cache=True):
        buffer.encode_name(self.label, allow_cache=allow_cache)

    def __str__(self):
        return "%s" % (self.label,)

class PTR(CNAME):
    pass

class NS(CNAME):
    pass

class SOA(RD):
        
    @classmethod
    def parse(cls,buffer,length):
        mname = buffer.decode_name()
        rname = buffer.decode_name()
        times = buffer.unpack("!IIIII")
        return cls(mname,rname,times)

    def __init__(self,mname=[],rname=[],times=None):
        self.mname = mname
        self.rname = rname
        self.times = times or (0,0,0,0,0)

    def set_mname(self,mname):
        self._mname = DNSLabel(mname)

    def get_mname(self):
        return self._mname

    mname = property(get_mname,set_mname)

    def set_rname(self,rname):
        self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self, buffer, allow_cache=True):
        buffer.encode_name(self.mname, allow_cache=allow_cache)
        buffer.encode_name(self.rname, allow_cache=allow_cache)
        buffer.pack("!IIIII", *self.times)

    def __str__(self):
        return "%s:%s:%s" % (self.mname,self.rname,":".join(map(str,self.times)))

class NAPTR(RD):

    def __init__(self,order,preference,flags,service,regexp,replacement=None):
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement or DNSLabel([])

    @classmethod
    def parse(cls, buffer, length):
        order, preference = buffer.unpack('!HH')
        (length,) = buffer.unpack('!B')
        flags = buffer.get(length)
        (length,) = buffer.unpack('!B')
        service = buffer.get(length)
        (length,) = buffer.unpack('!B')
        regexp = buffer.get(length)
        replacement = buffer.decode_name()
        return cls(order, preference, flags, service, regexp, replacement)

    def pack(self, buffer, allow_cache=True):
        buffer.pack('!HH', self.order, self.preference)
        buffer.pack('!B', len(self.flags))
        buffer.append(self.flags)
        buffer.pack('!B', len(self.service))
        buffer.append(self.service)
        buffer.pack('!B', len(self.regexp))
        buffer.append(self.regexp)
        buffer.encode_name(self.replacement, allow_cache=allow_cache)

    def __str__(self):
        return '%d %d "%s" "%s" "%s" %s' %(
            self.order,self.preference,self.flags,
            self.service,self.regexp,self.replacement or '.'
        )


class OPT(RD):

    @classmethod
    def parse(cls, buffer, length):
        options = []
        while length > 4:
            opt_code, opt_length = buffer.unpack("!HH")
            length -= 4
            opt_data = buffer.get(opt_length)
            length -= opt_length
            options.append(EDNSOption(opt_code, opt_data))
        if length:
            raise Exception("Remaining OPT data: %s" % buffer.get(length).encode('hex'))
        return cls(options=options)

    def __init__(self, options=()):
        self.options = options

    def pack(self, buffer, allow_cache=True):
        for opt in self.options:
            buffer.pack("!HH", opt.code, len(opt.data))
            buffer.append(opt.data)

    def __str__(self):
        return " ".join((str(opt) for opt in self.options))


class DNSKEY(RD):

    def __init__(self, zk=1, sep=0, ptc=3, alg=8, key=None):
        self.zk = bool(zk)  # Zone Key flag
        self.sep = bool(sep)  # Secure Entry Point flag
        self.ptc = ptc  # Protocol Field, MUST have value 3, see http://tools.ietf.org/html/rfc4034#section-2.1.2
        self.alg = alg  # Algorithm field
        self.key = key  # Public key

    @classmethod
    def parse(cls, buffer, length):
        flags, ptc, alg = buffer.unpack("!HBB")
        length -= 4
        zk = (flags >> 8) & 1
        sep = flags & 1
        key = buffer.get(length)
        return cls(zk=zk, sep=sep, ptc=ptc, alg=alg, key=key)

    @property
    def flags(self):
        return (bool(self.zk) << 8) + bool(self.sep)

    def pack(self, buffer, allow_cache=True):
        buffer.pack("!HBB", self.flags, self.ptc, self.alg)
        buffer.append(self.key)

    def __str__(self):
        return colonized(self.flags, self.ptc, self.alg, base64chunked(self.key), calc_tag(self))


class RRSIG(RD):

    def __init__(self, tc, alg, lbs, ttl, exp, inc, tag, name, sig=''):
        self.tc = tc  # Type Covered field
        self.alg = alg  # Algorithm Number field
        self.lbs = lbs  # Labels field
        self.ttl = ttl  # Original TTL field
        self.exp = exp  # Signature Expiration field
        self.inc = inc  # Signature Inception field
        self.tag = tag  # Key Tag field
        self.name = name  # Signer's Name field
        self.sig = sig  # Signature field

    @classmethod
    def parse(cls, buffer, length):
        tc, alg, lbs, ttl = buffer.unpack("!HBBI")
        length -= 2 + 1 + 1 + 4
        exp, inc, tag = buffer.unpack("!IIH")
        length -= 4 + 4 + 2
        name = buffer.decode_name()
        length -= len(name) + 2
        sig = buffer.get(length)
        return cls(tc=tc, alg=alg, lbs=lbs, ttl=ttl, exp=exp, inc=inc, tag=tag, name=name, sig=sig)

    def pack(self, buffer, with_sig=True, allow_cache=True):
        buffer.pack("!HBBI", self.tc, self.alg, self.lbs, self.ttl)
        buffer.pack("!IIH", self.exp, self.inc, self.tag)
        buffer.encode_name(self.name, allow_cache=False)
        if with_sig:
            buffer.append(self.sig)

    def __str__(self):
        return colonized(QTYPE[self.tc], self.alg, self.lbs, self.ttl, ts2str(self.exp), ts2str(self.inc),
                         self.tag, self.name, base64chunked(self.sig))


class DS(RD):

    def __init__(self, key_tag, algorithm=8, digest_type=2, digest=None):
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type  # digest type
        self.digest = digest

    @classmethod
    def parse(cls, buffer, length):
        tag, alg, dtype = buffer.unpack("!HBB")
        digest_length = {1: 20, 2: 32}[dtype]
        digest = buffer.get(digest_length)
        return cls(tag, alg, dtype, digest)

    def pack(self, buffer, allow_cache=True):
        buffer.pack("!HBB", self.key_tag, self.algorithm, self.digest_type)
        buffer.append(self.digest)

    def __str__(self):
        return colonized(self.key_tag, self.algorithm, self.digest_type, hexchunked(self.digest))
