# -*- coding: utf-8 -*-

import base64
import random
import socket
import datetime

from bit import get_bits,set_bits
from bimap import Bimap
from label import DNSLabel, DNSBuffer

QTYPE =  Bimap({1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
                16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
                28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
                37:'CERT', 39:'DNAME', 41:'OPT', 42:'APL', 43:'DS',
                44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
                48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
                55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR',
                252:'AXFR', 255:'*', 32768:'TA', 32769:'DLV'})
CLASS =  Bimap({ 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'})
QR =     Bimap({ 0:'QUERY', 1:'RESPONSE' })
RCODE =  Bimap({ 0:'None', 1:'Format Error', 2:'Server failure', 
                 3:'Name Error', 4:'Not Implemented', 5:'Refused', 6:'YXDOMAIN',
                 7:'YXRRSET', 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'})
OPCODE = Bimap({ 0:'QUERY', 1:'IQUERY', 2:'STATUS', 5:'UPDATE' })

class DNSError(Exception):
    pass

class DNSRecord(object):

    """
    dnslib
    ------

    A simple library to encode/decode DNS wire-format packets. This was originally
    written for a custom nameserver.

    The key classes are:

        * DNSRecord (contains a DNSHeader and one or more DNSQuestion/DNSRR records)
        * DNSHeader 
        * DNSQuestion
        * RR (resource records)
        * RD (resource data - superclass for TXT,A,AAAA,MX,CNAME,PRT,SOA,NAPTR)
        * DNSLabel (envelope for a DNS label)

    The library has (in theory) very rudimentary support for EDNS0 options
    however this has not been tested due to a lack of data (anyone wanting
    to improve support or provide test data please raise an issue)

    Note: In version 0.3 the library was modified to use the DNSLabel class to
    support arbirary DNS labels (as specified in RFC2181) - and specifically
    to allow embedded '.'s. In most cases this is transparent (DNSLabel will
    automatically convert a domain label presented as a dot separated string &
    convert pack to this format when converted to a string) however to get the
    underlying label data (as a tuple) you need to access the DNSLabel.label
    attribute. To specifiy a label to the DNSRecord classes you can either pass
    a DNSLabel object or pass the elements as a list/tuple.

    To decode a DNS packet:

    >>> packet = 'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93'.decode('hex')
    >>> d = DNSRecord.parse(packet)
    >>> print d
    <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=5 ns=0 ar=0>
    <DNS Question: 'www.google.com' qtype=A qclass=IN>
    <DNS RR: 'www.google.com' rtype=CNAME rclass=IN ttl=5 rdata='www.l.google.com'>
    <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.104'>
    <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.99'>
    <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.103'>
    <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.147'>

    To create a DNS Request Packet:

    >>> d = DNSRecord(header=DNSHeader(id=0), q=DNSQuestion("google.com"))
    >>> print d
    <DNS Header: id=0x0 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
    <DNS Question: 'google.com' qtype=A qclass=IN>
    >>> d.pack().encode('hex')
    '00000100000100000000000006676f6f676c6503636f6d0000010001'

    >>> d = DNSRecord(header=DNSHeader(id=0), q=DNSQuestion("google.com",QTYPE.MX))
    >>> print d
    <DNS Header: id=0x0 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
    <DNS Question: 'google.com' qtype=MX qclass=IN>
    >>> d.pack().encode('hex')
    '00000100000100000000000006676f6f676c6503636f6d00000f0001'

    To create a DNS Response Packet:

    >>> d = DNSRecord(DNSHeader(id=0, qr=1,aa=1,ra=1),
    ...               q=DNSQuestion("abc.com"),
    ...               a=RR("abc.com",rdata=A("1.2.3.4")))
    >>> print d
    <DNS Header: id=0x0 type=RESPONSE opcode=QUERY flags=AA,RD,RA rcode=None q=1 a=1 ns=0 ar=0>
    <DNS Question: 'abc.com' qtype=A qclass=IN>
    <DNS RR: 'abc.com' rtype=A rclass=IN ttl=0 rdata='1.2.3.4'>
    >>> d.pack().encode('hex')
    '0000858000010001000000000361626303636f6d0000010001c00c0001000100000000000401020304'

    To create a skeleton reply to a DNS query:

    >>> q = DNSRecord(header=DNSHeader(id=0), q=DNSQuestion("abc.com",QTYPE.CNAME))
    >>> a = q.reply(data="xxx.abc.com")
    >>> print a
    <DNS Header: id=0x0 type=RESPONSE opcode=QUERY flags=AA,RD,RA rcode=None q=1 a=1 ns=0 ar=0>
    <DNS Question: 'abc.com' qtype=CNAME qclass=IN>
    <DNS RR: 'abc.com' rtype=CNAME rclass=IN ttl=0 rdata='xxx.abc.com'>
    >>> a.pack().encode('hex')
    '0000858000010001000000000361626303636f6d0000050001c00c0005000100000000000603787878c00c'

    Add additional RRs:

    >>> a.add_answer(RR('xxx.abc.com',QTYPE.A,rdata=A("1.2.3.4")))
    >>> print a
    <DNS Header: id=0x0 type=RESPONSE opcode=QUERY flags=AA,RD,RA rcode=None q=1 a=2 ns=0 ar=0>
    <DNS Question: 'abc.com' qtype=CNAME qclass=IN>
    <DNS RR: 'abc.com' rtype=CNAME rclass=IN ttl=0 rdata='xxx.abc.com'>
    <DNS RR: 'xxx.abc.com' rtype=A rclass=IN ttl=0 rdata='1.2.3.4'>
    >>> a.pack().encode('hex')[86:]
    'c0250001000100000000000401020304'

    Changelog:

        *   0.1     2010-09-19  Initial Release
        *   0.2     2010-09-22  Minor fixes
        *   0.3     2010-10-02  Add DNSLabel class to support arbitrary labels (embedded '.')
        *   0.4     2012-02-26  Merge with dbslib-circuits
        *   0.5     2012-09-13  Add support for RFC2136 DDNS updates
                                Patch provided by Wesley Shields <wxs@FreeBSD.org> - thanks
        *   0.6     2012-10-20  Basic AAAA support
        *   0.7     2012-10-20  Add initial EDNS0 support (untested)
        *   0.8     2012-11-04  Add support for NAPTR, Authority RR and additional RR
                                Patch provided by Stefan Andersson (https://bitbucket.org/norox) - thanks
        *   0.8.1   2012-11-05  Added NAPTR test case and fixed logic error
                                Patch provided by Stefan Andersson (https://bitbucket.org/norox) - thanks
        *   0.8.2   2012-11-11  Patch to fix IPv6 formatting
                                Patch provided by Torbjörn Lönnemark (https://bitbucket.org/tobbezz) - thanks
        *   0.8.3   2013-04-27  Don't parse rdata if rdlength is 0
                                Patch provided by Wesley Shields <wxs@FreeBSD.org> - thanks

    License:

        *   BSD

    Author:

        *   Paul Chakravarti (paul.chakravarti@gmail.com)

    Master Repository/Issues:

        *   https://bitbucket.org/paulc/dnslib

    """

    version = "0.8.3"

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
        return cls(header,questions,rr,ns=ns,ar=ar)

    def __init__(self,header=None,questions=None,rr=None,q=None,a=None,ns=None,ar=None):
        """
            Create DNSRecord
        """
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.rr = rr or []
        self.ns = ns or []
        self.ar = ar or []
        # Shortcuts to add a single Question/Answer
        if q:
            self.questions.append(q)
        if a:
            self.rr.append(a)
        self.set_header_qa()

    def reply(self,data="",ra=1,aa=1):
        answer = RDMAP.get(QTYPE[self.q.qtype],RD)(data)
        return DNSRecord(DNSHeader(id=self.header.id,bitmap=self.header.bitmap,qr=1,ra=ra,aa=aa),
                         q=self.q,
                         a=RR(self.q.qname,self.q.qtype,rdata=answer))


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

    def set_qname(self,qname):
        self._qname = ensure_label(qname)

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


def ensure_rtype(x):
    if isinstance(x, type) and issubclass(x, RD):
        x = x.__name__
    if isinstance(x, basestring):
        x = QTYPE[x]
    return x


def ensure_label(x):
    if not isinstance(x, DNSLabel):
        x = DNSLabel(x)
    return x


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
                rdata = RDMAP.get(QTYPE[rtype],RD).parse(buffer,rdlength)
            else:
                rdata = ''
            return cls(rname, rtype, rclass, ttl, rdata)

    def __init__(self,rname=[],rtype=1,rclass=1,ttl=0,rdata=None):
        self.rname = rname
        self.rtype = ensure_rtype(rtype)
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def set_rname(self,rname):
        self._rname = ensure_label(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self,buffer):
        buffer.encode_name(self.rname)
        buffer.pack("!HHI",self.rtype,self.rclass,self.ttl)
        rdlength_ptr = buffer.offset
        buffer.pack("!H",0)
        start = buffer.offset
        self.rdata.pack(buffer)
        end = buffer.offset
        buffer.update(rdlength_ptr,"!H",end-start)

    def __str__(self):
        return "<DNS RR: %r rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
                    self.rname, QTYPE[self.rtype], CLASS[self.rclass], 
                    self.ttl, self.rdata)


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

    def pack(self,buffer):
        b = DNSBuffer()
        super(OptRR, self).pack(b)
        buffer.append(b.data[1:])

    def __str__(self):
        return ("<DNS OPT RR: EDNS(0) rtype=OPT pl=%s DO=%d options=%s>\n%s" % (
            self.rclass, self.flag_do, len(self.rdata.options), str(self.rdata))).strip()


class RD(object):

    @classmethod
    def parse(cls,buffer,length):
        data = buffer.get(length)
        return cls(data)

    def __init__(self,data=""):
        self.data = data

    def pack(self,buffer):
        buffer.append(self.data)

    def __str__(self):
        return self.data.encode("hex")


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

    def pack(self,buffer):
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

    def pack(self,buffer):
        buffer.pack("!BBBB",*map(int,self.data.split(".")))

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
 
    def pack(self,buffer):
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
        self._mx = ensure_label(mx)

    def get_mx(self):
        return self._mx

    mx = property(get_mx,set_mx)

    def pack(self,buffer):
        buffer.pack("!H",self.preference)
        buffer.encode_name(self.mx)
        
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
        self._label = ensure_label(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self,buffer):
        buffer.encode_name(self.label)

    def __str__(self):
        return "%s" % (self.label)

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
        self._mname = ensure_label(mname)

    def get_mname(self):
        return self._mname

    mname = property(get_mname,set_mname)

    def set_rname(self,rname):
        self._rname = ensure_label(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self,buffer):
        buffer.encode_name(self.mname)
        buffer.encode_name(self.rname)
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

    def pack(self, buffer):
        buffer.pack('!HH', self.order, self.preference)
        buffer.pack('!B', len(self.flags))
        buffer.append(self.flags)
        buffer.pack('!B', len(self.service))
        buffer.append(self.service)
        buffer.pack('!B', len(self.regexp))
        buffer.append(self.regexp)
        buffer.encode_name(self.replacement)

    def __str__(self):
        return '%d %d "%s" "%s" "%s" %s' %(
            self.order,self.preference,self.flags,
            self.service,self.regexp,self.replacement or '.'
        )


def base64chunked(bytecode, size=56):
    ascii = base64.b64encode(bytecode)
    chunks = [ascii[start:start + size] for start in range(0, len(ascii), size)]
    return " ".join(chunks)


def colonized(*args):
    return ":".join((str(a) for a in args))


def ts2str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')


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

    def __init__(self, options):
        self.options = options

    def pack(self, buffer):
        for opt in self.options:
            buffer.pack("!HH", opt.code, len(opt.data))
            buffer.append(opt.data)

    def __str__(self):
        return " ".join((str(opt) for opt in self.options))


class DNSKEY(RD):

    def __init__(self, zk=1, sep=0, ptc=3, alg=8, key=None):
        self.zk = zk  # Zone Key flag
        self.sep = sep  # Secure Entry Point flag
        self.ptc = ptc  # Protocol Field, MUST have value 3, see http://tools.ietf.org/html/rfc4034#section-2.1.2
        self.alg = alg  # Algorithm field
        self.key = key  # Public key

    @classmethod
    def parse(cls, buffer, length):
        zk, sep, ptc, alg = buffer.unpack("!BBBB")
        key = buffer.get(length - 4)
        return cls(zk=zk, sep=sep, ptc=ptc, alg=alg, key=key)

    def pack(self, buffer):
        buffer.pack("!BBBB", self.zk, self.sep, self.ptc, self.alg)
        buffer.append(self.key)

    def __str__(self):
        flags = 256 * self.zk + self.sep
        return colonized(flags, self.ptc, self.alg, base64chunked(self.key))


class RRSIG(RD):

    def __init__(self, tc, alg, lbs, ttl, exp, inc, tag, name, sig):
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

    def pack(self, buffer):
        buffer.pack("!HBBI", self.tc, self.alg, self.lbs, self.ttl)
        buffer.pack("!IIH", self.exp, self.inc, self.tag)
        buffer.encode_name(self.name, allow_cache=False)
        buffer.append(self.sig)

    def __str__(self):
        return colonized(QTYPE[self.tc], self.alg, self.lbs, self.ttl, ts2str(self.exp), ts2str(self.inc),
                         self.tag, self.name, base64chunked(self.sig))


RDMAP = {'CNAME': CNAME, 'A': A, 'AAAA': AAAA, 'TXT': TXT, 'MX': MX,
         'PTR': PTR, 'SOA': SOA, 'NS': NS, 'NAPTR': NAPTR, 'OPT': OPT,
         'DNSKEY': DNSKEY, 'RRSIG': RRSIG}


def test_unpack():
    """
    Test decoding with sample DNS packets captured from Wireshark

    >>> def unpack(s):
    ...     d = DNSRecord.parse(s.decode('hex'))
    ...     print d

    Test
        >>> unpack('e9fa010000010000000000010469657466036f726700000100010000291000000080000000')
        <DNS Header: id=0xe9fa type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=1>
        <DNS Question: 'ietf.org' qtype=A qclass=IN>
        <DNS OPT RR: EDNS(0) rtype=OPT pl=4096 DO=1 options=0>

    Short response for query DNSKEY ietf.org
        >>> unpack('3f0f870000010001000000000469657466036f72670000300001c00c003000010000070801080101030503010001abe34351faa44f0557c2c63f4c1004554bd0433d0517eac73f69fec67ef00072ab21472dd65c1e838617b0a007938a60cbc63a0cacb98425a0f9706eaed6b395b2c1bbad6d7c86db894c5b2e238a394952c685ad2e44bd4bb8c9d9ae45cfd31a71179cdd574243bec1a213e1c2edae67168e863c3aab9dea50da25d8f570aaf69d7d4dae6311a3022edc3215b466d0266ce9ba4a4355969830c026f0ce6fcf8536bd10951132e00e843bae1b220f5dbb27c8151318cef01d35d778c26a36c545c32d52d1538c7e33ee35cfd99cc3717b20a5ee0b605b9e9c5400711051944ea86b290747bae53eaaa6c39f272042c9505a0c71bfc17512e06f24debab1659f1b')
        <DNS Header: id=0x3f0f type=RESPONSE opcode=QUERY flags=AA,TC,RD rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: 'ietf.org' qtype=DNSKEY qclass=IN>
        <DNS RR: 'ietf.org' rtype=DNSKEY rclass=IN ttl=1800 rdata='257:3:5:AwEAAavjQ1H6pE8FV8LGP0wQBFVL0EM9BRfqxz9p/sZ+8AByqyFHLdZc HoOGF7CgB5OKYMvGOgysuYQloPlwbq7Ws5WywbutbXyG24lMWy4jijlJ UsaFrS5EvUu4ydmuRc/TGnEXnN1XQkO+waIT4cLtrmcWjoY8Oqud6lDa Jdj1cKr2nX1NrmMRowIu3DIVtGbQJmzpukpDVZaYMMAm8M5vz4U2vRCV ETLgDoQ7rhsiD127J8gVExjO8B0113jCajbFRcMtUtFTjH4z7jXP2ZzD cXsgpe4LYFuenFQAcRBRlE6oaykHR7rlPqqmw58nIELJUFoMcb/BdRLg byTeurFlnxs='>

    Short response for query A ietf.org with DNSSEC
        >>> unpack('96e7850000010002000000000469657466036f72670000010001c00c000100010000070800040c163a1ec00c002e0001000007080114000105020000070853cea5a551ed64869e04c00c143d6d26bcbc9e86459c31624d792a5d434933726b9917c8b57c645b9fa32bb4ec6d18a8a99bb02be6043e1e57e2c3c10c7af4ff841a90dfae95c37bcd0c615b6d5a5b7bba8a13013daa600aa3c423ac1aa1e22e4b641365038c401f649380074a0312a4a867435583db52ad63a32a87e8cecb134d4816febd7b16673acea8e9242a94ef252986baf1cc49cf1ec37be124f36c27397cbb8f69a4d0ced1cf4e9982ebd79bfa84806eae9a4b12333d03803b318f71c565b2b9af4df85f8f98b1cdd2945e12690647e6a43eb68bd6701b8360896c2aec67cbc291a0af3a3fbb36a9af3a11e8d1463fc8b75b762a0fa88581aa4d969012c23640fdbf929cb583f98b')
        <DNS Header: id=0x96e7 type=RESPONSE opcode=QUERY flags=AA,RD rcode=None q=1 a=2 ns=0 ar=0>
        <DNS Question: 'ietf.org' qtype=A qclass=IN>
        <DNS RR: 'ietf.org' rtype=A rclass=IN ttl=1800 rdata='12.22.58.30'>
        <DNS RR: 'ietf.org' rtype=RRSIG rclass=IN ttl=1800 rdata='A:5:2:1800:20140722195549:20130722185742:40452:ietf.org:FD1tJry8noZFnDFiTXkqXUNJM3JrmRfItXxkW5+jK7TsbRioqZuwK+YE Ph5X4sPBDHr0/4QakN+ulcN7zQxhW21aW3u6ihMBPapgCqPEI6waoeIu S2QTZQOMQB9kk4AHSgMSpKhnQ1WD21KtY6Mqh+jOyxNNSBb+vXsWZzrO qOkkKpTvJSmGuvHMSc8ew3vhJPNsJzl8u49ppNDO0c9OmYLr15v6hIBu rppLEjM9A4A7MY9xxWWyua9N+F+PmLHN0pReEmkGR+akPraL1nAbg2CJ bCrsZ8vCkaCvOj+7NqmvOhHo0UY/yLdbdioPqIWBqk2WkBLCNkA='>

    Standard query A www.google.com
        >>> unpack('d5ad010000010000000000000377777706676f6f676c6503636f6d0000010001')
        <DNS Header: id=0xd5ad type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>

    Standard query response CNAME www.l.google.com A 66.249.91.104 A 66.249.91.99 A 66.249.91.103 A 66.249.91.147
        >>> unpack('d5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93')
        <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=5 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>
        <DNS RR: 'www.google.com' rtype=CNAME rclass=IN ttl=5 rdata='www.l.google.com'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.104'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.99'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.103'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.147'>

    Standard query MX google.com
        >>> unpack('95370100000100000000000006676f6f676c6503636f6d00000f0001')
        <DNS Header: id=0x9537 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>

    Standard query response MX 10 smtp2.google.com MX 10 smtp3.google.com MX 10 smtp4.google.com MX 10 smtp1.google.com
        >>> unpack('95378180000100040000000006676f6f676c6503636f6d00000f0001c00c000f000100000005000a000a05736d747032c00cc00c000f000100000005000a000a05736d747033c00cc00c000f000100000005000a000a05736d747034c00cc00c000f000100000005000a000a05736d747031c00c')
        <DNS Header: id=0x9537 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=4 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp2.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp3.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp4.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp1.google.com'>

    Standard query PTR 103.91.249.66.in-addr.arpa
        >>> unpack('b38001000001000000000000033130330239310332343902363607696e2d61646472046172706100000c0001')
        <DNS Header: id=0xb380 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>

    Standard query response PTR ik-in-f103.google.com
        >>> unpack('b38081800001000100000000033130330239310332343902363607696e2d61646472046172706100000c0001c00c000c00010000000500170a696b2d696e2d6631303306676f6f676c6503636f6d00')
        <DNS Header: id=0xb380 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>
        <DNS RR: '103.91.249.66.in-addr.arpa' rtype=PTR rclass=IN ttl=5 rdata='ik-in-f103.google.com'>

    Standard query TXT google.com

        >>> unpack('c89f0100000100000000000006676f6f676c6503636f6d0000100001')
        <DNS Header: id=0xc89f type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>

    Standard query response TXT
        >>> unpack('c89f8180000100010000000006676f6f676c6503636f6d0000100001c00c0010000100000005002a29763d7370663120696e636c7564653a5f6e6574626c6f636b732e676f6f676c652e636f6d207e616c6c')
        <DNS Header: id=0xc89f type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>
        <DNS RR: 'google.com' rtype=TXT rclass=IN ttl=5 rdata='v=spf1 include:_netblocks.google.com ~all'>

    Standard query SOA google.com
        >>> unpack('28fb0100000100000000000006676f6f676c6503636f6d0000060001')
        <DNS Header: id=0x28fb type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>

    Standard query response SOA ns1.google.com
        >>> unpack('28fb8180000100010000000006676f6f676c6503636f6d0000060001c00c00060001000000050026036e7331c00c09646e732d61646d696ec00c77b1566d00001c2000000708001275000000012c')
        <DNS Header: id=0x28fb type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>
        <DNS RR: 'google.com' rtype=SOA rclass=IN ttl=5 rdata='ns1.google.com:dns-admin.google.com:2008110701:7200:1800:1209600:300'>

    Standard query response NAPTR sip2sip.info
        >>> unpack('740481800001000300000000077369703273697004696e666f0000230001c00c0023000100000c940027001e00640173075349502b44325500045f736970045f756470077369703273697004696e666f00c00c0023000100000c940027000a00640173075349502b44325400045f736970045f746370077369703273697004696e666f00c00c0023000100000c94002900140064017308534950532b44325400055f73697073045f746370077369703273697004696e666f00')
        <DNS Header: id=0x7404 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=3 ns=0 ar=0>
        <DNS Question: 'sip2sip.info' qtype=NAPTR qclass=IN>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='30 100 "s" "SIP+D2U" "" _sip._udp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='10 100 "s" "SIP+D2T" "" _sip._tcp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='20 100 "s" "SIPS+D2T" "" _sips._tcp.sip2sip.info'>

    Standard query response NAPTR 0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org
        >>> unpack('aef0818000010001000000000130013001300130013101310131013301390133013001310138013701380465313634036f72670000230001c00c002300010000a6a300320064000a0175074532552b53495022215e5c2b3f282e2a2924217369703a5c5c31406677642e70756c7665722e636f6d2100')
        <DNS Header: id=0xaef0 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' qtype=NAPTR qclass=IN>
        <DNS RR: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' rtype=NAPTR rclass=IN ttl=42659 rdata='100 10 "u" "E2U+SIP" "!^\+?(.*)$!sip:\\\\1@fwd.pulver.com!" .'>
    """


if __name__ == '__main__':
    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
