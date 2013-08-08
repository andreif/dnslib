# coding=utf-8
from .utils import colonized, base64chunked, ts2str, hexchunked, calc_tag
from .label import Label
from .buffer import Buffer
from .enums import QTYPE


class RDATA(object):

    @classmethod
    def parse(cls, buf, length):
        data = buf.get(length)
        return cls(data)

    def __init__(self, data=''):
        self.data = data

    def pack(self, buf, allow_cache=True):
        buf.append(self.data)

    def __str__(self):
        return self.data.encode('hex')

    def packed(self):
        return Buffer.packed(self)


class TXT(RDATA):

    @classmethod
    def parse(cls, buf, length):
        (txtlength,) = buf.unpack('!B')
        if txtlength < length:
            data = buf.get(txtlength)
        else:
            raise Exception(u"Invalid TXT record: length (%d) > RD length (%d)" % (txtlength, length))
        return cls(data)

    def pack(self, buf, allow_cache=True):
        if len(self.data) > 255:
            raise Exception(u"TXT record too long: %s" % self.data)
        buf.pack('!B', len(self.data))
        buf.append(self.data)

    def __str__(self):
        return str(self.data)


class A(RDATA):

    @classmethod
    def parse(cls, buf, length):
        ip = buf.unpack('!BBBB')
        data = '%d.%d.%d.%d' % ip
        return cls(data)

    def pack(self, buf, allow_cache=True):
        buf.pack('!BBBB', *map(int, str(self.data).split('.')))

    def __str__(self):
        return str(self.data)


class AAAA(RDATA):
    """
    Basic support for AAAA record - assumes IPv6 address data is presented
    as a simple tuple of 16 bytes
    """

    @classmethod
    def parse(cls, buf, length):
        data = buf.unpack('!16B')
        return cls(data)

    def pack(self, buf, allow_cache=True):
        buf.pack('!16B', *self.data)

    def __str__(self):
        hexes = map('{:02x}'.format, self.data)
        #noinspection PyArgumentList
        return ':'.join([''.join(hexes[i: i + 2]) for i in xrange(0, len(hexes), 2)])


class MX(RDATA):

    @classmethod
    def parse(cls, buf, length):
        (preference,) = buf.unpack('!H')
        mx = buf.decode_name()
        return cls(mx, preference)

    def __init__(self, mx='', preference=10):
        self.mx = mx
        self.preference = preference

    def set_mx(self, mx):
        self._mx = Label(mx)

    def get_mx(self):
        return self._mx

    mx = property(get_mx, set_mx)

    def pack(self, buf, allow_cache=True):
        buf.pack('!H', self.preference)
        buf.encode_name(self.mx, allow_cache=allow_cache)

    def __str__(self):
        return '%d:%s' % (self.preference, self.mx)


class CNAME(RDATA):

    @classmethod
    def parse(cls,buffer,length):
        label = buffer.decode_name()
        return cls(label)

    def __init__(self,label=[]):
        self.label = label

    def set_label(self,label):
        self._label = Label(label)

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


class SOA(RDATA):

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
        self._mname = Label(mname)

    def get_mname(self):
        return self._mname

    mname = property(get_mname,set_mname)

    def set_rname(self,rname):
        self._rname = Label(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self, buffer, allow_cache=True):
        buffer.encode_name(self.mname, allow_cache=allow_cache)
        buffer.encode_name(self.rname, allow_cache=allow_cache)
        buffer.pack("!IIIII", *self.times)

    def __str__(self):
        return "%s:%s:%s" % (self.mname,self.rname,":".join(map(str,self.times)))

class NAPTR(RDATA):

    def __init__(self,order,preference,flags,service,regexp,replacement=None):
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement or Label([])

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


class EDNSOption(object):

    def __init__(self,code,data):
        self.code = code
        self.data = data

    def __str__(self):
        return "<EDNS Option: Code=%d Data=%s>" % (self.code,self.data)


class OPT(RDATA):

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


class DNSKEY(RDATA):

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


class RRSIG(RDATA):

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


class DS(RDATA):

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


# TODO: move to enum
def ensure_rtype(x):
    if isinstance(x, type) and issubclass(x, RDATA):
        x = x.__name__
    if isinstance(x, basestring):
        x = QTYPE[x]
    return x
