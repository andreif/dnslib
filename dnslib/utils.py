# coding=utf-8
import base64
import datetime


def chunk(s, size):
    return [s[start:start + size] for start in range(0, len(s), size)]


def base64chunked(s, size=56):
    ascii = base64.b64encode(s)
    chunks = chunk(ascii, size)
    return ' '.join(chunks)


def hexchunked(s, size=56):
    h = s.encode('hex')
    chunks = chunk(h, size)
    return ' '.join(chunks)


def colonized(*args):
    return ':'.join((str(a) for a in args))


def ts2str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')


def calc_tag(rdata):
    """
    See: http://tools.ietf.org/html/rfc4034#appendix-B
    """
    from .dns import RD
    if isinstance(rdata, RD):
        rdata = rdata.packed()
    ac = 0
    for i in range(0, len(rdata)):
        ac += ord(rdata[i]) if (i & 1) else ord(rdata[i]) << 8
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def rsa_from_rdata(data):
    from dnslib import DNSBuffer
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import bytes_to_long

    b = DNSBuffer(data=data)
    (e_len,) = b.unpack('!B')
    if not e_len:
        (e_len,) = b.unpack('!H')
    rsa_e = b.get(e_len)
    rsa_n = b.get(b.remaining())
    return RSA.construct((bytes_to_long(rsa_n), bytes_to_long(rsa_e)))
