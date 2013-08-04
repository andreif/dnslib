# coding=utf-8
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

GitHub mirror is at:

    *   https://github.com/paulchakravarti/dnslib

For any issues please use the Bitbucket repository

"""
from .dns import *

VERSION = "0.8.3"
