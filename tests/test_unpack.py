# coding=utf-8
from dnslib import DNSRecord


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
        <DNS RR: 'ietf.org' rtype=DNSKEY rclass=IN ttl=1800 rdata='257:3:5:AwEAAavjQ1H6pE8FV8LGP0wQBFVL0EM9BRfqxz9p/sZ+8AByqyFHLdZc HoOGF7CgB5OKYMvGOgysuYQloPlwbq7Ws5WywbutbXyG24lMWy4jijlJ UsaFrS5EvUu4ydmuRc/TGnEXnN1XQkO+waIT4cLtrmcWjoY8Oqud6lDa Jdj1cKr2nX1NrmMRowIu3DIVtGbQJmzpukpDVZaYMMAm8M5vz4U2vRCV ETLgDoQ7rhsiD127J8gVExjO8B0113jCajbFRcMtUtFTjH4z7jXP2ZzD cXsgpe4LYFuenFQAcRBRlE6oaykHR7rlPqqmw58nIELJUFoMcb/BdRLg byTeurFlnxs=:45586'>

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
