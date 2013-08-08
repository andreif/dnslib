#!/usr/bin/env python
# coding=utf-8

from circuits.net.sockets import UDPServer

from dnslib import A, CNAME, MX, RR
from dnslib import Header, Message, QTYPE

AF_INET = 2
SOCK_DGRAM = 2

IP = "127.0.0.1"
TXT = "circuits_server.py"


class DNSServer(UDPServer):

    channel = "dns"

    def read(self, sock, data):
        request = Message.parse(data)
        id = request.header.id
        qname = request.q.qname
        qtype = request.q.qtype
        print "------ Request (%s): %r (%s)" % (str(sock),
                qname.label, QTYPE[qtype])

        reply = Message(Header(id=id, qr=1, aa=1, ra=1), q=request.q)

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, qtype,      rdata=A(IP)))
        elif qtype == QTYPE['*']:
            reply.add_answer(RR(qname, QTYPE.A,    rdata=A(IP)))
            reply.add_answer(RR(qname, QTYPE.MX,   rdata=MX(IP)))
            reply.add_answer(RR(qname, QTYPE.TXT,  rdata=TXT(TXT)))
        else:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(TXT)))

        return reply.pack()

if __name__ == "__name__":
    DNSServer(("0.0.0.0", 53)).run()
