#!/usr/bin/env python
# coding=utf-8
"""
    Simple DNS proxy - listens on proxy port and forwards request/reply to real server
    passing data through dnslib and printing the raw/parsed data

    This is mostly for testing - normal usage would be to use dig to generate request 
    and compare outputs

    Options:

      --port=PORT          Proxy port (default: 8053)
      --bind=BIND          Proxy bind address (default: all)
      --dns=DNS            DNS server (default: 8.8.8.8)
      --dns_port=DNS_PORT  DNS server port (default: 53)

    Usage:

    # python udp_proxy.py

    (from another window)

    # dig @127.0.0.1 www.google.com -p 8053

"""
import optparse
import socket
from dnslib import DNSRecord, QTYPE

AF_INET = 2
SOCK_DGRAM = 2

with_indent = lambda indent, obj: indent + str(obj).replace("\n", "\n" + indent)


def serve_request(proxy, options):
    # Wait for client connection
    data,client = proxy.recvfrom(8192)
    if options.verbose > 1:
        print data.encode('hex')
    # Parse and print request
    request = DNSRecord.parse(data)
    id = request.header.id
    qname = request.q.qname
    qtype = request.q.qtype
    print "------ Request (%s): %r (%s)" % (str(client),qname.label,QTYPE[qtype])
    print with_indent("  ", request)
    # Use dnslib to make request
    if options.dnslib:
        data = request.pack()
    # Send request to server
    s = socket.socket(AF_INET, SOCK_DGRAM)
    s.sendto(data,(options.dns,options.dns_port))
    # Wait for reply
    data,server = s.recvfrom(8192)
    if options.verbose > 1:
        print data.encode('hex')
    # Parse and print reply
    reply = DNSRecord.parse(data)
    id = reply.header.id
    qname = reply.q.qname
    qtype = reply.q.qtype
    print "------ Reply (%s): %r (%s)" % (str(server),qname.label,QTYPE[qtype])
    print with_indent("  ", reply)
    print
    # Remove additional sections
    if options.answer:
        reply.ar = []
        reply.ns = []
        reply.set_header_qa()
        print "------ Reply without additional sections:"
        print reply.pack().encode('hex')
    # Use dnslib to make reply
    if options.dnslib:
        data = reply.pack()
    # Send reply to client
    proxy.sendto(data,client)


if __name__ == "__main__":
    parser = optparse.OptionParser(usage="Usage: %prog [options]")
    parser.add_option("--port", type=int, default=8053, help="Proxy port (default: 8053)")
    parser.add_option("--bind", default="127.0.0.1", help="Proxy bind address (default: 127.0.0.1)")
    parser.add_option("--dns", default="8.8.8.8", help="DNS server (default: 8.8.8.8)")
    parser.add_option("--dns_port", type=int, default=53, help="DNS server port (default: 53)")
    parser.add_option("-v", "--verbose", type=int, default=1, help="Verbosity level (default: 1)")
    parser.add_option("--dnslib", type=int, default=1, help="Use dnslib for querying and responding")
    parser.add_option("--answer", type=int, default=False, help="Skip authority and additional sections")
    options, args = parser.parse_args()

    proxy = socket.socket(AF_INET, SOCK_DGRAM)
    proxy.bind((options.bind, options.port))

    while True:
        serve_request(proxy, options)
