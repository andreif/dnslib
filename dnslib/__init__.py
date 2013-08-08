# coding=utf-8
"""
dnslib
------

A simple library to encode/decode DNS wire-format packets. This was originally
written for a custom nameserver.

The key classes are:

    * Message (contains a Header and one or more Question/DNSRR records)
    * Header
    * Question
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
attribute. To specifiy a label to the Message classes you can either pass
a DNSLabel object or pass the elements as a list/tuple.

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
from .message import *

VERSION = "0.8.3"
