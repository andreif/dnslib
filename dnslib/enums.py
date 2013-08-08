# coding=utf-8
from .bimap import Bimap


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
