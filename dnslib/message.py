# coding=utf-8
from .enums import *
from .rdata import *
from .bit import get_bits, set_bits
from .buffer import Buffer
from .label import Label


class Section(list):
    pass


class Message(object):

    @classmethod
    def parse(cls, packet):
        """
        Parse DNS packet data and return DNSRecord instance
        """
        buf = Buffer(packet)
        header = Header.parse(buf)
        questions = []
        anwers = []
        authority = []
        additional = []
        for i in range(header.question_count):
            questions.append(Question.parse(buf))

        for i in range(header.answer_count):
            anwers.append(RR.parse(buf))

        for i in range(header.authority_count):
            authority.append(RR.parse(buf))

        for i in range(header.additional_count):
            additional.append(RR.parse(buf))

        return cls(header, questions, anwers, authority, additional, packet=packet)

    def __init__(self, header=None, questions=None, answers=None, authority=None, additional=None, packet=None):
        self.packet = packet
        self.header = header or Header()
        self.questions = questions or []
        self.answers = answers or []
        self.authority = authority or []
        self.additional = additional or []
        self.set_header_qa()

    def add_question(self, rr):
        self.questions.append(rr)
        self.set_header_qa()

    def add_answer(self, rr):
        self.answers.append(rr)
        self.set_header_qa()

    def add_authority(self, rr):
        self.authority.append(rr)
        self.set_header_qa()

    def add_additional(self, rr):
        self.additional.append(rr)
        self.set_header_qa()

    def has(self, rtype):
        rtype = ensure_rtype(rtype)
        for rr in self.answers + self.authority + self.additional:
            if rr.rtype == rtype:
                return True

    def set_header_qa(self):
        self.header.question_count = len(self.questions)
        self.header.answer_count = len(self.answers)
        self.header.authority_count = len(self.authority)
        self.header.additional_count = len(self.additional)

    def pack(self):
        self.set_header_qa()
        buf = Buffer()
        self.header.pack(buf)
        for section in [self.questions, self.answers, self.authority, self.additional]:
            for rr in section:
                rr.pack(buf)
        return buf.data

    def __str__(self):
        sections = [str(self.header)]
        sections.extend([str(q) for q in self.questions])
        sections.extend([str(rr) for rr in self.answers])
        sections.extend([str(rr) for rr in self.authority])
        sections.extend([str(rr) for rr in self.additional])
        return '\n'.join(sections)


class Header(object):

    @classmethod
    def parse(cls, buf):
        (msg_id, bitmap, n_qu, n_an, n_au, n_ad) = buf.unpack('!HHHHHH')
        return cls(msg_id, bitmap, n_qu, n_an, n_au, n_ad)

    def __init__(self, msg_id=None, bitmap=None, n_qu=0, n_an=0, n_au=0, n_ad=0, **args):
        if msg_id is None:
            import random
            self.msg_id = random.randint(0, 0xFFFF)
        else:
            self.msg_id = msg_id
        if bitmap is None:
            self.bitmap = 0
            self.rd = 1
        else:
            self.bitmap = bitmap

        self.question_count = n_qu
        self.answer_count = n_an
        self.authority_count = n_au
        self.additional_count = n_ad

        for k, v in args.items():
            if k.lower() in 'qr opcode aa tc rd ra rcode'.split():
                setattr(self, k.lower(), v)

    def get_qr(self):
        return get_bits(self.bitmap, 15)

    def set_qr(self, val):
        self.bitmap = set_bits(self.bitmap, val, 15)

    qr = property(get_qr, set_qr)

    def get_opcode(self):
        return get_bits(self.bitmap, 11, 4)

    def set_opcode(self, val):
        self.bitmap = set_bits(self.bitmap, val, 11, 4)

    opcode = property(get_opcode, set_opcode)

    def get_aa(self):
        return get_bits(self.bitmap, 10)

    def set_aa(self, val):
        self.bitmap = set_bits(self.bitmap, val, 10)

    aa = property(get_aa, set_aa)
        
    def get_tc(self):
        return get_bits(self.bitmap, 9)

    def set_tc(self, val):
        self.bitmap = set_bits(self.bitmap, val, 9)

    tc = property(get_tc, set_tc)
        
    def get_rd(self):
        return get_bits(self.bitmap, 8)

    def set_rd(self, val):
        self.bitmap = set_bits(self.bitmap, val, 8)

    rd = property(get_rd, set_rd)
        
    def get_ra(self):
        return get_bits(self.bitmap, 7)

    def set_ra(self, val):
        self.bitmap = set_bits(self.bitmap, val, 7)

    ra = property(get_ra, set_ra)

    def get_rcode(self):
        return get_bits(self.bitmap, 0, 4)

    def set_rcode(self, val):
        self.bitmap = set_bits(self.bitmap, val, 0, 4)

    rcode = property(get_rcode, set_rcode)

    def pack(self, buf):
        buf.pack('!HHHHHH', self.msg_id, self.bitmap, self.question_count, self.answer_count, self.authority_count,
                 self.additional_count)

    def __str__(self):
        f = [self.aa and 'AA',
             self.tc and 'TC',
             self.rd and 'RD',
             self.ra and 'RA']
        if OPCODE[self.opcode] == 'UPDATE':
            f1 = 'zo'
            f2 = 'pr'
            f3 = 'up'
            f4 = 'ad'
        else:
            f1 = 'q'
            f2 = 'a'
            f3 = 'ns'
            f4 = 'ar'
        return "<DNS Header: id=0x%x type=%s opcode=%s flags=%s rcode=%s %s=%d %s=%d %s=%d %s=%d>" % (
            self.msg_id, QR[self.qr], OPCODE[self.opcode], ','.join(filter(None, f)), RCODE[self.rcode],
            f1, self.question_count, f2, self.answer_count, f3, self.authority_count, f4, self.additional_count)


class Question(object):
    
    @classmethod
    def parse(cls, buf):
        qname = buf.decode_name()
        qtype, qclass = buf.unpack('!HH')
        return cls(qname, qtype, qclass)

    def __init__(self, qname='', qtype=1, qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def set_qname(self, qname):
        self._qname = Label(qname)

    def get_qname(self):
        return self._qname

    qname = property(get_qname, set_qname)

    def pack(self, buf):
        buf.encode_name(self.qname)
        buf.pack('!HH', self.qtype, self.qclass)

    def __str__(self):
        return "<DNS Question: %r qtype=%s qclass=%s>" % (self.qname, QTYPE[self.qtype], CLASS[self.qclass])


class RR(object):

    @classmethod
    def parse(cls, buf):
        rname = buf.decode_name()
        rtype, rclass, ttl, rdlength = buf.unpack('!HHIH')
        if rtype == QTYPE.OPT:
            rdata = OPT.parse(buf, rdlength)
            do = (ttl >> 15) & 1
            return OPT_RR(udp_payload=rclass, do=do, rdata=rdata)
        else:
            if rdlength:
                rdata = globals().get(QTYPE[rtype], RDATA).parse(buf, rdlength)
            else:
                rdata = ''
            return cls(rname, rtype, rclass, ttl, rdata)

    def __init__(self, rname='', rtype=None, rclass=1, ttl=0, rdata=None):
        self.rname = rname
        self.rtype = ensure_rtype(rtype)
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def set_rname(self, rname):
        self._rname = Label(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname, set_rname)

    def pack(self, buf, allow_cache=True):
        buf.encode_name(self.rname, allow_cache=allow_cache)
        buf.pack('!HHI', self.rtype, self.rclass, self.ttl)
        rdlength_ptr = buf.offset
        buf.pack('!H', 0)
        start = buf.offset
        self.rdata.pack(buf, allow_cache=allow_cache)
        end = buf.offset
        buf.update(rdlength_ptr, '!H', end - start)

    def packed(self):
        return Buffer.packed(self)

    def __str__(self):
        return "<DNS RR: %r rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
            self.rname, QTYPE[self.rtype], CLASS[self.rclass], self.ttl, self.rdata)

    def __repr__(self):
        return super(self.__class__, self).__repr__().replace('.RR', '.RR ' + QTYPE[self.rtype])


class OPT_RR(RR):

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


def reply(msg, data='', ra=1, aa=1):
    q = msg.questions[0]
    r = Message(Header(msg_id=msg.header.msg_id, bitmap=msg.header.bitmap, qr=1, ra=ra, aa=aa))
    r.add_question(q)
    answer = globals().get(QTYPE[q.qtype], RDATA)(data)
    r.add_answer(RR(q.qname, q.qtype, rdata=answer))
    return r
