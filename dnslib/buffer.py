# coding=utf-8
import struct
from .bit import get_bits, set_bits
from .label import DNSLabel


class Buffer(object):

    """
    A simple data buffer - supports packing/unpacking in struct format 

    >>> b = Buffer()
    >>> b.pack("!BHI",1,2,3)
    >>> b.offset
    7
    >>> b.append("0123456789")
    >>> b.offset
    17
    >>> b.offset = 0
    >>> b.unpack("!BHI")
    (1, 2, 3)
    >>> b.get(5)
    '01234'
    >>> b.get(5)
    '56789'
    >>> b.update(7,"2s","xx")
    >>> b.offset = 7
    >>> b.get(5)
    'xx234'
    """

    def __init__(self,data=""):
        """
            Initialise Buffer from data
        """
        self.data = data
        self.offset = 0

    def remaining(self):
        """
            Return bytes remaining
        """
        return len(self.data) - self.offset

    def get(self,len):
        """
            Gen len bytes at current offset (& increment offset)
        """
        start = self.offset
        end = self.offset + len
        self.offset += len
        return self.data[start:end]

    def pack(self,fmt,*args):
        """
            Pack data at end of data according to fmt (from struct) & increment
            offset
        """
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt,*args)

    def append(self,s):
        """
            Append s to end of data & increment offset
        """
        self.offset += len(s)
        self.data += s

    def update(self,ptr,fmt,*args):
        """
            Modify data at offset `ptr` 
        """
        s = struct.pack(fmt,*args)
        self.data = self.data[:ptr] + s + self.data[ptr+len(s):]

    def unpack(self,fmt):
        """
            Unpack data at current offset according to fmt (from struct)
        """
        return struct.unpack(fmt,self.get(struct.calcsize(fmt)))


class DNSBuffer(Buffer):

    """
    Extends Buffer to provide DNS name encoding/decoding (with caching)

    >>> b = DNSBuffer()
    >>> b.encode_name("aaa.bbb.ccc")
    >>> b.encode_name("xxx.yyy.zzz")
    >>> b.encode_name("zzz.xxx.bbb.ccc")
    >>> b.encode_name("aaa.xxx.bbb.ccc")
    >>> b.encode_name("")
    >>> b.encode_name(".")
    >>> b.data.encode("hex")
    '036161610362626203636363000378787803797979037a7a7a00037a7a7a03787878c00403616161c01e0000'
    >>> b.offset = 0
    >>> b.decode_name()
    'aaa.bbb.ccc'
    >>> b.decode_name()
    'xxx.yyy.zzz'
    >>> b.decode_name()
    'zzz.xxx.bbb.ccc'
    >>> b.decode_name()
    'aaa.xxx.bbb.ccc'
    >>> b.decode_name()
    ''
    >>> b.decode_name()
    ''

    >>> b = DNSBuffer()
    >>> b.encode_name(['a.aa','b.bb','c.cc'])
    >>> b.offset = 0
    >>> len(b.decode_name().label)
    3
    """

    def __init__(self, data=""):
        """
            Add 'names' dict to cache stored labels
        """
        super(DNSBuffer, self).__init__(data)
        self.names = {}

    def decode_name(self):
        """
            Decode label at current offset in buffer (following pointers
            to cached elements where necessary)
        """
        label = []
        done = False
        while not done:
            (len,) = self.unpack("!B")
            if get_bits(len,6,2) == 3:
                # Pointer
                self.offset -= 1
                pointer = get_bits(self.unpack("!H")[0],0,14)
                save = self.offset
                self.offset = pointer
                label.extend(self.decode_name().label)
                self.offset = save
                done = True
            else:
                if len > 0:
                    label.append(self.get(len))
                else:
                    done = True
        return DNSLabel(label)

    def encode_name(self, name, allow_cache=True):
        """
            Encode label and store at end of buffer (compressing
            cached elements where needed) and store elements
            in 'names' dict
        """
        if not isinstance(name,DNSLabel):
            name = DNSLabel(name)
        name.validate()
        # root domain:
        if str(name) in ['', '.']:
            self.append("\x00")
            return
        name = list(name.label)
        while name:
            if tuple(name) in self.names and allow_cache:
                # Cached - set pointer
                pointer = self.names[tuple(name)]
                pointer = set_bits(pointer,3,14,2)
                self.pack("!H",pointer)
                return
            else:
                if allow_cache:
                    self.names[tuple(name)] = self.offset
                element = name.pop(0)
                self.pack("!B", len(element))
                self.append(element)
        self.append("\x00")


def packed(*args):
    buf = DNSBuffer()
    for obj in args:
        obj.pack(buf)
    return buf.data
