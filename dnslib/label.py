# coding=utf-8


class DNSLabelError(Exception):
    pass


class DNSLabel(object):
    """
    Container for DNS label supporting arbitary label chars (including '.')

    >>> l1 = DNSLabel("aaa.bbb.ccc")
    >>> l2 = DNSLabel(["aaa","bbb","ccc"])
    >>> l1 == l2
    True
    >>> x = { l1 : 1 }
    >>> x[l1]
    1
    >>> print l1
    aaa.bbb.ccc
    >>> l1
    'aaa.bbb.ccc'

    """
    def __init__(self, label):
        if isinstance(label, (list, tuple)):
            self.label = tuple(label)
        else:
            self.label = tuple(label.split("."))

    def validate(self):
        if len(self) > 253:
            raise DNSLabelError("Domain label too long: %r" % self)

        for element in self.label:
            if len(element) > 63:
                raise DNSLabelError("Label component too long: %r" % element)

    def __str__(self):
        return ".".join(self.label)

    def __repr__(self):
        return "%r" % str(self)

    def __hash__(self):
        return hash(self.label)

    def __eq__(self, other):
        return self.label == other.label

    def __len__(self):
        return len(str(self))
