import re

from collections import namedtuple


MAX_FILESIZE = 16*1024*1024
MIN_STRINGLEN = 4
ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
String = namedtuple("String", ["s", "offset"])


def ascii_strings(buf, n=4):
    reg = "([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())

def unicode_strings(buf, n=4):
    reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def get_strings(exe):

    string_list = []

    with open(exe, 'rb') as f:
        b = f.read()

    # s.offset
    for s in ascii_strings(b, n=4):
        string_list.append(s.s)

    for s in unicode_strings(b):
        string_list.append(s.s)

    return string_list, decoded_strings

