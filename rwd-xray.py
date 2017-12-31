#!/usr/bin/env python
import os
import sys
import struct
import gzip

def main():
    get_headers = {
        "\x31\x0D\x0A": get_31_headers,
        "\x5A\x0D\x0A": get_5a_headers,
    }

    get_decoder = {
        "\x31\x0D\x0A": get_31_decoder,
        "\x5A\x0D\x0A": get_5a_decoder,
    }

    f_name, f_ext = os.path.splitext(sys.argv[1])
    open_fn = open
    if f_ext == ".gz":
        open_fn = gzip.open
        f_name, f_ext = os.path.splitext(f_name)

    with open_fn(sys.argv[1], 'rb') as f:
        file_fmt = f.read(3)

        assert file_fmt in get_headers, "indicator bytes not recognized: " + file_fmt.encode("hex")

        headers = get_headers[file_fmt](f)
        decoder = get_decoder[file_fmt](headers)
        assert len(decoder) == 256, "decoder table is not complete"

        addr = 0
        firmware = ['\x00'] * (0x40000)
        while addr < 0x37f80:
            addr_prev = addr
            addr = (ord(f.read(1)) << 12) | (ord(f.read(1)) << 4)
            assert addr > addr_prev
            for i in range(128):
                e = f.read(1)
                d = decoder[e]
                firmware[addr + i] = d

        with open(f_name + '.bin', 'wb') as o:
            for b in firmware:
                o.write(b)

def get_31_headers(f):
    headers = {}

    idx = 0
    while 1:
        delim = f.read(1)
        # stop when delimiter is not found (0x__0D0A)
        if f.read(2) != "\x0D\x0A":
            f.seek(-3,1)
            break

        headers[delim] = []
        print "header[%d]: %s" % (idx, delim)
        i = 0
        for line in iter(lambda: f.readline(), b''):
            # stop when delimiter is repeated
            if line == delim + "\x0D\x0A": break
            # remove 0x0D 0x0A from end of data
            data = line.rstrip()
            headers[delim].append(data)
            print "%d[%d]: %s" % (i, len(data), data)
            i += 1
        idx += 1

    return headers

def get_5a_headers(f):
    headers = {}

    idx = 0
    null_cnt = 0
    while null_cnt != 2:
        headers[idx] = []
        print "header[%d]:" % idx
        cnt = ord(f.read(1))
        if cnt == 0: null_cnt += 1
        # headers are wrapped with 0x00 (stop when second instance is found)
        for i in range(0, cnt):
            length = ord(f.read(1))
            data = f.read(length)
            headers[idx].append(data)
            print "%d[%d]: 0x%s %s" % (i, length, data.encode("hex"), data)
        idx += 1

    return headers

def get_31_decoder(headers):
    decoder = {}

    k = headers['&'][0].decode('hex')
    k1, k2, k3 = map(ord, k)
    print "keys:", hex(k1), hex(k2), hex(k3)
    for i in range(256):
        e = (((i - k3) ^ k2) + k1) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def get_5a_decoder(headers):
    decoder = {}

    k1, k2, k3 = map(ord, headers[5][0][0:3])
    print "keys:", hex(k1), hex(k2), hex(k3)
    for i in range(256):
        e = (((i - k3) ^ k2) + k1) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def get_checksum(data):
    result = -sum(map(ord, data))
    return chr(result & 0xFF)

if __name__== "__main__":
    main()