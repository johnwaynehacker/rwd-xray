#!/usr/bin/env python
import os
import sys
import struct
import gzip

def main():
    get_headers = {
        "\x5A\x0D\x0A": get_5a_headers,
        "\x31\x0D\x0A": get_31_headers,
    }

    get_decoder = {
        "\x5A\x0D\x0A": get_5a_decoder,
        "\x31\x0D\x0A": get_31_decoder,
    }

    get_firmware = {
        "\x5A\x0D\x0A": get_5a_firmware,
        "\x31\x0D\x0A": get_31_firmware,
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

        firmware = get_firmware[file_fmt](f, decoder)
        # TODO: how do we find these across different firmware files?
        if (os.path.basename(f_name) == '39990-TV9-A910'):
            print 'checksums:'
            print hex(ord(firmware[0x07fff])), "=", hex(ord(get_checksum(firmware[0x01f1e:0x07fff])))
            print hex(ord(firmware[0x225ff])), "=", hex(ord(get_checksum(firmware[0x08000:0x225ff])))
            print hex(ord(firmware[0x271ff])), "=", hex(ord(get_checksum(firmware[0x23200:0x271ff])))
            print hex(ord(firmware[0x295ff])), "=", hex(ord(get_checksum(firmware[0x27200:0x295ff])))

        f_out = f_name + '.bin'
        with open(f_out, 'wb') as o:
            o.write(firmware)
        print 'firmware: ' + f_out

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

def get_5a_decoder(headers):
    # TODO: no idea if this is correct
    decoder = {}

    k1, k2, k3 = map(ord, headers[5][0][0:3])
    print "keys:", hex(k1), hex(k2), hex(k3)
    for i in range(256):
        e = (((i - k3) ^ k2) + k1) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def get_31_decoder(headers):
    decoder = {}

    k = headers['&'][0].decode('hex')
    k1, k2, k3 = map(ord, k)
    print "keys:", hex(k1), hex(k2), hex(k3)
    for i in range(256):
        e = (((i - k1) ^ k2) + k3) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def get_5a_firmware(f, decoder):
    # TODO: no idea if this is correct (first 8 bytes look different)
    return ''.join(map(lambda x: decoder[x], f.read()))

def get_31_firmware(f, decoder):
    firmware = []

    addr = 0
    while 1:
        data = f.read(130)
        # stop when there is no longer an address followed by 128 bytes of data
        if len(data) != 130:
            # TODO: what are the last 4 bytes?
            # print 'trailing data:'
            # for d in data:
            #     print hex(ord(d)), '->', hex(ord(decoder[d]))
            break

        addr_prev = addr
        addr = (ord(data[0]) << 12) | (ord(data[1]) << 4)
        assert addr > addr_prev
        # fill any address gaps with null values
        for i in range(0 if addr_prev == 0 else addr_prev + 128, addr):
            firmware.append('\x00')
        for i in range(2, 130):
            firmware.append(decoder[data[i]])

    return ''.join(firmware)

def get_checksum(data):
    result = -sum(map(ord, data))
    return chr(result & 0xFF)

if __name__== "__main__":
    main()