#!/usr/bin/env python
import os
import sys
import struct
import gzip
import binascii
import operator
import itertools

def get_file_checksum(data):
    expected = struct.unpack('<L', data[-4:])[0]
    actual = sum(map(ord, data[0:-4]))

    return expected, actual

def is_ascii(s):
    return all(ord(c) == 0 or (ord(c) >= 0x20 and ord(c) <= 0x7E) for c in s)

def get_5a_headers(data):
    headers = {}

    d_idx = 0
    h_idx = 0
    null_cnt = 0
    while 1:
        headers[h_idx] = []
        cnt = ord(data[d_idx])
        # headers are wrapped with 0x00 (stop when second instance is found)
        if cnt == 0: null_cnt += 1
        if null_cnt == 2:
            break
        d_idx += 1

        for i in range(0, cnt):
            length = ord(data[d_idx])
            d_idx += 1
            h_data = data[d_idx:d_idx+length]
            d_idx += length
            headers[h_idx].append(h_data)

        display_headers = [val if is_ascii(val) else '0x'+binascii.b2a_hex(val) for val in headers[h_idx]]
        print("header[{}]: {}".format(h_idx, ' '.join(display_headers)))
        h_idx += 1

    return headers, d_idx

def get_31_headers(data):
    headers = {}

    d_idx = 0
    h_idx = 0
    while 1:
        delim = data[d_idx]
        # stop when delimiter is not found (0x__0D0A)
        if data[d_idx+1:d_idx+3] != "\x0D\x0A":
            break
        d_idx += 3

        headers[delim] = []
        while 1:
            # stop when delimiter is repeated
            if data[d_idx:d_idx+3] == delim + "\x0D\x0A":
                d_idx += 3
                break
            # header data
            end_idx = data.find("\x0D\x0A", d_idx)
            assert end_idx != -1, "newline delimiter not found!"
            h_data = data[d_idx:end_idx]
            d_idx += len(h_data) + 2
            headers[delim].append(h_data)
        
        display_headers = [val if is_ascii(val) else '0x'+binascii.b2a_hex(val) for val in headers[delim]]
        print("header[{}]: {}".format(delim, ' '.join(display_headers)))
        h_idx += 1

    return headers, d_idx

def get_5a_keys(headers):
    k1, k2, k3 = map(ord, headers[5][0][0:3])
    
    return k1, k2, k3

def get_31_keys(headers):
    k = binascii.a2b_hex(headers['&'][0])
    k1, k2, k3 = map(ord, k)

    return k1, k2, k3

def get_5a_firmware(data):
    print('firmware addrs: 0x{} 0x{}'.format(
        binascii.b2a_hex(data[0:4]),
        binascii.b2a_hex(data[4:8])
    ))

    return data[8:]

def get_31_firmware(data):
    firmware = list()
    chunk_size = 130
    data_size = chunk_size - 2
    addr_next = 0
    for i in xrange(0, len(data), chunk_size):
        addr = (ord(data[i]) << 12) | (ord(data[i+1]) << 4)
        assert addr >= addr_next, "address decreased"
        # fill any address gaps with None
        skipped_bytes = addr - addr_next
        if skipped_bytes:
            # print "skipped_bytes", skipped_bytes
            firmware.extend([None] * skipped_bytes)
        firmware += data[i+2:i+data_size+2]
        addr_next = addr + data_size

    return firmware

def decrypt_firmware(key1, key2, key3, encrypted, search_value):
    operators = [
        { 'fn': operator.__xor__, 'sym': '^' },
        { 'fn': operator.__and__, 'sym': '&' },
        { 'fn': operator.__or__,  'sym': '|' },
        { 'fn': operator.__add__, 'sym': '+' },
        { 'fn': operator.__sub__, 'sym': '-' },
    ]

    keys = [
        { 'val': key1, 'sym': 'k1' },
        { 'val': key2, 'sym': 'k2' },
        { 'val': key3, 'sym': 'k3' },
    ]

    print('firmware search text: {}'.format(search_value))
    firmware_candidates = list()

    key_perms = list(itertools.permutations(keys))
    op_perms = list(itertools.product(operators, repeat=3))
    display_ciphers = list()
    for o1, o2, o3 in op_perms:
        for k1, k2, k3 in key_perms:
            decoder = get_decoder(
                k1['val'], k2['val'], k3['val'],
                o1['fn'], o2['fn'], o3['fn'])
            
            if len(decoder) != 256:
                continue

            data = map(lambda x: '\x00' if x is None else decoder[x], encrypted)
            decrypted = ''.join(data)
            sys.stdout.write('.')
            sys.stdout.flush()
            if search_value in decrypted and decrypted not in firmware_candidates:
                firmware_candidates.append(decrypted)
                display_ciphers.append(
                    "(((i {} {}) {} {}) {} {}) & 0xFF".format(
                        o1['sym'], k1['sym'],
                        o2['sym'], k2['sym'],
                        o3['sym'], k3['sym']))
    print("")
    for cipher in display_ciphers:
        print("cipher: {}".format(cipher))
    return firmware_candidates

def get_decoder(key1, key2, key3, op1, op2, op3):
    decoder = {}

    for i in range(256):
        e = op3(op2(op1(i, key1), key2), key3) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def get_checksum(data):
    result = -sum(map(ord, data))
    return chr(result & 0xFF)

def write_firmware(data, file_name):
    with open(file_name, 'wb') as o:
        o.write(data)
    print('firmware: {}'.format(file_name))

def main():
    get_headers = {
        "Z": get_5a_headers,
        "1": get_31_headers,
    }

    get_keys = {
        "Z": get_5a_keys,
        "1": get_31_keys,
    }

    get_firmware = {
        "Z": get_5a_firmware,
        "1": get_31_firmware,
    }

    checksums = {
        "39990-TV9-A910": [
            (0x01f1e, 0x07fff),
            (0x08000, 0x225ff),
            (0x23200, 0x271ff),
            (0x27200, 0x295ff),
        ],
    }

    # read data from file
    f_name, f_ext = os.path.splitext(sys.argv[1])
    f_base = os.path.basename(f_name)
    open_fn = open
    if f_ext == ".gz":
        open_fn = gzip.open
        f_name, f_ext = os.path.splitext(f_name)

    with open_fn(sys.argv[1], 'rb') as f:
        raw_data = f.read()

    # validate checksum for entire file
    file_checksum_expected, file_checksum_actual = get_file_checksum(raw_data)
    print("file checksum: {} = {}".format(
        hex(file_checksum_expected),
        hex(file_checksum_actual)))
    assert file_checksum_expected == file_checksum_actual, "file checksum mismatch"

    # determine file format from indicator bytes
    indicator_len = 3
    file_fmt = raw_data[0:indicator_len].strip()
    print("file format: {} = 0x{}".format(file_fmt, binascii.b2a_hex(file_fmt)))
    assert file_fmt in get_headers, "indicator bytes not recognized"

    # extract file headers
    headers, headers_len = get_headers[file_fmt](raw_data[indicator_len:])
    k1, k2, k3 = get_keys[file_fmt](headers)
    print("keys: {} {} {}".format(hex(k1), hex(k2), hex(k3)))

    # extract encrypted firmware (last for bytes are checksum for entire file)
    firmware_start = indicator_len + headers_len
    encrypted = get_firmware[file_fmt](raw_data[firmware_start:-4])

    # attempt to decrypt firmware (validate by searching for part number in decrypted bytes)
    part_num_prefix = f_base.replace('-','').replace('_', '')
    part_num_prefix = part_num_prefix[0:5] + '-' + part_num_prefix[5:8] + '-' + part_num_prefix[8:12]
    firmware_candidates = decrypt_firmware(k1, k2, k3, encrypted, part_num_prefix)
    if not len(firmware_candidates):
        print("decryption failed!")
        print("(could not find a cipher that results in the part number being in the data)")
        exit(1)

    # validate known checksums
    if f_base in checksums.keys():
        idx = 0
        for firmware in firmware_candidates:
            print("firmware[{}] checksums:".format(idx))
            match = True
            for start, end in checksums[f_base]:
                sum = ord(get_checksum(firmware[start:end]))
                chk = ord(firmware[end])
                print("{} {} {}".format(hex(chk), "=" if chk == sum else "!=", hex(sum)))
                if sum != chk:
                    match = False
            
            if match:
                print("checksums good!")
                f_out = f_name + '.bin'
                write_firmware(firmware, f_out)
                break

            idx += 1

        if not match:
            print("failed to find firmware!")
    else:
        # sometimes more than one set of keys will result in the part number being found
        # without known checksums we can't really tell which firmware file is correct
        if len(firmware_candidates) > 1:
            print("multiple sets of keys resulted in data containing the part number")
            print("which firmware file is correct?  who knows!")

        idx = 1
        # write out decrypted firmware files
        for firmware in firmware_candidates:
            f_idx = "" if len(firmware_candidates) == 1 else "." + str(idx)
            f_out = f_name + f_idx + '.bin'
            write_firmware(firmware, f_out)
            idx += 1


if __name__== "__main__":
    main()
