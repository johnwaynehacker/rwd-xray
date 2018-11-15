#!/usr/bin/env python
import os
import sys
import struct
import gzip
import binascii
import operator
import itertools
import importlib

def get_checksum(data):
    result = -sum(map(ord, data))
    return chr(result & 0xFF)

def write_firmware(data, file_name):
    with open(file_name, 'wb') as o:
        o.write(data)
    print('firmware: {}'.format(file_name))

def read_file(fn):
    f_name, f_ext = os.path.splitext(fn)
    f_base = os.path.basename(f_name)
    open_fn = open
    if f_ext == ".gz":
        open_fn = gzip.open
        f_name, f_ext = os.path.splitext(f_name)

    with open_fn(fn, 'rb') as f:
        f_data = f.read()
    
    return f_data

def get_part_number_prefix(fn):
    f_name, f_ext = os.path.splitext(fn)
    f_base = os.path.basename(f_name)
    part_num_prefix = f_base.replace('-','').replace('_', '')
    part_num_prefix = part_num_prefix[0:5] + '-' + part_num_prefix[5:8] + '-' + part_num_prefix[8:12]
    return part_num_prefix

def main():
    f_name = sys.argv[1]
    f_dir = os.path.dirname(f_name)
    f_base = os.path.basename(f_name).split('.')[0]
    f_raw = read_file(f_name)
    f_type = "x" + binascii.b2a_hex(f_raw[0])
    f_module = importlib.import_module("format.{}".format(f_type))
    f_class = getattr(f_module, f_type)
    fw = f_class(f_raw)
    print(fw)

    # attempt to decrypt firmware (validate by searching for part number in decrypted bytes)
    part_number_prefix = get_part_number_prefix(f_name)
    firmware_candidates = fw.decrypt(part_number_prefix)

    if not len(firmware_candidates):
        print("decryption failed!")
        print("(could not find a cipher that results in the part number being in the data)")
        exit(1)

    checksums = {
        "39990-TV9-A910": [
            (0x01f1e, 0x07fff),
            (0x08000, 0x225ff),
            (0x23200, 0x271ff),
            (0x27200, 0x295ff),
        ],
    }

    if len(firmware_candidates) > 1:
        print("multiple sets of keys resulted in data containing the part number")

    firmware_good = list()
    idx = 0
    for fc in firmware_candidates:
        # concat all address blocks to allow checksum validation using memory addresses
        firmware = ''
        for block in xrange(len(fc)):
            start = fw.firmware_blocks[block]["start"]
            # fill gaps with \x00
            if len(firmware) < start:
                firmware += '\x00' * (start-len(firmware))
            firmware += fc[block]

        # validate known checksums
        if f_base in checksums.keys():
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
                firmware_good.append(firmware)
            else:
                print("checksums bad!")
        else:
            # no checksums so assume good
            firmware_good.append(firmware)
        
        idx += 1

    # sometimes more than one set of keys will result in the part number being found
    # hopefully the checksums narrowed it down to a single candidate
    if len(firmware_good) > 1:
        print("which firmware file is correct?  who knows!")

    idx = 1
    # write out decrypted firmware files
    for f_data in firmware_good:
        start_addr = fw.firmware_blocks[0]["start"]
        f_addr = hex(start_addr)
        f_out = os.path.join(f_dir, f_base + '.' + f_addr + '.bin')
        write_firmware(f_data[start_addr:], f_out)
        idx += 1

if __name__== "__main__":
    main()
