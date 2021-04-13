#!/usr/bin/env python
import os
import sys
import struct
import gzip
import binascii

def main():
    folder = sys.argv[1]

    formats = {}
    for item in os.listdir(folder):
        path = os.path.join(folder, item)
        if not os.path.isfile(path):
            continue
        with gzip.open(path, 'rb') as f:
            indicator = f.read(3)
            assert indicator[1:3] == "\x0d\x0a"
            if indicator not in formats:
                formats[indicator] = { 'count': 0 }
            formats[indicator]['count'] += 1

    print('indicator bytes')
    for indicator in formats:
        ind_bytes = binascii.b2a_hex(indicator)
        ind_count = formats[indicator]['count']
        print('{} : {}'.format(ind_bytes, ind_count))

if __name__== "__main__":
    main()
