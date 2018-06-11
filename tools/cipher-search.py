#!/usr/bin/env python
import os
import sys
import operator
import binascii
import itertools

OPERATORS = [
    { 'fn': operator.__xor__, 'sym': '^' },
    { 'fn': operator.__and__, 'sym': '&' },
    { 'fn': operator.__or__,  'sym': '|' },
    { 'fn': operator.__add__, 'sym': '+' },
    { 'fn': operator.__sub__, 'sym': '-' },
]

def get_decoder(key1, key2, key3, op1, op2, op3):
    decoder = {}

    for i in range(256):
        e = op3(op2(op1(i, key1), key2), key3) & 0xFF
        decoder[chr(e)] = chr(i)

    return decoder

def main():
    keys =      binascii.a2b_hex(sys.argv[1].replace('0x','')) # ex: 0x123456
    encrypted = binascii.a2b_hex(sys.argv[2].replace('0x','')) # ex: 0x........
    decrypted = binascii.a2b_hex(sys.argv[3].replace('0x','')) # ex: 0x........

    keys = [
        { 'val': ord(keys[0]), 'sym': 'k1' },
        { 'val': ord(keys[1]), 'sym': 'k2' },
        { 'val': ord(keys[2]), 'sym': 'k3' },
    ]
    for key in keys:
        print("{}: {}".format(key['sym'], hex(key['val'])))
    print('encrypted: 0x{}'.format(binascii.b2a_hex(encrypted)))
    print('decrypted: 0x{}'.format(binascii.b2a_hex(decrypted)))

    found = False
    key_perms = list(itertools.permutations(keys))
    op_perms = list(itertools.product(OPERATORS, repeat=3))
    for o1, o2, o3 in op_perms:
        for k1, k2, k3 in key_perms:
            decoder = get_decoder(
                k1['val'], k2['val'], k3['val'],
                o1['fn'], o2['fn'], o3['fn'])
            
            if len(decoder) != 256:
                continue

            value = map(lambda x: decoder[x], encrypted)
            # print("0x{} -> 0x{}".format(
            #     binascii.b2a_hex(''.join(encrypted)),
            #     binascii.b2a_hex(''.join(value))))
            if ''.join(value) == decrypted:
                found = True
                print("cipher: (((i {} {}) {} {}) {} {}) & 0xFF".format(
                    o1['sym'], k1['sym'],
                    o2['sym'], k2['sym'],
                    o3['sym'], k3['sym']))

    if not found:
        print("cipher not found :(")

if __name__== "__main__":
    main()
