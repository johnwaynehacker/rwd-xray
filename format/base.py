import sys
import struct
import operator
import itertools
import re

class Base(object):
    def __init__(self, data, headers, keys, addr_blocks, encrypted):
        self._file_format = data[0:1]
        self._file_headers = headers
        self._file_checksum = struct.unpack('<L', data[-4:])[0]
        self._firmware_blocks = addr_blocks
        self._firmware_encrypted = encrypted
        self._keys = keys

        self.validate_file_checksum(data)

    @property
    def file_format(self):
        return self._file_format

    @property
    def file_checksum(self):
        return self._file_checksum

    @property
    def file_headers(self):
        return self._file_headers

    @property
    def firmware_blocks(self):
        return self._firmware_blocks

    @property
    def firmware_encrypted(self):
        return self._firmware_encrypted

    @property
    def keys(self):
        return self._keys

    def calc_checksum(self, data):
        result = -sum(map(ord, data))
        return chr(result & 0xFF)

    def validate_file_checksum(self, data):
        calculated = sum(map(ord, data[0:-4])) & 0xFFFFFFFF
        assert calculated == self.file_checksum, "file checksum mismatch"

    def _get_decoder(self, key1, key2, key3, op1, op2, op3):
        decoder = {}
        values = set()

        for e in range(256):
            d = op3(op2(op1(e, key1), key2), key3) & 0xFF
            decoder[chr(e)] = chr(d)
            values.add(d)

        return decoder if len(values) == 256 else None

    def decrypt(self, search_value):
        search_value_padded = ''.join(map(lambda c: c + '.', search_value))
        print("search:")
        print(search_value)
        print(search_value_padded)

        search_exact = re.compile('.*'+search_value+'.*', flags=re.IGNORECASE|re.MULTILINE|re.DOTALL)
        # sometimes there is an extra character after each character
        # 37805-RBB-J530 -> 3377880550--RRBCBA--JA503000
        search_padded = re.compile('.*'+search_value_padded+'.*', flags=re.IGNORECASE|re.MULTILINE|re.DOTALL)
        operators = [
            { 'fn': operator.__xor__, 'sym': '^' },
            { 'fn': operator.__and__, 'sym': '&' },
            { 'fn': operator.__or__,  'sym': '|' },
            { 'fn': operator.__add__, 'sym': '+' },
            { 'fn': operator.__sub__, 'sym': '-' },
            { 'fn': operator.__mul__, 'sym': '*' },
            { 'fn': operator.__div__, 'sym': '/' },
            { 'fn': operator.__mod__, 'sym': '%' },
        ]

        keys = list()
        for i in range(len(self._keys)):
            k = ord(self._keys[i])
            keys.append({ 'val': k, 'sym': 'k{}'.format(i) })
        assert len(keys) == 3, "excatly three keys currently required!"

        firmware_candidates = list()

        key_perms = list(itertools.permutations(keys))
        op_perms = list(itertools.product(operators, repeat=3))
        display_ciphers = list()
        attempted_decoders = list()
        for k1, k2, k3 in key_perms:
            for o1, o2, o3 in op_perms:
                decoder = self._get_decoder(
                    k1['val'], k2['val'], k3['val'],
                    o1['fn'], o2['fn'], o3['fn'])
                
                if decoder is None or decoder in attempted_decoders:
                    continue
                attempted_decoders.append(decoder)

                candidate = [map(lambda x: decoder[x], e) for e in self._firmware_encrypted]
                decrypted = ''.join([c for l in candidate for c in l])
                if (search_exact.match(decrypted) or search_padded.match(decrypted)) and candidate not in firmware_candidates:
                    sys.stdout.write('X')
                    firmware_candidates.append([''.join(c) for c in candidate])
                    display_ciphers.append(
                        "(((i {} {}) {} {}) {} {}) & 0xFF".format(
                            o1['sym'], k1['sym'],
                            o2['sym'], k2['sym'],
                            o3['sym'], k3['sym']))
                else:
                    sys.stdout.write('.')
                sys.stdout.flush()

        print("")
        for cipher in display_ciphers:
            print("cipher: {}".format(cipher))
        return firmware_candidates


    def __str__(self):
        info = [
            "file format: {}".format(self.file_format),
            "file checksum: {}".format(hex(self.file_checksum)),
        ]
        info.append("headers:")
        info.extend([str(h) for h in self._file_headers])
        info.append("keys:")
        info.extend([
            "k{} = {}".format(i, hex(ord(self._keys[i])))
            for i in range(len(self._keys))
        ])
        info.append("address blocks:")
        info.extend([
            "start = {} len = {}".format(hex(i["start"]), hex(i["length"]))
            for i in self._firmware_blocks
        ])

        return '\n'.join(info)
