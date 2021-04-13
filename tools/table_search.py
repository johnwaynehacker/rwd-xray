import os
import sys
import binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-bytes", required=True, help="Table row length in bytes")
args = parser.parse_args()

def main():
    with open(os.path.join(sys.path[0], "user.bin"), "rb+") as input_bin:
        cur_pos = 0
        len = int(args.bytes)
        next_pos = cur_pos + len
        excludes = [
        b'6265622d352c6265622d352c6265622d352c',
        b'ffffffffffffffffffffffffffffffffffff',
        b'000000000000000000000000000000000000',
        b'65622d352c6265622d352c6265622d352c62',
        b'622d352c6265622d352c6265622d352c6265',
        b'2d352c6265622d352c6265622d352c626562',
        b'352c6265622d352c6265622d352c6265622d',
        b'2c6265622d352c6265622d352c6265622d35'
        ]
        for i in input_bin:
            input_bin.seek(cur_pos)
            dat_1 = input_bin.read(len)
            input_bin.seek(next_pos)
            dat_2 = input_bin.read(len)
            if dat_1 == dat_2 and binascii.hexlify(dat_1) not in excludes:
                print("Match! Address: {} Data: {}".format(hex(cur_pos), binascii.hexlify(dat_1)))
                cur_pos = cur_pos + len
                next_pos = next_pos + len
            else:
                cur_pos = cur_pos + 1
                next_pos = next_pos + 1
main()
