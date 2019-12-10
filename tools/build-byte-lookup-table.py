#!/usr/bin/env python3
#
#  Build byte lookup table from full fw bin and rwd encrypted data
#
import os
import sys
import argparse
import subprocess
import struct

from bin_to_rwd import decrypt_lookup_table as crv_enc_lookup_table

RWD_PATCH_START_ADDR = 0x4000

def main():
  # Example: python3 build-byte-lookup-table.py --input_bin civic-stock.bin --input_enc 39990-TBA-A030-M1.enc
  # The encryption file can be generated using rwd-xray.py: python2 wd-xray.py 39990-TBA-A030-M1.wd.gz

  parser = argparse.ArgumentParser()
  parser.add_argument("--input_bin", required=True, help="Full firmware binary file")
  parser.add_argument("--input_enc", required=True, help="Encrypted data from offcial honda rwd file")
  args = parser.parse_args()

  if not os.path.exists(args.input_bin):
    print('%s not found' % args.input_bin)
    sys.exit(-1)

  if not os.path.exists(args.input_enc):
    print('%s not found' % args.input_enc)
    sys.exit(-1)

  decrypt_lookup_table = {}

  with open(args.input_bin, 'rb') as f:
    full_fw = f.read()

  with open(args.input_enc, 'rb') as f:
    rwd_enc = f.read()

  for i in range(len(rwd_enc)):
    if rwd_enc[i] in decrypt_lookup_table and decrypt_lookup_table[rwd_enc[i]] != full_fw[RWD_PATCH_START_ADDR + i]:
      print('Build failed. The code in rwd is not the same as in firmware binary.')
      sys.exit(-2)
    decrypt_lookup_table[rwd_enc[i]] = full_fw[RWD_PATCH_START_ADDR + i]

  print('decrypt_lookup_table =', decrypt_lookup_table)

  if crv_enc_lookup_table == decrypt_lookup_table:
    print('The table is the same as crv/civic.')
  else:
   print('New encryption table found.')

if __name__== "__main__":
    main()
