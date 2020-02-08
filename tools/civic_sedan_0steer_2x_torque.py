#!/usr/bin/env python3
#
# civic sedan 2x torque and 0steer
#
import os
import sys
import argparse
import subprocess
import struct

original_torque_table = [0x1680,  0x1680]


new_torque_table = [0x21C0, 0x2D00]

original_filter_table = [0x108, 0x108]

new_filter_table = [0x400, 0x480]

version_addr = 0x4b436 #other possible offsets: 0x4b48f, 0x4b4e8, 0x4b541, 0x4b59a, 0x4b5f3, 0x4b64c, 0x4b6a5, 0x4b6fe, 0x4b757, 0x4b7b0
speed_clamp_lo_addr = 0x13545
torque_table_start_addr = 0x137ba
filter_table_start_addr = 0x13a0c
torque_table_size = len(original_torque_table) * 2
filter_table_size = len(original_filter_table) * 2

def main():
  # example: python3 /Users/jo/rwd-xray/tools/crv_0steer_2x_torque.py --input_bin /Users/jo/user.bin

  parser = argparse.ArgumentParser()
  parser.add_argument("--input_bin", required=True, help="Full firmware binary file")
  args = parser.parse_args()

  with open(args.input_bin, 'rb') as f:
    full_fw = f.read()
    # Verify the table data
    cur_table = full_fw[torque_table_start_addr:(torque_table_start_addr + torque_table_size)]
    original_torque_table_bytes = bytearray()
    for v in original_torque_table:
      original_torque_table_bytes += struct.pack('!H', v)
    assert cur_table == original_torque_table_bytes, 'Incorrect full fw bin, torque table mismatched.'
    cur_table = full_fw[filter_table_start_addr:(filter_table_start_addr + filter_table_size)]
    original_filter_table_bytes = bytearray()
    for v in original_filter_table:
      original_filter_table_bytes += struct.pack('!H', v)
    assert cur_table == original_filter_table_bytes, 'Incorrect full fw bin, filter table mismatched.'

    # Build new table data
    new_fw = bytearray()
    new_fw += full_fw[:speed_clamp_lo_addr]
    new_fw.append(0x00)
    new_fw += full_fw[(speed_clamp_lo_addr + 1):torque_table_start_addr]
    for v in new_torque_table:
      new_fw += struct.pack('!H', v)
    new_fw += full_fw[(torque_table_start_addr + torque_table_size):filter_table_start_addr]
    for v in new_filter_table:
      new_fw += struct.pack('!H', v)
    new_fw += full_fw[(filter_table_start_addr + filter_table_size):version_addr]
    new_fw.append(0x2c)
    new_fw += full_fw[(version_addr + 1):]
    assert len(full_fw) == len(new_fw), 'New fw length error {}.'.format(len(new_fw))
    out_bin_path = os.path.join(os.path.dirname(args.input_bin), '{}_{}x.bin'.format(os.path.basename(args.input_bin).split('.')[0], '0steer_2'))
    with open(out_bin_path, 'wb') as out_f:
      out_f.write(new_fw)
      print('New fw bin saved to %s.' % out_bin_path)
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    cmds = [
      'python3',
      'bin_to_rwd.py',
      '--input_bin', out_bin_path,
      '--model',  '39990-TBA-A030'
    ]
    subprocess.check_call(cmds, cwd=cur_dir)
    print('RWD file %s created.' % (out_bin_path[:-4] + '.rwd'))

if __name__== "__main__":
    main()
