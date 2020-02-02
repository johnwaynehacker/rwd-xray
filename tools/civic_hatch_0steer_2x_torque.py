#!/usr/bin/env python3
#
# civic hatch 2x torque and 0steer
#
import os
import sys
import argparse
import subprocess
import struct

original_torque_table = [0x1200, 0x1200]

new_torque_table = [0x1B00, 0x2400]

original_filter_table = [0x108, 0x108]

new_filter_table = [0x400, 0x480]

#original_index_table
#  0x0, 0x67, 0x107, 0x1CB, 0x294, 0x35E, 0x457, 0x60D, 0x6EE,
#  0x0, 0xDE, 0x14D, 0x1EF, 0x290, 0x377, 0x454, 0x610, 0x6EE,
#  0x0, 0xDE, 0x14D, 0x1EF, 0x290, 0x377, 0x454, 0x610, 0x6EE,
#  0x0, 0xDE, 0x14D, 0x1EF, 0x290, 0x377, 0x454, 0x610, 0x6EE,
#  0x0, 0xDE, 0x14D, 0x1EF, 0x290, 0x377, 0x454, 0x610, 0x6EE,
#  0x0, 0xDE, 0x14D, 0x1EF, 0x290, 0x377, 0x454, 0x610, 0x6EE,
#  0x0, 0xDE, 0x1BB, 0x299, 0x377, 0x455, 0x532, 0x610, 0x6EE,

##therefore correct torqueV is 0x0, 0x1C0, 0x2A0, 0x3E8, 0x52D, 0x700, 0x8BE, 0xC3F, 0xE00
version_addr = 0x4b54a #other possible offsets: 0x4b5a3, 0x4b5fc, 0x4b655, 0x4b6ae
speed_clamp_lo_addr = 0x135c1
torque_table_start_addr = 0x13836
filter_table_start_addr = 0x13a88
torque_table_size = len(original_torque_table) * 2
filter_table_size = len(original_filter_table) * 2

def main():
  # example: python3 /Users/jo/rwd-xray2/tools/crv_0steer_2x_torque.py --input_bin /Users/jo/Library/Mobile\ Documents/com\~apple\~CloudDocs/CR-V/EPS/user.bin

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
    new_fw += full_fw[:version_addr]
    new_fw.append(0x2c)
    new_fw += full_fw[(version_addr + 1):speed_clamp_lo_addr]
    new_fw.append(0x00)
    new_fw += full_fw[(speed_clamp_lo_addr + 1):torque_table_start_addr]
    for v in new_torque_table:
      new_fw += struct.pack('!H', v)
    new_fw += full_fw[(torque_table_start_addr + torque_table_size):filter_table_start_addr]
    for v in new_filter_table:
      new_fw += struct.pack('!H', v)
    new_fw += full_fw[(filter_table_start_addr + filter_table_size):]
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
      '--model',  '39990-TGG-A120'
    ]
    subprocess.check_call(cmds, cwd=cur_dir)
    print('RWD file %s created.' % (out_bin_path[:-4] + '.rwd'))

if __name__== "__main__":
    main()
