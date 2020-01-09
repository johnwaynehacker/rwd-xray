#!/usr/bin/env python3
#
# civic sedan 2x torque and 0steer
#
import os
import sys
import argparse
import subprocess
import struct

original_torque_table = [
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680, 0x1680,
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680,  0x1680,
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680,  0x1680,
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680,  0x1680,
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680,  0x1680,
  0x0,   0x917, 0xDC5,  0x1017,  0x119F,  0x140B,  0x1680,  0x1680,  0x1680,
  0x0,   0x6B3, 0xB1A,  0xCCD,   0xE9A,   0x104D,  0x119A,  0x11DA,  0x11DA]


new_torque_table = [
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20,
0x0, 	0xD16, 	0x1690, 	0x1D54, 	0x21D8, 	0x25E7, 	0x2910, 	0x2B97, 	0x2D20]

torque_table_start_addr = 0x1379a
speed_clamp_lo_addr = 0x13545
torque_table_size = len(original_torque_table) * 2


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
    # Build new table data
    new_fw = bytearray()
    new_fw += full_fw[:speed_clamp_lo_addr]
    new_fw += bytes(1)
    new_fw += full_fw[(speed_clamp_lo_addr + 1):torque_table_start_addr]
    for v in new_torque_table:
      new_fw += struct.pack('!H', v)
    new_fw += full_fw[(torque_table_start_addr + torque_table_size):]
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
