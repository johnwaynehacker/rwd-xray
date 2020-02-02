#!/usr/bin/env python3
#
# civic hatch 2x torque and 0steer
#
import os
import sys
import argparse
import subprocess
import struct

original_torque_table = [
  0x0, 0x2a1, 0x692, 0xaee, 0xeb6, 0x10ae, 0x1200, 0x1200, 0x1200,
  0x0, 0x746, 0xb04, 0xcdf, 0xe19, 0x1008, 0x1200, 0x1200, 0x1200,
  0x0, 0x746, 0xb04, 0xcdf, 0xe19, 0x1008, 0x1200, 0x1200, 0x1200,
  0x0, 0x746, 0xb04, 0xcdf, 0xe19, 0x1008, 0x1200, 0x1200, 0x1200,
  0x0, 0x746, 0xb04, 0xcdf, 0xe19, 0x1008, 0x1200, 0x1200, 0x1200,
  0x0, 0x746, 0xb04, 0xcdf, 0xe19, 0x1008, 0x1200, 0x1200, 0x1200,
  0x0, 0x6B3, 0xB1a, 0xccd, 0xe9a, 0x104d, 0x119a, 0x11da, 0x11da]

new_torque_table = [
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400,
0x0, 	0xA70, 	0x1200, 	0x1766, 	0x1B00, 	0x1E3D, 	0x20C2, 	0x22C6, 	0x2400]

version_addr = 0x4b4ea #other possible offsets: 0x4b543, 0x4b59c, 0x4b5f5, 0x4b64e, 0x4b6a7, 0x4b700
torque_table_start_addr = 0x13812
speed_clamp_lo_addr = 0x135bd
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
    new_fw += full_fw[:version_addr]
    new_fw.append(0x2c)
    new_fw += full_fw[(version_addr + 1):speed_clamp_lo_addr]
    new_fw.append(0x00)
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
      '--model',  '39990-TEA-T330'
    ]
    subprocess.check_call(cmds, cwd=cur_dir)
    print('RWD file %s created.' % (out_bin_path[:-4] + '.rwd'))

if __name__== "__main__":
    main()
