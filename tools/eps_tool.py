# place stock user.bin in /rwd-xray/tools and run 'python3 eps_tool.py'

import os
import sys
import subprocess
import struct
import hashlib
import binascii

default_decrypt_lookup_table = {144: 72, 218: 55, 255: 255, 164: 1, 195: 26, 99: 2, 28: 178, 205: 158, 125: 138, 45: 118, 222: 98, 142: 78, 62: 58, 243: 38, 163: 18, 83: 254, 3: 234, 172: 214, 92: 194, 12: 174, 189: 154, 109: 134, 29: 114, 206: 94, 126: 74, 46: 54, 227: 34, 147: 14, 113: 0, 67: 250, 236: 230, 156: 210, 76: 190, 252: 170, 173: 150, 93: 130, 13: 110, 148: 253, 120: 159, 199: 148, 198: 137, 77: 126, 23: 104, 73: 83, 203: 73, 78: 62, 123: 53, 254: 42, 43: 33, 90: 23, 161: 12, 10: 3, 132: 249, 191: 239, 226: 220, 197: 201, 248: 191, 117: 181, 34: 172, 37: 161, 88: 151, 141: 142, 8: 131, 134: 121, 185: 111, 54: 101, 190: 90, 57: 79, 128: 68, 139: 57, 14: 46, 138: 35, 131: 10, 100: 241, 1: 228, 146: 200, 133: 185, 168: 171, 104: 155, 40: 139, 251: 85, 94: 66, 91: 45, 103: 124, 55: 112, 231: 156, 80: 56, 224: 92, 102: 113, 96: 60, 98: 188, 97: 252, 140: 206, 122: 31, 232: 187, 16: 40, 202: 51, 26: 7, 239: 251, 5: 153, 219: 77, 119: 128, 21: 157, 238: 102, 180: 5, 217: 119, 30: 50, 7: 100, 32: 44, 183: 144, 50: 176, 110: 70, 157: 146, 2: 164, 44: 182, 145: 8, 58: 15, 27: 29, 64: 52, 9: 67, 31: 199, 179: 22, 42: 11, 193: 20, 211: 30, 129: 4, 241: 32, 74: 19, 178: 208, 247: 160, 112: 64, 242: 224, 114: 192, 165: 193, 0: 36, 59: 37, 196: 9, 154: 39, 75: 41, 72: 147, 249: 127, 162: 204, 130: 196, 229: 209, 182: 133, 48: 48, 86: 109, 240: 96, 137: 99, 151: 136, 209: 24, 108: 198, 181: 197, 212: 13, 244: 21, 11: 25, 118: 117, 228: 17, 214: 141, 52: 229, 160: 76, 115: 6, 106: 27, 56: 143, 25: 71, 36: 225, 194: 212, 208: 88, 187: 69, 171: 65, 153: 103, 38: 97, 207: 243, 82: 184, 184: 175, 188: 218, 213: 205, 121: 95, 15: 195, 81: 248, 24: 135, 70: 105, 150: 125, 174: 86, 158: 82, 220: 226, 201: 115, 71: 116, 51: 246, 177: 16, 176: 80, 22: 93, 39: 108, 159: 231, 223: 247, 186: 47, 169: 107, 245: 213, 235: 81, 192: 84, 124: 202, 175: 235, 84: 237, 79: 211, 234: 59, 143: 227, 237: 166, 33: 236, 253: 106, 65: 244, 111: 219, 200: 179, 101: 177, 17: 232, 20: 221, 166: 129, 60: 186, 61: 122, 167: 140, 204: 222, 87: 120, 41: 75, 135: 132, 136: 163, 49: 240, 250: 63, 107: 49, 170: 43, 18: 168, 221: 162, 35: 242, 225: 28, 149: 189, 85: 173, 152: 167, 95: 215, 53: 165, 89: 87, 66: 180, 6: 89, 47: 203, 210: 216, 215: 152, 233: 123, 116: 245, 127: 223, 19: 238, 69: 169, 105: 91, 4: 217, 216: 183, 68: 233, 63: 207, 155: 61, 246: 149, 230: 145}

def param_to_data_string(param):
    # strip leading '0x'
    param = param.replace('0x','')
    param = param.replace(', ','')
    # pad to even number of characters (required by binascii)
    if len(param) % 2 == 1:
        param = '0' + param
    return binascii.a2b_hex(param)

def generate_file_header(indicator, headers):
    header_bytes = indicator
    for header in headers:
        header_bytes += chr(len(header))
        for item in header:
            header_bytes += chr(len(item.encode())) + str(item)
    return header_bytes

def checksum_by_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += struct.unpack('!H', fw[i:i + 2])[0]
  return s

# sum of -x, x is unsigned shorts
def checksum_by_negative_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += -struct.unpack('!H', fw[i:i + 2])[0]
  return s

checksum_funcs = [checksum_by_sum, checksum_by_negative_sum]

def main():
    hash_md5 = hashlib.md5()
    with open(os.path.join(sys.path[0], "user.bin"), "rb+") as f:
        input_bin = f.read()
        fw_bytes = f
        if len(input_bin) == 393216:
            data_size = 0x4c000
            checksum_offsets = [(0, 0x4bf80), (1, 0x4bffe)] #original bin checksums are at offsets 0x4FF80 and 0x4FFFE, but since we start the bin from 0x4000 after bootloader, we offset the checksum accordingly
        elif len(input_bin) == 524288:
            data_size = 0x6c000
            checksum_offsets = [(0, 0x6bf80), (1, 0x6bffe)] #original bin checksums are at offsets 0x6FF80 and 0x6FFFE, but since we start the bin from 0x4000 after bootloader, we offset the checksum accordingly
        hash = hashlib.md5(input_bin).hexdigest()
        if hash == '79b695a73fd5ff22cbfeb4b83908ab29': #CR-V thanks to joe1
            print('Detected bin: 39990-TLA-A040 Honda CR-V')
            supported_versions = ['39990-TLA-A030\x00\x00', '39990-TLA-A040\x00\x00', '39990-TLA,A040\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0xf8db, 0xf936, 0xf991, 0xf9ec, 0xfa47, 0xfaa2, 0xfafd, 0xfb58, 0xfbb3, 0xfc0e, 0xfc69, 0xfcc4]
            version_old = b'39990-TLA-A040'
            version_new = b'39990-TLA,A040'
            data_offsets = [
                0x11908, #speed_clamp_lo
                0x11b5e, #torque_table row 0
                0x11db0, #filter_table row 0
                0x11eac, #new_table row 0
                0x119ae, #speed_table row 0
                ]
            data_old = [
                '0x0028', #speed_clamp_lo
                '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', #torque_table row 0
                '0x009f, 0x0100, 0x0180, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6', #filter_table row 0
                '0x0021, 0x004d, 0x0096, 0x00c0, 0x00cb, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 0
                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 0
                ]
            data_new = [
                '0x0000', #speed_clamp_lo
                '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x2000, 0x2e00, 0x3C00', #torque_table row 0
                '0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200', #filter_table row 0
                '0x0021, 0x004d, 0x0096, 0x00c0, 0x00c7, 0x00c7, 0x00c7, 0x00c7, 0x00c7', #new_table row 0
                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 0
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 0',
                'filter_table row 0',
                'new_table row 0',
                'speed_table row 0'
                ]
        elif hash == '9ccedbdd7d4d8d0eb356fadcc763353d':
            print('Detected bin: 39990-TBA-A030 Honda Civic Sedan')
            car_model = '39990-TBA-A030'  #civic sedan thanks to mystery leaker
            supported_versions = ['39990-TBA-A010\x00\x00', '39990-TBA-A030\x00\x00', '39990-TBA,A030\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b42d, 0x4b486, 0x4b4df, 0x4b538, 0x4b591, 0x4b5ea, 0x4b643, 0x4b69c, 0x4b6f5, 0x4b74e, 0x4b7a7]
            version_old = b'39990-TBA-A030'
            version_new = b'39990-TBA,A030'
            data_offsets = [
                0x13544, #speed_clamp_lo
                0x137ac, #torque_table row 1
                0x139fe, #filter_table row 1
                ]
            data_old = [
                '0x0028', #speed_clamp_lo
                '0x0000, 0x0917, 0x0dc5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', #torque_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', #filter_table row 1
                ]
            data_new = [
                '0x0000',
                '0x0000, 0x0917, 0x0dc5, 0x1017, 0x119f, 0x140b, 0x1680, 0x21C0, 0x2D00', #torque_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', #filter_table row 1
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 1',
                'filter_table row 1',
                ]
        elif hash == 'aafcf594418ba625fa439a0e52ee7d36': #civic hatch au thanks to ming
            print('Detected bin: 39990-TEA-T330 Honda Civic Hatch (Australia)')
            supported_versions = ['39990-TEA-T310\x00\x00', '39990-TEA-T330\x00\x00', '39990-TEA,T330\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b4e1, 0x4b53a, 0x4b593, 0x4b5ec, 0x4b645, 0x4b69e, 0x4b6f7]
            version_old = b'39990-TEA-T330'
            version_new = b'39990-TEA,T330'
            data_offsets = [
                0x135bc, #speed_clamp_lo
                0x13824, #torque_table row 1
                0x13a76, #filter_table row 1
                ]
            data_old = [
                '0x0028', #speed_clamp_lo
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', #torque_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', #filter_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1B00, 0x2400', #torque_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', #filter_table row 1
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 1',
                'filter_table row 1',
                ]
        elif hash == '11ba08b27a643c3e3b23bbd08463a40e': #civic hatch thanks to R3DLOBST3R
            print('Detected bin: 39990-TGG-A120 Honda Civic Hatch')
            supported_versions = ['39990-TGG-A110\x00\x00', '39990-TGG-A120\x00\x00', '39990-TGG,A120\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b541, 0x4b59a, 0x4b5f3, 0x4b64c, 0x4b6a5]
            version_old = b'39990-TGG-A120'
            version_new = b'39990-TGG,A120'
            data_offsets = [
                0x135c0, #speed_clamp_lo
                0x13816, #torque_table row 0
                0x13828, #torque_table row 1
                0x13a68, #filter_table row 0
                0x13a7a, #filter_table row 1
                ]
            data_old = [
                '0x0028', #speed_clamp_lo
                '0x0000, 0x0380, 0x0800, 0x0c00, 0x0eb6, 0x10ae, 0x1200, 0x1200, 0x1200', #torque_table row 0
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', #torque_table row 1
                '0x00c0, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a', #filter_table row 0
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', #filter_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', #torque_table row 0
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1B00, 0x2400', #torque_table row 1
                '0x00c0, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a, 0x011a, 0x0400, 0x0480', #filter_table row 0
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', #filter_table row 1
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 1',
                'filter_table row 1',
                ]
        elif hash == '3f0c3b65ed8f105673b2bc6d9933fa10': #clarity thanks to wirelessnet2
            print('Detected bin: 39990-TRW-A020 Honda Clarity')
            supported_versions = ['39990-TRW-A010\x00\x00', '39990-TRW-A020\x00\x00', '39990-TRW,A020\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4ba1d, 0x4ba76, 0x4bacf, 0x4bb28, 0x4bb81, 0x4bbda]
            version_old = b'39990-TRW-A020'
            version_new = b'39990-TRW,A020'
            data_offsets = [
                0x13638, #speed_clamp_lo
                0x1388e, #torque_table row 0
                0x13ae0, #filter_table row 0
                0x13bdc, #new_table row 0
                ]
            data_old = [
                '0x000a', #speed_clamp_lo
                '0x0000, 0x0580, 0x0a00, 0x0d00, 0x0f00, 0x10c0, 0x11ff, 0x1300, 0x1400', #torque_table row 0
                '0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200', #filter_table row 0
                '0x004d, 0x0066, 0x0080, 0x009a, 0x00b3, 0x00c0, 0x00c0, 0x00c0, 0x00c0', #new_table row 0
                ]
            data_new = [
                '0x0000', #speed_clamp_lo
                '0x0000, 0x0580, 0x0a00, 0x0d00, 0x0f00, 0x10c0, 0x11ff, 0x1300, 0x2800', #torque_table row 0
                '0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0280', #filter_table row 0
                '0x004d, 0x0066, 0x0080, 0x009a, 0x00b3, 0x00c0, 0x00c0, 0x00c0, 0x00ff', #new_table row 0
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 0',
                'filter_table row 0',
                ]
        elif hash == '87114e2d4ec30c336dde9820f8a09620': #insight thanks to fkndean
            print('Detected bin: 39990-TXM-A040 Honda Insight')
            supported_versions = ['39990-TXM-A010\x00\x00', '39990-TXM-A040\x00\x00', '39990-TXM,A040\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0xecdf, 0xed3a, 0xed95, 0xedf0, 0xf7e4, 0xf83f]
            version_old = b'39990-TXM-A040'
            version_new = b'39990-TXM,A040'
            data_offsets = [
                0x11964, #speed_clamp_lo
                0x11bba, #torque_table row 0
                0x11e0c, #filter_table row 0
                0x11f08, #new_table row 0
                0x11a0a, #speed_table row 0
                ]
            data_old = [
                '0x000a', #speed_clamp_lo
                '0x0000, 0x0500, 0x0800, 0x0a80, 0x0ce6, 0x1000, 0x1180, 0x1200, 0x1300', #torque_table row 0
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #filter_table row 0
                '0x0033, 0x0080, 0x009a, 0x00b3, 0x00b8, 0x00b8, 0x00b8, 0x00b8, 0x00b8', #new_table row 0
                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 0
                ]
            data_new = [
                '0x0000', #speed_clamp_lo
                '0x0000, 0x0500, 0x0800, 0x0a80, 0x0ce6, 0x1000, 0x1180, 0x1200, 0x2600', #torque_table row 0
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #filter_table row 0
                '0x0033, 0x0080, 0x009a, 0x00b3, 0x00b8, 0x00b8, 0x00b8, 0x00b8, 0x00b8', #new_table row 0
                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 0
            #    0   	 15.5    31.1    46.6    62.1    77.7    93.2    108.7   124.3    #mph breakpoints for torque limit
                ]
            data_label = [
                'speed_clamp_lo',
                'torque_table row 0',
                'filter_table row 0',
                'new_table row 0',
                'speed_table row 0'
                ]
        else:
             print('unsupported fw')
             sys.exit()


## do patch
    with open(os.path.join(sys.path[0], "user_patched.bin"), 'wb+') as output_bin:
        output_bin.write(input_bin)
        for version_offset in version_offsets:
            output_bin.seek(version_offset)
            #validate original version
            version_old_actual = output_bin.read(int(len(version_old)))
            assert version_old_actual == version_old, 'Check version at offset {}: expected {} but found {}'.format(hex(version_offset), version_old, version_old_actual.decode())
            #validate new version length
            assert len(version_old) == len(version_new), 'New version length error. {} is {} bytes, {} is {} bytes.'.format(version_old, len(version_old), version_new, len(version_new))
            output_bin.seek(version_offset)
            output_bin.write(version_new)
            print("Update version at offset {} from {} to {}".format(hex(version_offset), version_old.decode(), version_new.decode()))
        for data_offsets, data_old, data_new, data_label in zip(data_offsets, data_old, data_new, data_label):
            if data_new != data_old:
                data_old_bytes = param_to_data_string(data_old)
                data_new_bytes = param_to_data_string(data_new)
                output_bin.seek(data_offsets)
                #validate original data
                data_old_actual = output_bin.read(int(len(data_old_bytes.hex())/2))
                assert data_old_actual == data_old_bytes, 'Check {} at offset {}: expected {} but found {}'.format(data_label, hex(data_offsets), str(data_old_bytes), str(data_old_actual))
                #validate original data length
                assert len(data_old) == len(data_new), '{} data length error. {} is {} bytes, {} is {} bytes'.format(data_label, data_old, len(data_old_bytes), data_new, len(data_new_bytes))
                output_bin.seek(data_offsets)
                output_bin.write(data_new_bytes)
                print("Update {} at offset {} from".format(data_label, hex(data_offsets)))
                print("{} to".format(str(data_old)))
                print("{}".format(str(data_new)))
    with open(os.path.join(sys.path[0], "user_patched.bin"), 'rb+') as f:
        full_fw = f.read()
        patch_fw = full_fw[0x4000:(0x4000 + data_size)]
    for func_idx, off in checksum_offsets:
        old_checksum = struct.unpack('!H', patch_fw[off:off+2])[0]
        new_checksum = checksum_funcs[func_idx](patch_fw, 0, off) & 0xFFFF
        print('Update checksum at offset {} from {} to {}'.format(hex(off),  hex(old_checksum), hex(new_checksum)))
        patch_fw = patch_fw[:off] + struct.pack('!H', new_checksum & 0xFFFF) + patch_fw[off+2:]
        #validate patched fw length
    with open(os.path.join(sys.path[0], "user_patched.bin"), 'rb') as output_bin:
        new_fw = output_bin.read()
        with open(os.path.join(sys.path[0], "user.bin"), 'rb') as input_bin:
            old_fw = input_bin.read()
            assert len(new_fw) == len(old_fw), 'New fw length error. Old:{}, New:{}'.format(len(old_fw), len(new_fw))
    print('Patch done, saved to {}. Encrypting...'.format(os.path.join(sys.path[0], "user_patched.bin")))


## do encryption
    encrypt_lookup_table = {}
    for k, v in default_decrypt_lookup_table.items():
        encrypt_lookup_table[v] = k
    encrypted = bytearray()
    for b in patch_fw:
        encrypted.append(encrypt_lookup_table[b])
    out_enc_path = os.path.join(sys.path[0], "user_patched.enc")
    with open(out_enc_path, 'wb') as out_f:
        out_f.write(encrypted)
        print('Encryption done, saved to {}. Building RWD...'.format(out_enc_path))


## build rwd
    start_addr = param_to_data_string(hex(0x4000))
    data_siz = param_to_data_string(hex(data_size))

    indicator = '\x5A\x0D\x0A' # CAN format
    headers = [
        ['\x00'], # always zero
        [], # always empty
        ['\x30'], # significant byte in 29 bit addr (0x18da__f1)
        supported_versions, # previous firmware version(s)
        security_key, # security access key (one per prev firmware version)
        ['\x01\x02\x03'], # firmware encryption key
    ]

    for i in range(len(headers)):
        print('[Header {}]: {}'.format(i, headers[i]))

    rwd_header_bytes = generate_file_header(indicator, headers)

    rwd_start_len = start_addr.rjust(4, b'\x00') + data_siz.rjust(4, b'\x00')
    file_checksum = sum(rwd_header_bytes.encode()+rwd_start_len+encrypted) & 0xFFFFFFFF

    print('File checksum: {}'.format(hex(file_checksum)))
    rwd_checksum_bytes = struct.pack('<L', file_checksum)

    out_rwd_path = os.path.join(sys.path[0], "user_patched.rwd")
    with open(out_rwd_path, 'wb+') as f:
        f.write(rwd_header_bytes.encode())
        f.write(rwd_start_len)
        f.write(encrypted)
        f.write(rwd_checksum_bytes)

    print('RWD file built, saved to {}.'.format(out_rwd_path))
    print("Done!")


main()
