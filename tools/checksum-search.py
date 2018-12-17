import sys
import binascii
import struct

# first param is start addr (e.g. 0x4000)
start = int(sys.argv[1], 0)
# second param is firmware file name
fn = sys.argv[2]

with open(fn, 'r') as f:
  fw = f.read()
checksum = 0
for i in range(start, len(fw)-2, 2):
  checksum += struct.unpack('!H', fw[i:i+2])[0]
  packed = struct.pack('!H', checksum & 0xFFFF)
  if i > 2 and packed == fw[i+2:i+4]:
    print("found: {}".format(hex(i+2)))
    packed

# end = 0x4e5ec
# struct.pack('!H', sum([struct.unpack('!H', fw[addr:addr+2])[0] for addr in range(0x4000, end, 2)]) & 0xFFFF)
# fw[end:end+2]
