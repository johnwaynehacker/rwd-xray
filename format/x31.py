from binascii import a2b_hex

from base import Base
from header import Header
from header_value import HeaderValue

class x31(Base):
    def __init__(self, data):
        start_idx = 3 # skip file type indicator bytes
        headers, header_data_len = self._parse_file_headers(data[start_idx:])
        keys = self._get_keys(headers)

        start_idx += header_data_len
        addr_blocks, encrypted = self._get_firmware(data[start_idx:-4]) # exclude file checksum
        
        Base.__init__(self, data, headers, keys, addr_blocks, encrypted)

    def _parse_file_headers(self, data):
        headers = list()
        d_idx = 0

        for h_idx in range(6):
            h_prefix = data[d_idx:d_idx+3]
            d_idx += 3

            # delimiter is 0x__0D0A
            assert h_prefix[1:] == "\x0D\x0A", "header delimiter not found!"

            f_header = Header(h_prefix[0], h_prefix, h_prefix)
            # stop when delimiter is repeat ed
            while data[d_idx:d_idx+3] != h_prefix:
                # values delimited by 0x0D0A
                end_idx = data.find("\x0D\x0A", d_idx)
                assert end_idx != -1, "field delimiter not found!"

                v_data = data[d_idx:end_idx]
                d_idx += len(v_data)

                # skip past field delimiter
                v_suffix = data[d_idx:d_idx+2]
                d_idx += 2

                h_value = HeaderValue("", v_suffix, v_data)
                f_header.values.append(h_value)

            # skip past delimiter
            h_suffix = data[d_idx:d_idx+3]
            d_idx += 3
            assert h_prefix == h_suffix, "header prefix and suffix do not match"

            headers.append(f_header)
            
        return headers, d_idx

    def _get_keys(self, headers):
        for header in headers:
            if header.id == "&":
                assert len(header.values) == 1, "encryption key header does not have exactly one value!"
                value = a2b_hex(header.values[0].value)
                assert len(value) == 3, "encryption key header not three bytes!"
                return value

        raise Exception("could not find encryption key header!")

    def _get_firmware(self, data):
        firmware = list()
        addr_blocks = list()
        chunk_size = 130
        data_size = chunk_size - 2
        addr_next = 0
        block_start = 0
        block_data = ""
        for i in xrange(0, len(data), chunk_size):
            addr = (ord(data[i]) << 12) | (ord(data[i+1]) << 4)
            assert addr >= addr_next, "address decreased"
            if addr != addr_next:
                if len(block_data) > 0:
                    firmware.append(block_data)
                    addr_blocks.append({"start": block_start, "length": len(block_data)})
                block_start = addr
                block_data = ""
            
            block_data += data[i+2:i+data_size+2]
            addr_next = addr + data_size
        if len(block_data) > 0:
            firmware.append(block_data)
            addr_blocks.append({"start": block_start, "length": len(block_data)})

        assert len(addr_blocks) > 0, "could not find firmware address blocks!"

        return addr_blocks, firmware
