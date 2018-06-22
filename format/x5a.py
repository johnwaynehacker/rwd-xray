from base import Base
from header import Header
from header_value import HeaderValue

class x5a(Base):
    def __init__(self, data):
        headers, header_data_len = self._parse_file_headers(data[3:])
        fw_start_idx = header_data_len + 3 # account for file type indicator bytes
        keys = self._get_keys(headers)
        encrypted = self._get_firmware(data[fw_start_idx:-4])
        Base.__init__(self, data, headers, keys, encrypted)

    def _parse_file_headers(self, data):
        headers = list()
        d_idx = 0

        for h_idx in range(6):
            h_prefix = data[d_idx]
            d_idx += 1

            # first byte is number of values
            cnt = ord(h_prefix)

            f_header = Header(h_idx, h_prefix, "")
            for v_idx in range(cnt):
                v_prefix = data[d_idx]
                d_idx += 1

                # first byte is length of value
                length = ord(v_prefix)
                v_data = data[d_idx:d_idx+length]
                d_idx += length

                h_value = HeaderValue(v_prefix, "", v_data)
                f_header.values.append(h_value)

            headers.append(f_header)

        return headers, d_idx

    def _get_keys(self, headers):
        for header in headers:
            if header.id == 5:
                assert len(header.values) == 1, "encryption key header does not have exactly one value!"
                assert len(header.values[0].value) == 3, "encryption key header not three bytes!"
                return header.values[0].value

        raise Exception("could not find encryption key header!")

    def _get_firmware(self, data):
        # TODO: store these somewhere
        # print('firmware addrs: 0x{} 0x{}'.format(
        #     binascii.b2a_hex(data[0:4]),
        #     binascii.b2a_hex(data[4:8])
        # ))

        firmware = data[8:]
        assert len(firmware) % 8 == 0, "firmware length not a multiple of eight!"
        return firmware
