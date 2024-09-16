
import struct
from xml.etree.ElementTree import VERSION
from Ticket import Ticket
class Response:
    def __init__(self, code):
        self.code = code
     
    def to_binary(self):
        if isinstance(self.code, int):
            bin_num = struct.pack('>I', self.code)
            return bin_num
        else:
            bin_num = struct.pack('>I', 1609)
            return bin_num
             