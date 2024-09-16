
#BS"D
import struct
import time
from datetime import datetime

class Ticket:
    def __init__(self, version, client_id, server_id, iv, aes_key, expiration_time):
        self.version = version  # Server version (1 byte)
        self.client_id = client_id  # Client ID (16 bytes)
        self.server_id = server_id  # Server ID (16 bytes)
        self.creation_time = int((datetime.now().timestamp()))  # Creation time - now
        self.iv = iv  # IV for the ticket (16 bytes)
        self.aes_key = aes_key  # AES key encrypted for the client (32 bytes)
        self.expiration_time = expiration_time  # Expiration time of the ticket (4 bytes)

    def to_binary(self):
        parts = []

        # Version (1 byte)
        parts.append(struct.pack('<B', self.version))

        # Client ID (16 bytes, padded or truncated to size)
        parts.append(self.client_id.encode().ljust(16, b'\x00')[:16])

        # Server ID (16 bytes, padded or truncated to size)
        parts.append(self.server_id.encode().ljust(16, b'\x00')[:16])
       
        #creation time
        parts.append(struct.pack('<Q', self.creation_time))
        # IV (16 bytes)
        parts.append(self.iv)

        # AES Key (32 bytes)
        parts.append(self.aes_key)
        # Expiration Time (4 bytes)
        parts.append(self.expiration_time)
        #parts.append(struct.pack('<I', self.expiration_time))
        return b''.join(parts)
