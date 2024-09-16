
#BS"D
import os
import struct
from Ticket import Ticket
class Request:
    def __init__(self, client_id, version, code, name=None, password=None, server_id=None, aes_key=None, auth_iv=None, enc_version=None, enc_client_id=None, enc_server_id=None,enc_creation_time=None, ticket=None, message_size=None, message_iv=None, message_content=None):
        self.client_id = client_id if client_id is not None else ''
        self.version = version
        self.code = code
        self.name = name if name is not None else ''
        self.password = password if password is not None else ''
        self.server_id = server_id if server_id is not None else ''
        self.aes_key = aes_key if aes_key is not None else ''
        self.nonce = os.urandom(8) if code in [1027] else None # Making up a code for nonce.
        self.auth_iv = auth_iv if auth_iv is not None else ''
        self.enc_version = enc_version if enc_version is not None else ''
        self.enc_client_id = enc_client_id if enc_client_id is not None else ''
        self.enc_server_id = enc_server_id if enc_server_id is not None else ''
        self.enc_creation_time = enc_creation_time if enc_creation_time is not None else ''
        self.ticket = ticket if ticket is not None else ''
        self.message_size = message_size if message_size is not None else 0
        self.message_iv = message_iv if message_iv is not None else ''
        self.message_content = message_content if message_content is not None else ''
        # Calculate the payload size
        self.payload_size = 0
        if self.name:
            self.payload_size += 255
        if self.password:
            self.payload_size += 255
        if self.aes_key:
            self.payload_size += 32
        if self.server_id:
            self.payload_size += 16
        if self.nonce:
            self.payload_size += 8
            self.payload_size += 16 # second client_id.
        if self.code == 1028:
            self.payload_size = 185
        if self.code == 1029:
            self.payload_size = 4+ 16 + int(self.message_size)
           
    def to_binary(self):
        parts = []
        # Client ID (16 bytes, padded or truncated to size)
        parts.append(self.client_id.encode().ljust(16, b'\x00')[:16])
        # Version (1 byte)
        parts.append(struct.pack('<B', self.version))
        # Code (2 bytes)
        parts.append(struct.pack('<H', self.code))
        # Payload Size (4 bytes)
        parts.append(struct.pack('<I', self.payload_size))

        # Payload
        if self.name:
            parts.append(self.name.encode().ljust(255, b'\x00')[:255])
        if self.password:
            parts.append(self.password.encode().ljust(255, b'\x00')[:255])
        if self.aes_key:
            parts.append(self.aes_key.ljust(32, b'\x00')[:32])
        if self.server_id:
            parts.append(self.server_id.encode().ljust(16, b'\x00')[:16])
           
        if self.nonce:
            parts.append(self.nonce)
        if self.code == 1028:
            parts.append(self.auth_iv.ljust(16, b'\x00')[:16])
            parts.append(self.enc_version.ljust(16, b'\x00')[:16])
            parts.append(self.enc_client_id.ljust(32, b'\x00'))
            parts.append(self.enc_server_id.ljust(32, b'\x00'))
            parts.append(self.enc_creation_time.ljust(16, b'\x00')[:16])
            parts.append(self.ticket.to_binary())
           
        if self.code == 1029:
            parts.append(struct.pack('<I', self.message_size))
            parts.append(self.message_iv.ljust(16, b'\x00')[:16])
            parts.append(self.message_content.ljust(16, b'\x00')[:16])
        return b''.join(parts)
