#BS"D
import struct

class Ticket:
    def __init__(self, version, client_id, server_id, creation_time, iv, aes_key, expiration_time):
        self.version = version  # Server version (1 byte)
        self.client_id = client_id  # Client ID (16 bytes)
        self.server_id = server_id  # Server ID (16 bytes)
        # Timestamp
        self.creation_time = creation_time
        self.iv = iv  # IV for the ticket (16 bytes)
        self.aes_key = aes_key  # AES key encrypted for the client (32 bytes)
        self.expiration_time = expiration_time  # Expiration time of the ticket (4 bytes)
       
    def from_string(tic):
        # Assuming the ticket string format is "version,client_id,server_id,creation_time,expiration_time"
        ticket_version = struct.unpack('<B', tic[0:1])[0]
        ticket_client_id = tic[1:17].decode().rstrip('\x00')
        ticket_server_id = tic[17:33].decode().rstrip('\x00')
        ticket_creation_time = struct.unpack('<Q', tic[33:41])[0]
        ticket_iv = tic[41:57]
        ticket_aes_key = tic[57:89]
        ticket_expiration_time = tic[89:]#struct.unpack('<I', tic[81:97])[0]
        return Ticket(ticket_version, ticket_client_id, ticket_server_id, ticket_creation_time, ticket_iv, ticket_aes_key, ticket_expiration_time)

    def to_binary(self):
        parts = []

        # Version (1 byte)
        parts.append(struct.pack('<B', self.version))

        # Client ID (16 bytes, padded or truncated to size)
        parts.append(self.client_id.encode().ljust(16, b'\x00')[:16])

        # Server ID (16 bytes, padded or truncated to size)
        parts.append(self.server_id.encode().ljust(16, b'\x00')[:16])
       
        parts.append(struct.pack('<Q', self.creation_time))
       
        # IV (16 bytes)
        parts.append(self.iv)
        # AES Key (32 bytes)
        parts.append(self.aes_key)
        # Expiration Time (4 bytes)
        parts.append(self.expiration_time)

        return b''.join(parts)
