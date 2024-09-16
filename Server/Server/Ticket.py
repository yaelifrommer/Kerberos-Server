
#BS"D
import struct

class Ticket:
    def __init__(self, version, client_id, server_id, creation_time, iv, aes_key, expiration_time):
        self.version = version  
        self.client_id = client_id  
        self.server_id = server_id  
        # Timestamp
        self.creation_time = creation_time
        self.iv = iv  # IV for the ticket (16 bytes)
        self.aes_key = aes_key  # AES key encrypted for the client (32 bytes)
        self.expiration_time = expiration_time  # Expiration time of the ticket (4 bytes)
