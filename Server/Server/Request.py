
import struct
from Ticket import Ticket
from Authenticator import Authenticator

class Request:
    def __init__(self, data):
        self.client_id = data[:16].decode().rstrip('\x00')
        self.version = struct.unpack('<B', data[16:17])[0]
        self.code = struct.unpack('<H', data[17:19])[0]
        self.payload_size = struct.unpack('<I', data[19:23])[0]
        if self.code == 1028:
             # Authenticator fields
            auth_start = 23
            auth_iv = data[auth_start:auth_start+16]
            auth_version = data[auth_start+16:auth_start+32].rstrip(b'\x00') 
            auth_client_id = data[auth_start+32:auth_start+64].rstrip(b'\x00')
            server_id = data[auth_start+64:auth_start+96].rstrip(b'\x00')
            creation_time = data[auth_start+96:auth_start+112].rstrip(b'\x00')
            # Ticket fields
            auth_start = 23
            auth_iv_length = 16
            auth_version_length = 16  # There seems to be a contradiction here; I assume 16 according to the code
            auth_client_id_length = 32
            server_id_length = 32
            creation_time_length = 16  # There seems to be a contradiction here; I assume 16 according to the code
            # Calculate ticket_start
            ticket_start = (auth_start + auth_iv_length + auth_version_length +
                            auth_client_id_length + server_id_length + creation_time_length)
            ticket_version = struct.unpack('<B', data[ticket_start:ticket_start+1])[0]
            ticket_client_id = data[ticket_start+1:ticket_start+17].rstrip(b'\x00').decode()
            ticket_server_id = data[ticket_start+17:ticket_start+33].rstrip(b'\x00').decode()
            ticket_creation_time = struct.unpack('<Q', data[ticket_start+33:ticket_start+41])[0]
            ticket_iv = data[ticket_start+41:ticket_start+57]
            ticket_aes_key = data[ticket_start+57:ticket_start+89]
            ticket_expiration_time = data[ticket_start+89:].rstrip(b'\x00')
            self.ticket = Ticket(ticket_version, ticket_client_id, ticket_server_id, ticket_creation_time, ticket_iv, ticket_aes_key, ticket_expiration_time)
            self.Authenticator = Authenticator(auth_iv,self.ticket.iv, auth_version, auth_client_id, server_id, creation_time, ticket_aes_key)
        elif self.code == 1029:
            start = 23
            self.message_size = struct.unpack('<I', data[start:start + 4])[0]
            self.message_iv = data[start + 4:start + 20].rstrip(b'\x00')
            self.message_content = data[start + 20:start + 36].rstrip(b'\x00')
            
