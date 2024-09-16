#B"SD
#בנאי מקבל מחרוזת ומפרק למשתנים
#פונקציה

import struct
from Ticket import Ticket
class Response:
    def __init__(self, binary_data):
        # Unpack the header from the binary data
        self.version, self.code, self.payload_size = struct.unpack('<BHI', binary_data[:7])
        payload_data = binary_data[7:]
        # Handling different response codes
        if self.code == 1600:
            self.client_id = payload_data[:16].decode().rstrip('\x00')
        elif self.code == 1602:
            # Assuming message_servers_list is a list of server information
            self.message_servers_list = self.parse_server_list(payload_data)
        elif self.code == 1603:
            self.client_id = payload_data[:16].decode().rstrip('\x00')
            self.iv = payload_data[16:32]
            self.nonce = payload_data[32:48]
            self.aes_key = payload_data[48:80]
            tic = payload_data[80:]
            # Unpack the fields from the binary data
            ticket_version = struct.unpack('<B', tic[0:1])[0]
            ticket_client_id = tic[1:17].decode().rstrip('\x00')
            ticket_server_id = tic[17:33].decode().rstrip('\x00')
            ticket_creation_time = struct.unpack('<Q', tic[33:41])[0]
            ticket_iv = tic[41:57]
            ticket_aes_key = tic[57:89]
            ticket_expiration_time = tic[89:]
            self.ticket = Ticket(ticket_version, ticket_client_id, ticket_server_id, ticket_creation_time, ticket_iv, ticket_aes_key, ticket_expiration_time)
            self.ticket.to_binary()
    def parse_server_list(self, data):
        servers = []
        server_size = 16 + 255
        for i in range(0, len(data), server_size):
            server_id = data[i:i+16].decode().rstrip('\x00')
            server_name = data[i+16:i+server_size].decode().rstrip('\x00')
            servers.append({'id': server_id, 'name': server_name})
        return servers

    # Getter methods for each field
    def get_version(self):
        return self.version

    def get_code(self):
        return self.code

    def get_payload_size(self):
        return self.payload_size

    def get_client_id(self):
        return getattr(self, 'client_id', None)

    def get_message_servers_list(self):
        return getattr(self, 'message_servers_list', None)

    def get_iv(self):
        return getattr(self, 'iv', None)
    def get_nonce(self):
        return getattr(self, 'nonce', None)
    def get_aes_key(self):
        return getattr(self, 'aes_key', None)

    def get_ticket(self):
        return getattr(self, 'ticket', None)
    # response taking care functions:
    def registeration_ok(self):
        lines = []
        file_path = 'me.info'
        with open(file_path, 'r') as file:
            lines = file.readlines()
        # Ensure there are at least two lines before
        while len(lines) < 1:
            lines.append('\n')
        # Replace or add the third line with the client_id
        if len(lines) >= 2:
            lines[1] = self.client_id + '\n'
        else:
            lines.append(self.client_id + '\n')
        with open(file_path, 'w') as file:
            file.writelines(lines)
