# -*- coding: utf-8 -*-
# BS"D
# Build a response according to given fields
# Change the response to binary format according to the protocol.

import struct
from Ticket import Ticket

class Response:
    def __init__(self, version, code, payload_size, payload1, payload2, payload3, payload4, payload5 = None):
        self.version = version
        self.code = code
        self.payload_size = payload_size
        if code == 1600:
            self.client_id = payload1
        elif code == 1602:
            self.message_servers_list = payload1
        elif code == 1603:
            self.client_id = payload1
            self.iv = payload2
            self.nonce = payload5
            self.aes_key = payload3
            self.ticket = payload4
           
       

    def to_binary(self):
        parts = []
        
        # Version (1 byte)
        parts.append(struct.pack('<B', self.version))
       
        # Code (2 bytes)
        parts.append(struct.pack('<H', self.code))
       
        # Payload Size (4 bytes)
        parts.append(struct.pack('<I', self.payload_size))
       
        # Payload
        if (self.code == 1600 or self.code == 1603) and self.client_id: # 1600, 1603
            parts.append(self.client_id.encode().ljust(16, b'\x00')[:16])


        if self.code == 1603 and self.iv: # 1603
            parts.append(self.iv.ljust(16, b'\x00')[:16])
            
        if self.code == 1603 and self.nonce: # 1603
            parts.append(self.nonce.ljust(8, b'\x00'))
        if self.code == 1603 and self.aes_key: # 1603
            #לפני בינארי
            parts.append(self.aes_key.ljust(32, b'\x00')[:32])
        if self.code == 1603 and self.ticket: # 1603
            parts.append(self.ticket.to_binary())
        if self.code == 1602 and self.message_servers_list:
            for server in self.message_servers_list:
                # Server ID (16 bytes, padded or truncated to size)
                server_id_binary = server['id'].encode().ljust(16, b'\x00')[:16]
                parts.append(server_id_binary)

                # Server Name (255 bytes, padded with null bytes, include null terminator)
                server_name_binary = server['name'].encode().ljust(255, b'\x00')[:255]
                parts.append(server_name_binary)
               
        return b''.join(parts)
