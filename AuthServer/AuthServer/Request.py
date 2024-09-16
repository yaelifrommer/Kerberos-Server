
import struct
import uuid
import os
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Ticket import Ticket
import base64
from Crypto.Util.Padding import pad, unpad

VERSION =  24

class Request:
    def __init__(self, data):
        self.client_id = data[:16].decode().rstrip('\x00')
        self.version = struct.unpack('<B', data[16:17])[0]
        self.code = struct.unpack('<H', data[17:19])[0]
        self.payload_size = struct.unpack('<I', data[19:23])[0]
        payload_data = data[23:]
        if self.code == 1024:  
            self.name = payload_data[:255].decode().rstrip('\x00')
            self.password = payload_data[255:510].decode().rstrip('\x00')
        elif self.code == 1027:
            self.server_id = self.read_msg_srvr_id()
            self.nonce = payload_data[16:24]
       
       
    def read_msg_srvr_id(self):
        # Path to the info.msg file
        file_path = 'msg.info'
        # Reading the file and capturing the third line
        with open(file_path, 'r') as file:
            lines = file.readlines()
            unique_id_line = lines[2].strip()  # Removing spaces from the beginning and end of the line
        # Converting the third line to a UUID object
        try:
            unique_id = str(uuid.UUID(unique_id_line))
            uid = unique_id[:16]
        except Exception as e:
            print(f"Error getting messages server id.")
            return None
        return uid
    

    def get_client_id(self):
        return self.client_id

    def get_version(self):
        return self.version

    def get_code(self):
        return self.code

    def get_payload_size(self):
        return self.payload_size

    def get_name(self):
        return getattr(self, 'name', None)

    def get_password(self):
        return getattr(self, 'password', None)

    def get_aes_key(self):
        return getattr(self, 'aes_key', None)

    def get_server_id(self):
        return getattr(self, 'server_id', None)

    def get_nonce(self):
        return getattr(self, 'nonce', None)
   
    def name_exists(self,name, file_path):
        if not os.path.exists(file_path):
            return False
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.split(' :')
                if name == parts[1]:#in line:
                    return True
        return False
   
    def verify_name_password(self, name, temp_pass_hash, file_path):
        if not os.path.exists(file_path):
            return False, None
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    client_id, line_name, stored_pass_hash_str, date= line.strip().split(" :")
                    stored_pass_hash = eval(stored_pass_hash_str)
                    if name == line_name and temp_pass_hash == stored_pass_hash:
                        return True, client_id
        except Exception as e:
            print("Error verifying name to password.")
        return False, None

    def save_client_server(self,client_id, name, file_path):
        # Generate SHA-256 hash of the password
        password_hash = hashlib.sha256(self.password.encode()).digest()
        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(file_path, 'a') as file:
            file.write(f"{client_id} :{name} :{password_hash} :{last_seen}\n")

    def register_client(self):
        # Check if the client/server name exists
        if self.name_exists(self.name, 'clients.txt') or self.name_exists(self.name, 'servers.txt'):
            temp_password_hash = hashlib.sha256(self.password.encode()).digest()
            TORF, client_id = self.verify_name_password(self.name, temp_password_hash, 'clients.txt')
            if TORF == False:
                return 1601, None  # Registration failed
            else:
                return 1600, client_id  # Reconnection succeeded
        new_id = str(uuid.uuid4())
        new_id=new_id[:16]
        self.save_client_server(new_id, self.name, 'clients.txt')

        # Return success response
        return 1600, new_id  # Registration succeeded
   
    def aes_key(self):
        # Generate a random 256-bit (32 bytes) AES key
        file_path = 'clients.txt'
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line_parts = line.strip().split(' :')
                    if line_parts[0] == self.client_id:
                        # Return the password hash
                        password = line_parts[2]
                    else:
                        password = None
        except FileNotFoundError:
            password = None
        except Exception as e:
            print(f"An error occurred with generating an AES key to client - server.")
        aes_key_t = os.urandom(32)
        ivv = os.urandom(AES.block_size)
        aes_key_t_COPY = aes_key_t
        cipher_encrypt = AES.new(eval(password), AES.MODE_CBC,ivv)  # Create a cipher object.      
        encrypted_aes_key = cipher_encrypt.encrypt(aes_key_t) # Encrypt the shared key.
        if self.nonce is not None:
            encrypted_nonce = cipher_encrypt.encrypt(self.nonce.ljust(16, b'\x00'))  # Padding if needed
        # Create a Ticket object
        expiration_time = int((datetime.now().timestamp()) + 3600)  # 1 hour from now
        # Get the message server key for encrypting the shared key.
        filename = 'msg.info'
        try:
            # Open the file and read lines
            with open(filename, 'r') as file:
                lines = file.readlines()
            # Extract the fourth line (considering list is 0-indexed)
            base64_key = lines[3].strip()
            # Convert from base64 to binary
            server_key = base64.b64decode(base64_key)
        except Exception as e:
            print(f"An unexpected error occurred with getting the message server key.")
        # Creating the encrypted key between server to client.
        # Message server key
        siv = os.urandom(AES.block_size) # The iv for encrypting the shared key with the servers key.
        cipher = AES.new(server_key, AES.MODE_CBC, siv)
        ticket_iv = siv
        # Encrypt server-client key - with message server key.
        encrypted_aes_key_server_client = cipher.encrypt(aes_key_t_COPY)
        expiration_time_bytes = struct.pack('<Q', expiration_time)
        encrypted_expiration_time = cipher.encrypt(expiration_time_bytes.ljust(32, b'\x00'))
        ticket = Ticket(VERSION, self.client_id, self.server_id, ticket_iv, encrypted_aes_key_server_client, encrypted_expiration_time)
        
        return 1603, ivv, encrypted_aes_key, ticket, encrypted_nonce
