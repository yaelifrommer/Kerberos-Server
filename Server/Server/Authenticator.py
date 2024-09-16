import base64
from Crypto.Cipher import AES
import struct
from Crypto.Util.Padding import unpad

class Authenticator:
    def __init__(self, auth_iv,ticket_iv, version, client_id, server_id, creation_time, ticket_aes_key):
        # Get the server key for decrypting the aes for server-client connection
        filename = 'msg.info'
        try:
            # Open the file and read lines
            with open(filename, 'r') as file:
                lines = file.readlines()
                base64_server_key = lines[3].strip()
                server_key = base64.b64decode(base64_server_key)
                cipher = AES.new(server_key, AES.MODE_CBC, ticket_iv)
                self.aes_key_save = cipher.decrypt(ticket_aes_key)
                cipher_decrypt = AES.new(self.aes_key_save, AES.MODE_CBC, auth_iv)   
        except Exception as e:
            print(f"An unexpected error occurred.")

        # Decrypt Version.
        version_decrypted = cipher_decrypt.decrypt(version)
        # Removing the padding (assuming that padding is used as part of the encryption process)
        version_unpadded = unpad(version_decrypted, AES.block_size)
        decrypted_data = struct.unpack('<I', version_unpadded)[0]
        # Open these fields from their encryption and save them.
        self.version = decrypted_data
        # Get Iv
        self.iv = auth_iv
        # Decrypt Client_Id
        client_id_decrypted_padded = cipher_decrypt.decrypt(client_id)
        client_id_str = client_id_decrypted_padded.decode('latin-1')  #Using latin-1 instead of UTF-8
        self.client_id = client_id_str
        # Decrypt Server_Id
        server_id_decrypted_padded = cipher_decrypt.decrypt(server_id)
        server_id_str = server_id_decrypted_padded.decode('latin-1')  # Using latin-1 instead of UTF-8
        self.server_id = server_id_str
        # Decrypt Creation Time.
        decrypted_data = cipher_decrypt.decrypt(creation_time)
        decrypted_data_unpadded = unpad(decrypted_data, AES.block_size)
        number, = struct.unpack('<I', decrypted_data_unpadded)
        self.creation_time = number
       
