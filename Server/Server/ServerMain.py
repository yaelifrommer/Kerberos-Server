# -*- coding: utf-8 -*-
import base64  
import socket
import threading
from Request import Request
from Response import Response
from Crypto.Cipher import AES


def read_server_details(filename='msg.info'):
    with open(filename, 'r') as file:
        lines = file.readlines()
        # Read the server address and port number
        address, port = lines[0].strip().split(':')
        port = int(port)  # Convert port number to integer
        # Read the server name
        name = lines[1].strip()
        # Read the server ID
        server_id = lines[2].strip()
        # Read the symmetric key and convert it from base64 to binary
        symmetric_key = base64.b64decode(lines[3].strip())
       
        return address, port, name, server_id, symmetric_key

def handle_client_connection(conn, addr, aes_server_client_key):
    print(f"Connected by {addr}")
    i = 0
    while i < 2:
        data = conn.recv(10524)
        if not data:
            break
        i = i + 1
        request_obj = Request(data)
        if request_obj.code == 1028:  
            # Save shared key.
            aes_server_client_key = request_obj.Authenticator.aes_key_save
            response = Response(1604)
            res = response.to_binary()
        if request_obj.code == 1029:
            iv = request_obj.message_iv
            aes_key = aes_server_client_key
            message = request_obj.message_content
            cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher_decrypt.decrypt(message)
            message_open = decrypted_padded.decode('latin-1')
            message_open = message_open.rstrip()
            print(message_open)
            # Save shared key.
            response = Response(1605)
            res = response.to_binary()
        conn.sendall(res)
    conn.close()

def start_server(host, port):
    aes_server_client_key = None  # Initialize shared key variable
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server is listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            # Start a new thread for each client connection.
            client_thread = threading.Thread(target=handle_client_connection, args=(conn, addr, aes_server_client_key))
            client_thread.start()
def server_main():
    # Read and print the server details
    print("Hinda frommer 326130111")
    address, port, name, server_id, symmetric_key = read_server_details()
    start_server(address, port)
   
if __name__ == '__main__':
    server_main()
