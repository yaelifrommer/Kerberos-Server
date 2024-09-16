# -*- coding: utf-8 -*-
#Main class for the Authentication Server.
import socket
import os
from Crypto.Cipher import AES
from Request import Request
from Response import Response
import threading
VERSION = 24
def load_data_from_file(file_name, expected_fields):
    data = []
    if not os.path.exists(file_name):
        with open(file_name, 'w') as file:
            file.write("")  # This will create an empty file
    else:
        with open(file_name, 'r') as file:
            for line in file:
                parts = line.strip().split(' :')
                if len(parts) == expected_fields:
                    data.append(parts)
    return data

def load_clients():
    return load_data_from_file('clients.txt', 4)  # ID, Name, PasswordHash, LastSeen

def load_servers():
    return load_data_from_file('servers.txt', 3)  # ID, Name, AESKey

def read_port_from_file(filename='port.info'):
    with open(filename, 'r') as file:
        port = int(file.read().strip())
    return port

# Takes care of the received data.
def handle_client_connection(conn):
    data = conn.recv(102540)
    if data:
        request = Request(data)
        code = request.get_code()
        if code == 1024:
            # Registeraion of a client.
            code, ID = request.register_client()
            if code == 1600: # Registration succeded.
                response = Response(VERSION, code, 16, ID ,None,None,None)
            elif code == 1601: # Registration failed.
                response = Response(VERSION,code,0,None,None,None,None)
        elif code == 1027:
            # get an Aes key
            code, iv, encrypted_aes_key, ticket,nonce = request.aes_key()  
            response = Response(VERSION,code, 16 + 16 + 32 + 85,request.get_client_id(),iv,encrypted_aes_key,ticket,nonce)
            
        return response.to_binary() # And send to client.
    else:
        print("Error in clients request") #return an error response שגיאה כלליתהחזר ?

def client_handler(conn, addr):
    print('Connected by', addr)
    response = handle_client_connection(conn)  # Create a response according to the request.
    try:
        print()
        conn.sendall(response)  # Send the response.
    except:
        print("Error in receiving the data")
    finally:
        conn.close()

def start_server():
    host = '127.0.0.1'
    port = read_port_from_file()  # Function to read the port number from a file
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("server is listening on port", port)
        
        while True:
            conn, addr = s.accept()
            # Start a new thread for each client connection
            thread = threading.Thread(target=client_handler, args=(conn, addr))
            thread.start()
            
if __name__ == '__main__':
    print("Hinda frommer 326130111")
    start_server()
