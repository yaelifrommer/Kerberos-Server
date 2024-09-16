# -*- coding: utf-8 -*-
#The main class to initiate the client application.
import socket
from Ticket import Ticket
from Request import Request
from Response import Response
import hashlib
from Crypto.Cipher import AES
import struct
import os
from datetime import datetime
from Crypto.Util.Padding import pad

VERSION = 24
PASSWORD = None
def read_client_info():
    try:
        with open('me.info', 'r') as file:
            lines = file.readlines()  # Read all lines into a list
            # Ensure there are at least two lines in the file
            if len(lines) >= 2:
                name = lines[0].strip()  # Remove whitespace from the first line
                unique_id = lines[1].strip()  # Remove whitespace from the second line
            else:
                print("The file me.info does not contain enough lines.")
                name = None
                unique_id = None
    except FileNotFoundError:
        name = input("Enter your username: ")
        unique_id = None
        with open('me.info', 'w') as file:
            file.write(f"{name}\n")
    except Exception as e:
        print(f"2_An error occurred while reading the file.")
        return None
    try:
        with open('srv.info', 'r') as file2:
            lines = file2.readlines()
            address, port = lines[0].strip().split(':')
            # Read the port and the adddress of the Auth server
    except Exception as e:
        print(f"3_An error occurred while reading the srv file.")
        return None      
    # Return the values
    return address, int(port), name, unique_id


def send_message_to_server(address, port, message): # Sends a message to the authServer in a binary format.

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((address, port))
        try:
            s.sendall(message)
        except:
            print("Error sending message to server.")
        try:
            res = s.recv(102540)
            response = Response(res)
            if response.get_code() == 1601: # registeration forbidden.
                print("Error: Can't register client.")
                exit()
            elif response.get_code() == 1600:
                response.registeration_ok()
            elif response.get_code() == 1603:
                # Saves the AES key for comunication with the wanted server and the ticket.
                ticket = response.get_ticket()
                aes = response.get_aes_key()
                # Generate SHA-256 hash of the password
                password_hash = hashlib.sha256(PASSWORD.encode()).digest()
                iv = response.get_iv()
                # create the cipher object with the password and iv.
                cipher = AES.new(password_hash, AES.MODE_CBC,iv)
                aes_key = cipher.decrypt(aes)
                global aes_key_client_server_1603 
                aes_key_client_server_1603 = aes_key
                global ticket_1603
                ticket_1603 = ticket
        except Exception as e:
            print("An error occurred")
    return response

# Server Message functions:

def read_message_server_details(filename='srv.info'):
    try:
        with open(filename, 'r') as file:
            # Read all the lines in the file
            lines = file.readlines()
           
            # Assuming the second line contains the message server details
            message_server_line = lines[1].strip()  # Remove whitespace and newline characters
           
            # Split the line into IP and port based on the ':' character
            ip, port = message_server_line.split(':')
           
            # Convert the port from a string to an integer
            port = int(port)
           
            return ip, port
    except Exception as e:
        print(f"An unexpected error occurred.")
        return None, None

def send_message_to_message_server(host, port, message_list): # Sends a message to the authServer in a binary format.
   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        for message in message_list:
            s.sendall(message)
            data = s.recv(10524)
            received_number = struct.unpack('>I', data)[0]
            if received_number == 1609:
                print("General message server error")

   
def client_main():
    # Creating Registeration request.
    global PASSWORD
    x = read_client_info() # Get clients name, iad, port, address
    address = x[0]
    port = x[1]
    if len(x) > 2: # Reconnection - file me.info exists.
        name = x[2]
        unique_id = [3]
        PASSWORD = input("Please enter your password: ")
    else: # Register from beginning.
        name = input("Please enter your name: ")
        PASSWORD = input("Please enter your password: ")
    # Create a register request and send to server.
    register = Request("0000000000000000", VERSION, 1024, name, PASSWORD)
    req = register.to_binary() # Make the request readdy to be sent.
    try:
        server_response = send_message_to_server(address, port, req) # Send message.
    except Exception as e:
        print("Error connecting to server")

    # Create the request for getting an AES key for a spesific message server.
    address, port, name, unique_id = read_client_info()
    aes_key = Request(unique_id, VERSION, 1027, None, None, "", None)
    req = aes_key.to_binary() # Make the request readdy to be sent.
    try:
        server_response = send_message_to_server(address, port, req)
    except:
        print("Error connecting to server")  
    # Connecting to the Message Server.

    # Read and print the message server details
    ip, port = read_message_server_details()
    if ip and port:
        print(f"Message Server IP: {ip}, Port: {port}")

    ticket = ticket_1603
    aes_key = aes_key_client_server_1603
    srvr_clnt_iv = os.urandom(AES.block_size)
    cipher_encrypt = AES.new(aes_key, AES.MODE_CBC, srvr_clnt_iv)


    iv = srvr_clnt_iv 
    # We assumed that the key with which it is required to encrypt the 1028 request 
    # fields is the shared key between both - messages and the client,
    # because otherwise how would he know the key of the messages and logically.
    version = ticket.version
    client_id = ticket.client_id
    server_id = ticket.server_id
    creation_time = int((datetime.now().timestamp()))
    # Encrypt Version
    x = struct.pack('<I', version)
    data = pad(x, AES.block_size)
    version_e = cipher_encrypt.encrypt(data)
    # Encrypt Client_Id
    client_id_bytes = client_id.encode('utf-8')
    client_id_e = cipher_encrypt.encrypt(pad(client_id_bytes, AES.block_size))
    # Encrypt Server_Id
    server_id_bytes = server_id.encode('utf-8')
    server_id_e = cipher_encrypt.encrypt(pad(server_id_bytes, AES.block_size))
    # Encrypt Creation_Time
    x = struct.pack('<I', creation_time)
    data = pad(x, AES.block_size)
    creation_time_e = cipher_encrypt.encrypt(data)
    request_obj = Request(client_id, VERSION, 1028 ,None,None, None, None, iv, version_e, client_id_e, server_id_e, creation_time_e, ticket) 
    req_1 = request_obj.to_binary()

    # 1029 
    message_iv = os.urandom(AES.block_size)
    cipher_encrypt = AES.new(aes_key, AES.MODE_CBC, message_iv)
    message = str(input("Here you can write a message to the message server "))
   
    bin_message = message.encode('utf-8')
    message_content = cipher_encrypt.encrypt(pad(bin_message, AES.block_size))
   
    request_obj = Request(client_id, VERSION, 1029 ,None,None, None, None, None, None, None, None, None, None,len(message_content),message_iv,message_content)
    req_2 = request_obj.to_binary()
    send_message_to_message_server(address, port, [req_1, req_2])

if __name__ == '__main__':
    print("Hinda frommer 326130111")
    client_main()
