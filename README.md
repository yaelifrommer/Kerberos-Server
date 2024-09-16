# Secure Message Transfer System with Kerberos Authentication

## Introduction

Welcome to the **Secure Message Transfer System**, a robust implementation based on the **Kerberos protocol**. This project is designed to ensure the secure exchange of messages between a client and a server with proper authentication through an **Auth Server**. It involves symmetric key encryption (AES) for secure communication, client registration, and multi-threaded support on the server-side for concurrent clients.

The system includes:
- **Auth Server**: Responsible for client authentication and generating symmetric keys.
- **Message Server**: Receives authenticated client messages and prints them securely.
- **Client**: Initiates contact with the Auth Server, receives keys, and sends encrypted messages to the Message Server.

This project serves as a hands-on implementation of core concepts in **network security**, demonstrating encryption, authentication, and secure communication protocols.

## Features
- **Client Registration**: Clients can register with the Auth Server, receiving a unique ID and symmetric key.
- **Authenticated Messaging**: Clients securely send encrypted messages to the Message Server after authentication.
- **Multi-threaded Servers**: Both servers handle multiple client requests concurrently.
- **Secure Communication**: Messages and authentication data are encrypted using AES.

## Prerequisites

Before running the project, make sure you have the following installed:
- **Python 3.x**
- **PyCryptodome** for encryption

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yaelifrommer/Kerberos-Server.git
   cd Kerberos-Server                                                                                                                                       
   ```

2. **Install Dependencies**:
   Install the necessary Python libraries by running:
   ```bash
   pip install pycryptodome
   ```

## Running the System

### Step 1: Run the Auth Server
First, start the authentication server, which handles client registrations:
```bash
python AuthServerMain.py
```

### Step 2: Run the Message Server
Start the message server to handle client communication:
```bash
python ServerMain.py
```

### Step 3: Run the Client
Finally, run the client, which registers with the Auth Server, gets a key, and communicates securely with the Message Server:
```bash
python Client.py
```

## Author

- **Hinda Yael Frommer**
  - hindoush1111111@gmail.com
  - +972 556727164

This project was developed as part of a security course to demonstrate the practical implementation of secure communication protocols. Feel free to explore the project and understand how to securely transfer messages across the network!
