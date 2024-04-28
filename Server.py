#! /usr/bin/python3
import socket
import threading
import rsa
import hashlib
import sys
import re
import signal


# Function to get the network information from the user
def getNetworkInfo():

    # Requesting server IP and port from the user
    HOST = input('Please Enter the Server IP Address: ')
    PORT = input('Please Enter the Server Port: ')
    # Validating the IP address format
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', HOST):
        print("Invalid IP address format. Please try again.")
        return getNetworkInfo()
    # Validating the port number
    if not PORT.isdigit() or not 0 <= int(PORT) <= 65535:
        print("Invalid port number. Please try again.")
        return getNetworkInfo()
    return HOST, int(PORT)


# Assign the network information to the HOST and PORT variables
HOST, PORT = getNetworkInfo()

# Generate the public and private keys
pubkey, privkey = rsa.newkeys(1024)

# Create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

# List to store the clients data
clients_data = []


# Function to hash the admin password
def hashAdminPassword():

    # Requesting password from the user
    plainPassword = input('Please Enter a Password: ')
    # Hashing the password
    hashPassword = hashlib.sha256(plainPassword.encode('utf-8')).hexdigest()
    return hashPassword


# Function to broadcast the message to all the clients
def broadcast(msg):

    # Looping through all clients and sending the message
    for data_row in clients_data:
        try:
            data_row[0].send(rsa.encrypt(msg.encode('utf-8'), data_row[2]))
        except Exception as e:
            print(e)


# Function to handle the incoming connections
def receive():

    # Hashing the admin password
    realPassword = hashAdminPassword()
    while True:
        try:
            # Accepting a new client connection
            client, addr = server.accept()
            print(f'connected with {str(addr)}!')

            # Sending the public key to the client
            client.send(pubkey.save_pkcs1("PEM"))
            # Receiving the client's public key
            client_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))

            # Requesting the client's nickname
            client.send(rsa.encrypt('NICK'.encode('utf-8'), client_public_key))

            try:
                # Receiving the client's nickname
                nickname = rsa.decrypt(client.recv(1024), privkey).decode('utf-8')
            except:
                continue

            # Checking if the client is banned
            with open('bans.txt', 'r') as f:
                bans = f.readlines()

            if nickname + '\n' in bans:
                # Informing the client that they are banned
                client.send(rsa.encrypt('BANNED'.encode('utf-8'), client_public_key))

            # Checking if the client is the admin
            if nickname == "ADMIN":
                # Requesting the admin password
                client.send(rsa.encrypt('PASS'.encode('utf-8'), client_public_key))
                # Receiving the hashed password
                hashPassword = rsa.decrypt(client.recv(1024), privkey).decode('utf-8')

                # Checking if the password is correct
                if hashPassword != realPassword:
                    # Refusing the connection if the password is incorrect
                    client.send(rsa.encrypt('REFUSE'.encode('utf-8'), client_public_key))
                    client.close()
                    continue

            # Adding the client to the clients list
            clients_data.append([client, nickname, client_public_key])

            print(f'Nickname of the client is {nickname}')
            # Broadcasting that the client has connected
            broadcast(f'{nickname} has connected to the server \n')
            # Informing the client that they have connected
            client.send(rsa.encrypt("Connected to the server\n".encode('utf-8'), client_public_key))

            # Starting a new thread to handle the client's messages
            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
        except rsa.DecryptionError:
            print('Decryption Error')
        except socket.error as e:
            print(f'Socket Error : {e}')
        except Exception as e:
            print(f'Error in receiving the connection: {e}')


# Function to handle the interrupt signal
def signal_handler(sig, frame):

    print("Shutting down server...")
    # Closing the server socket
    server.close()
    sys.exit(0)


# Function to handle the client messages
def handle(client):

    while True:
        try:
            # Receiving and decrypting the client's message
            msg = decMessage = rsa.decrypt(client.recv(1024), privkey).decode("utf-8")
            print(decMessage)

            # Checking if the message is a command
            if msg.startswith('KICK') or msg.startswith('BAN'):
                # Checking if the client is the admin
                clientDataRow = next(row for row in clients_data if row[0] == client)
                if clients_data[clients_data.index(clientDataRow)][1] != 'ADMIN':
                    # Refusing the command if the client is not the admin
                    client.send(rsa.encrypt('Command Refused'.encode('utf,8'), clientDataRow[2]))
                    continue

                # Checking if the command is to kick a user
                if msg.startswith('KICK'):
                    nameToKick = msg[5:]
                    kickUser(nameToKick)

                # Checking if the command is to ban a user
                elif msg.startswith('BAN'):
                    nameToBan = msg[4:]
                    kickUser(nameToBan)
                    # Adding the user to the ban list
                    with open('bans.txt', 'a') as f:
                        f.write(f'{nameToBan}\n')
                    print(f'{nameToBan} was banned')

            # Checking if the message is to leave the chat
            elif msg.startswith('LEAVE'):
                nameToLeave = msg[6:]
                clientDataRow = next((row for row in clients_data if row[1] == nameToLeave), None)
                if clientDataRow:
                    # Removing the client from the clients list
                    clients_data.remove(clientDataRow)
                    # Closing the client's connection
                    clientDataRow[0].shutdown(socket.SHUT_RDWR)
                    clientDataRow[0].close()
                    # Broadcasting that the client has left
                    broadcast(f'{nameToLeave} has left the chat!')

            else:
                # Broadcasting the client's message
                broadcast(decMessage)

        except:
            # Removing the client from the clients list and closing their connection if an error occurs
            clientDataRow = next((row for row in clients_data if row[0] == client), None)
            if clientDataRow:
                clients_data.remove(clientDataRow)
                client.close()
                # Broadcasting that the client has disconnected
                broadcast(f'{clientDataRow[1]} disconnected from the server!')
            break


# Function to kick the user
def kickUser(name):

    # Finding the user in the clients list
    client_data_row = next((row for row in clients_data if row[1] == name), None)
    if client_data_row:
        # Broadcasting that the user was kicked
        broadcast(f'{name} was kicked!')
        # Removing the user from the clients list
        clients_data.remove(client_data_row)
        # Closing the user's connection
        client_data_row[0].shutdown(socket.SHUT_RDWR)
        client_data_row[0].close()


# Assign the signal handler to the interrupt signal
signal.signal(signal.SIGINT, signal_handler)

# Start the server
print('server running...')
receive()
