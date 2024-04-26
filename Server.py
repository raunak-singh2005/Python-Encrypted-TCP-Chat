#! /usr/bin/python3
import socket
import threading
import rsa
import hashlib

def getNetworkInfo():
    HOST = input('Please Enter the Server IP Address: ')
    PORT = int(input('Please Enter the Server Port: '))
    return HOST, PORT

HOST, PORT = getNetworkInfo()

pubkey, privkey = rsa.newkeys(1024)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients_data = []


def hashAdminPassword():
    plainPassword = input('Please Enter a Password: ')
    hashPassword = hashlib.sha256(plainPassword.encode('utf-8')).hexdigest()
    return hashPassword


def broadcast(msg):
    for data_row in clients_data:
        try:
            data_row[0].send(rsa.encrypt(msg.encode('utf-8'), data_row[2]))
        except Exception as e:
            print(e)


def receive():
    realPassword = hashAdminPassword()
    while True:
        client, addr = server.accept()
        print(f'connected with {str(addr)}!')

        client.send(pubkey.save_pkcs1("PEM"))
        client_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))

        client.send(rsa.encrypt('NICK'.encode('utf-8'), client_public_key))

        try:
            nickname = rsa.decrypt(client.recv(1024), privkey).decode('utf-8')
        except:
            continue

        with open('bans.txt', 'r') as f:
            bans = f.readlines()

        if nickname + '\n' in bans:
            client.send(rsa.encrypt('BANNED'.encode('utf-8'), client_public_key))

        if nickname == "ADMIN":
            client.send(rsa.encrypt('PASS'.encode('utf-8'), client_public_key))
            hashPassword = rsa.decrypt(client.recv(1024), privkey).decode('utf-8')

            if hashPassword != realPassword:
                client.send(rsa.encrypt('REFUSE'.encode('utf-8'), client_public_key))
                client.close()
                continue

        clients_data.append([client, nickname, client_public_key])

        print(f'Nickname of the client is {nickname}')
        broadcast(f'{nickname} has connected to the server \n')
        client.send(rsa.encrypt("Connected to the server\n".encode('utf-8'), client_public_key))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


def handle(client):
    while True:
        try:
            msg = decMessage = rsa.decrypt(client.recv(1024), privkey).decode("utf-8")
            print(decMessage)

            if msg.startswith('KICK') or msg.startswith('BAN'):
                clientDataRow = next(row for row in clients_data if row[0] == client)
                if clients_data[clients_data.index(clientDataRow)][1] != 'ADMIN':
                    client.send(rsa.encrypt('Command Refused'.encode('utf,8'), clientDataRow[2]))
                    continue

                if msg.startswith('KICK'):
                    nameToKick = msg[5:]  #
                    kickUser(nameToKick)

                elif msg.startswith('BAN'):
                    nameToBan = msg[4:]
                    kickUser(nameToBan)
                    with open('bans.txt', 'a') as f:
                        f.write(f'{nameToBan}\n')
                    print(f'{nameToBan} was banned')

            else:
                broadcast(decMessage)

        except:
            clientDataRow = next((row for row in clients_data if row[0] == client), None)
            if clientDataRow:
                clients_data.remove(clientDataRow)
                client.close()
                broadcast(f'{clientDataRow[1]} disconnected from the server!')
            break


def kickUser(name):
    client_data_row = next((row for row in clients_data if row[1] == name), None)
    if client_data_row:
        broadcast(f'{name} was kicked!')
        clients_data.remove(client_data_row)
        client_data_row[0].shutdown(socket.SHUT_RDWR)
        client_data_row[0].close()


print('server running...')
receive()
