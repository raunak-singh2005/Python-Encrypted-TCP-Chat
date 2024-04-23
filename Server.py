#! /usr/bin/python3
import socket
import threading
import rsa

HOST = '192.168.0.75'
PORT = 9091
pubkey, privkey = rsa.newkeys(1024)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients_data = []

def broadcast(msg):
    for data_row in clients_data:
        try:
            data_row[0].send(rsa.encrypt(msg.encode('utf-8'), data_row[2]))
        except Exception as e:
            print(e)


def receive():
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

        clients_data.append([client, nickname, client_public_key])

        print(f'Nickname of the client is {nickname}')
        broadcast(f'{nickname} has connected to the server \n')
        client.send(rsa.encrypt("Connected to the server\n".encode('utf-8'), client_public_key))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


def handle(client):
    while True:
        try:
            decMessage = rsa.decrypt(client.recv(1024), privkey).decode("utf-8")
            print(decMessage)
            broadcast(decMessage)
        except:
            client_data_row = next(row for row in clients_data if row[0] == client)
            clients_data.remove(client_data_row)
            client.close()
            broadcast(f'{client_data_row[1]} disconnected from the server!')
            break


print('server running...')
receive()
