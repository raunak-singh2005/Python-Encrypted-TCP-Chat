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

clients = []
nicknames = []
clientPubkey = []


def broadcast(msg):
    for client in clients:
        try:
            client.send(rsa.encrypt(msg.encode('utf-8'), clientPubkey[clients.index(client)]))
        except Exception as e:
            print(e)


def receive():
    while True:
        client, addr = server.accept()
        clients.append(client)
        print(f'connected with {str(addr)}!')

        client.send(pubkey.save_pkcs1("PEM"))
        clientPubkey.append(rsa.PublicKey.load_pkcs1(client.recv(1024)))

        client.send(rsa.encrypt('NICK'.encode('utf-8'), clientPubkey[clients.index(client)]))

        try:
            nickname = rsa.decrypt(client.recv(1024), privkey).decode('utf-8')
        except:
            continue

        nicknames.append(nickname)

        print(f'Nickname of the client is {nickname}')
        broadcast(f'{nickname} has connected to the server \n')
        client.send(rsa.encrypt("Connected to the server\n".encode('utf-8'), clientPubkey[clients.index(client)]))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


def handle(client):
    while True:
        try:
            decMessage = rsa.decrypt(client.recv(1024), privkey).decode("utf-8")
            print(decMessage)
            broadcast(decMessage)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f'{nickname} disconnected from the server!')
            nicknames.remove(nickname)
            clientPubkey.remove(clientPubkey[index])
            break


print('server running...')
receive()
