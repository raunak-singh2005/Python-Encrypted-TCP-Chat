import socket
import threading

HOST = '192.168.0.75'
PORT = 9090

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
nicknames = []


#Broadcast

def broadcast(msg):
    for client in clients:
        client.send(msg)


#Receive

def receive():
    while True:
        client, addr = server.accept()
        print(f'connected with {str(addr)}!')

        client.send('NICK'.encode('utf-8'))
        nickname = client.recv(1024).decode('utf-8')
#delete
        if nickname == 'ADMIN':
            client.send('PASS'.encode('utf-8'))
            password = client.recv(1024).decode('utf-8')
            
            if password != 'adminPass':
                client.send('REFUSE'.encode('utf-8'))
                client.close()
                continue
#delete
        nicknames.append(nickname)
        clients.append(client)

        print(f'Nickname of the client is {nickname}')
        broadcast(f'{nickname} has connected to the server \n'.encode('utf-8'))
        client.send("Connected to the server".encode("utf-8"))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


#Handle

def handle(client):
    while True:
        try:
            message = msg = client.recv(1024)
            if message.decode('utf-8').startswith("b'KICK"):
                nameToKick = message.decode('utf-8')[7:]
                kickUser(nameToKick)
            elif message.decode('utf-8').startswith('BAN'):
                nameToBan = message.decode('utf-8')[4:]
                kickUser(nameToBan)
                with open('bans.txt', 'a') as f:
                    f.write(f'{nameToBan}\n')
                print(f'{nameToBan} was banned!')

            else:
                print(f'{nicknames[clients.index(client)]} says {msg}')
                broadcast(msg)

        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f'{nickname} disconnected from the server!'.encode('utf-8'))
            nicknames.remove(nickname)
            break

def kickUser(name):
    if name in nicknames:
        broadcast(f'{name} has been kicked!'.encode('utf-8'))
        nameIndex = nicknames.index(name)
        clientToKick = clients[nameIndex]
        clients.remove(clientToKick)
        clientToKick.close()
        nicknames.remove(name)

def banUser():
    pass

print('server running...')
receive()
