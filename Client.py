#! /usr/bin/python3
import socket
import threading
import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog
import rsa
import hashlib
import re
import signal
import sys


# Function to get the network information from the user
def getNetworkInfo():

    HOST = simpledialog.askstring('IP Address', 'Please Enter the Server IP Address: ')
    PORT = simpledialog.askstring('Port', 'Please Enter the Server Port: ')
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', HOST):
        print("Invalid IP address format. Please try again.")
        return getNetworkInfo()
    if not PORT.isdigit() or not 0 <= int(PORT) <= 65535:
        print("Invalid port number. Please try again.")
        return getNetworkInfo()
    return HOST, int(PORT)


# Assign the network information to the HOST and PORT variables
HOST, PORT = getNetworkInfo()


# A class to represent a client
class Client:

    # Constructor
    def __init__(self, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
        except Exception as e:
            print(f'Error in connecting to the server: {e}')
            exit(0)

        msg = tkinter.Tk()
        msg.withdraw()

        try:
            self.nickname = simpledialog.askstring('Nickname', 'Please choose a nickname', parent=msg)
        except Exception as e:
            print(f'Error in getting the nickname: {e}')
            exit(0)

        if self.nickname == 'ADMIN':
            try:
                self.plaintextPassword = simpledialog.askstring('Password', 'Please enter the admin password', parent=msg)
                self.hashPassword = hashlib.sha256(self.plaintextPassword.encode('utf-8')).hexdigest()
            except Exception as e:
                print(f'Error in getting the password: {e}')
                exit(0)

        self.stopFlag = threading.Event()
        self.guiDone = False
        self.running = True
        self.pubkey, self.privkey = rsa.newkeys(1024)
        self.serverPubkey = None

        try:
            self.serverPubkey = rsa.PublicKey.load_pkcs1(self.sock.recv(1024))
            self.sock.send(self.pubkey.save_pkcs1("PEM"))
        except Exception as e:
            print(f'Error in exchanging the public keys: {e}')
            exit(0)

        guiThread = threading.Thread(target=self.guiLoop)
        receiveThread = threading.Thread(target=self.receive)

        guiThread.start()
        receiveThread.start()

    #  Function to create the GUI
    def guiLoop(self):
        try:
            self.win = tkinter.Tk()
            self.win.configure(bg='lightgray')

            self.chatLabel = tkinter.Label(self.win, text='Chat:', bg='lightgray')
            self.chatLabel.config(font=('Arial', 12))
            self.chatLabel.pack(padx=20, pady=5)

            self.textArea = tkinter.scrolledtext.ScrolledText(self.win)
            self.textArea.pack(padx=20, pady=5)
            self.textArea.config(state='disabled')

            self.msgLabel = tkinter.Label(self.win, text='Message:', bg='lightgray')
            self.msgLabel.config(font=('Arial', 12))
            self.msgLabel.pack(padx=20, pady=5)

            self.inputArea = tkinter.Text(self.win, height=3)
            self.inputArea.pack(padx=20, pady=5)

            self.sendButton = tkinter.Button(self.win, text='send', command=self.write)
            self.sendButton.config(font=('Arial', 12))
            self.sendButton.pack(padx=20, pady=5)

            self.leaveButton = tkinter.Button(self.win, text='Leave', command=self.leave)
            self.leaveButton.config(font=('Arial', 12))
            self.leaveButton.pack(padx=20, pady=5)

            self.guiDone = True

            self.win.protocol('WM_DELETE_WINDOW', self.stop)

            self.win.mainloop()

            while self.win:
                self.win.update()
                if self.stopFlag.is_set():
                    self.win.destroy()
                    self.win = None

        except Exception as e:
            print(f'Error in creating the GUI: {e}')
            self.stop()

    # Function to send the message to the server
    def write(self):
        try:
            msg = f'{self.nickname}: {self.inputArea.get("0.1", "end")}'
            message = msg.rstrip('\n')
            if message[len(self.nickname) + 2:].startswith('/'):
                if self.nickname == 'ADMIN':
                    if message[len(self.nickname) + 2:].startswith('/kick'):
                        self.sock.send(
                            rsa.encrypt(f'KICK {message[len(self.nickname) + 8:]}'.encode('utf-8'), self.serverPubkey))
                        self.inputArea.delete('0.1', 'end')

                    elif message[len(self.nickname) + 2:].startswith('/ban'):
                        self.sock.send(
                            rsa.encrypt(f'BAN {message[len(self.nickname) + 7:]}'.encode('utf-8'), self.serverPubkey))
                        self.inputArea.delete('0.1', 'end')
                    else:
                        self.sock.send(rsa.encrypt(message.encode('utf-8'), self.serverPubkey))
                        self.inputArea.delete('0.1', 'end')
                else:
                    print('Not ADMIN')
            else:
                self.sock.send(rsa.encrypt(message.encode('utf-8'), self.serverPubkey))
                self.inputArea.delete('0.1', 'end')
        except Exception as e:
            print(f'Error in sending the message: {e}')
            self.stop()

    # Function to stop the client
    def stop(self):
        try:
            self.running = False
            self.stopFlag.set()
            self.sock.close()
        except Exception as e:
            print(f'Error in stopping the client: {e}')
            exit(0)

    def leave(self):
        try:
            self.sock.send(rsa.encrypt(f'LEAVE {self.nickname}'.encode('utf-8'), self.serverPubkey))
            self.stop()
        except Exception as e:
            print(f'Error in leaving the chat: {e}')
            self.stop()

    # Function to receive and decrypt messages from the server
    def receive(self):
        while self.running:
            try:
                message = rsa.decrypt(self.sock.recv(1024), self.privkey).decode('utf-8')
                if message == 'NICK':
                    self.sock.send(rsa.encrypt(self.nickname.encode('utf-8'), self.serverPubkey))
                    nextMessage = rsa.decrypt(self.sock.recv(1024), self.privkey).decode('utf-8')
                    if nextMessage == "PASS":
                        self.sock.send(rsa.encrypt(self.hashPassword.encode('utf-8'), self.serverPubkey))
                        nextMessage = rsa.decrypt(self.sock.recv(1024), self.privkey).decode('utf-8')  # Add this line
                        if nextMessage == 'REFUSE':  # Check if the next message is 'REFUSE'
                            print('Connection refused!!')
                            self.stop()
                    elif nextMessage == 'BANNED':
                        print('connection refused because of ban')
                        self.stop()
                else:
                    if self.guiDone:
                        self.textArea.config(state='normal')
                        self.textArea.insert('end', f'{message}\n')
                        self.textArea.yview('end')
                        self.textArea.config(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                print('error')
                self.sock.close()
                break


def signal_handler(sig, frame):
    print("Shutting down client...")
    client.stop()
    sys.exit(0)


# Create a client object
if HOST and PORT:
    client = Client(HOST, PORT)
else:
    print('Error in getting the network information')
    exit(0)

signal.signal(signal.SIGINT, signal_handler)
