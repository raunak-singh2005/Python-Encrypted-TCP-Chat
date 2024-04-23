#! /usr/bin/python3
import socket
import threading
import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog
import rsa

HOST = '192.168.0.75'
PORT = 9091

class Client:

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        
        msg = tkinter.Tk()
        msg.withdraw()

        self.nickname = simpledialog.askstring('Nickname', 'Please choose a nickname', parent=msg)
        
        self.guiDone = False
        self.running = True
        self.pubkey, self.privkey = rsa.newkeys(1024)
        self.serverPubkey = None

        self.serverPubkey = rsa.PublicKey.load_pkcs1(self.sock.recv(1024))
        self.sock.send(self.pubkey.save_pkcs1("PEM"))
        
        guiThread = threading.Thread(target=self.guiLoop)
        receiveThread = threading.Thread(target=self.receive)

        guiThread.start()
        receiveThread.start()

    def guiLoop(self):
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
        
        self.guiDone = True
        
        self.win.protocol('WM_DELETE_WINDOW', self.stop)
        
        self.win.mainloop()
    
    def write(self):
        message = f'{self.nickname}: {self.inputArea.get("0.1","end")}'.encode("utf-8")

        self.sock.send(rsa.encrypt(message, self.serverPubkey))
        self.inputArea.delete('0.1', 'end')
    
    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)
    
    def receive(self):
        while self.running:
            try:
                message = rsa.decrypt(self.sock.recv(1024), self.privkey).decode("utf-8")
                if message == "FULL":
                    self.stop()
                elif message == 'NICK':
                    self.sock.send(rsa.encrypt(self.nickname.encode('utf-8'), self.serverPubkey))
                else:
                    if self.guiDone:
                        self.textArea.config(state='normal')
                        self.textArea.insert('end', message)
                        self.textArea.yview('end')
                        self.textArea.config(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                print('error')
                self.sock.close()
                break


client = Client(HOST, PORT)
