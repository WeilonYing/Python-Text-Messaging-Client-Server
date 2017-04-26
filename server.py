# COMP3331 Assignment
# Server
# Weilon Ying (z5059444)
# Written with some assistance from code.activestate.com/recipes/531824-chat-server-client-using-selectselect/

import select
import socket
import sys
import signal



usermap = {}
socketlist = []

class User(object):
    def __init__(self, host, sock):
        self.name = ''
        self.host = host
        self.sock = sock

        self.loggedIn = False
        self.username = None
        self.password = None

    def authenticate(self, message=None):
        output = 'null'
        if not message:
            output = "Please enter your username"

        elif not self.username and not self.password:
            self.username = message
            output = "Please enter your password"
        elif not self.password:
            self.password = message
            with open("credentials.txt") as f:
                for line in f:
                    credential = line.split(" ")

                    if (self.username == credential[0].rstrip()) and (self.password == credential[1].rstrip()):

                        self.loggedIn = True
                        self.name = self.username
                        output = "You have logged in as " + self.name
            if (not self.loggedIn):
                output = "Incorrect username or password"
                self.username = None
                self.password = None
                self.authenticate() # restart authentication procedure
        else:
            output = "Incorrect username or password. Please try again."
            self.username = None
            self.password = None
            self.authenticate()
        self.sock.sendall(bytes(output, 'utf-8'))

    def logout(self):
        usermap[self.sock] = None
        socketlist.remove(self.sock)
        self.loggedIn = False
        self.sock.close()
        self.sock = None

    def process(self, message=None):
        #output = "You said: " + message + "\n"
        #self.sock.sendall(bytes(output, 'utf-8'))
        if (not self.loggedIn):
            self.authenticate(message)
        else:
            #output = "You said: " + message + "\n"
            output = "null"
            if (message == "logout"):
                output = "Goodbye!"
                self.sock.sendall(bytes(output, 'utf-8'))
                self.logout()

            if (message == "help"):
                output = "== Available Commands ==\n"
                output += "logout - logs you out of the server\n"
                output += "broadcast - send a message to all current online users\n"
            else:
                output = "Invalid command. Type 'help' for list of available commands"

            # send output
            if self.sock:
                self.sock.sendall(bytes(output, 'utf-8'))

def serve(port, timeout, blockduration):
    welcomesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    welcomesocket.bind(('localhost', port))
    welcomesocket.listen(20)

    socketlist.append(welcomesocket)

    print ("Server started")

    while True:
        readready, writeready, exceptionready = select.select(socketlist, [], [], timeout)

        for sock in readready:
            if sock == welcomesocket:
                clientsocket, address = welcomesocket.accept()
                socketlist.append(clientsocket)
                print ("Client connected:", address)
                clientsocket.sendall(bytes("Hello! ", 'utf-8'))
                newUser = User(address, clientsocket)
                usermap[clientsocket] = newUser
                usermap[clientsocket].process()

                #broadcast(welcomesocket, clientsocket, "User " + str(address) + " has logged in")

            else:
                try:
                    data = sock.recv(2048)
                    if data:
                        #broadcast(welcomesocket, sock, "\r" + str(sock.getpeername()) + ": " + str(data, 'utf-8'))
                        usermap[sock].process(str(data, 'utf-8').rstrip())
                    else:
                        if sock in socketlist:
                            socketlist.remove(sock)
                        broadcast(welcomesocket, sock, "\r" + str(address) + " has logged out")
                except:
                    broadcast(welcomesocket, sock, "\r" + str(address) + " has logged out")
                    continue
    welcomesocket.close()

def broadcast (serversocket, sock, message):
    for socket in socketlist:
        if socket != serversocket:
            try:
                socket.send(bytes(message, 'utf-8'))
            except Exception as err:
                print (err)
                socket.close()
                if socket in socketlist:
                    socketlist.remove(socket)



if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug
        debug = False

        #try:
        port = int(args[0])
        blockduration = int(args[1])
        timeout = int(args[2])

        if (len(args) > 3):
            if args[3] == '-d':
                debug = True
        serve(port, timeout, blockduration)
        #server = Server(port)
        #server.serve()
        #except Exception as err:
        #    print("Error has occurred in main")
        #    print(err)

    else:
        print ("Usage: python3 server.py server_port block_duration timeout [-d]")

