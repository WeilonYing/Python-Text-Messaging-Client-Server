# COMP3331 Assignment
# Server
# Weilon Ying (z5059444)
# Credits: Written with some assistance from code.activestate.com/recipes/531824-chat-server-client-using-selectselect/

import select
import socket
import sys
import signal

from datetime import datetime, timedelta


# Global current online users and connected sockets list
usermap = {}
socketlist = []

# Global dictionary to store users' last login times since server start
loginhistory = {}

# User object. Has user-specfic functions and attributes.
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
                        broadcast(self.sock, "\r" + self.name + " has logged in")

                        loginhistory[self.name] = datetime.now()
            if (not self.loggedIn):
                output = "Incorrect username or password\n"
                output += "Please enter your username"
                self.username = None
                self.password = None
        else:
            output = "Incorrect username or password. Please try again."
            output += "Please enter your username"
            self.username = None
            self.password = None
        self.sock.sendall(bytes(output, 'utf-8'))

    def logout(self):
        usermap[self.sock] = None
        broadcast(self.sock, "\r" + self.name + " has logged out")
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

            try:
                command, parameter = message.split(" ", maxsplit=1)
            except ValueError:
                command = message
                parameter = None


            if (command == "logout"):
                output = "Goodbye!"
                self.sock.sendall(bytes(output, 'utf-8'))
                self.logout()

            elif (command == "whoelse"):
                output = getOnlineUsers(self.sock)

            elif (command == "whoelsesince"):
                if parameter:
                    try:
                        output = getUsersSince(self.sock, int(parameter))
                    except ValueError:
                        output = "Invalid parameter. Time parameter must be an integer."
                else:
                    output = "Usage: whoelsesince <time>"

            elif (command == "help"):
                output = "== Available Commands ==\n"
                output += "logout - logs you out of the server\n"
                output += "broadcast - send a message to all current online users\n"
                output += "whoelse - see all currently online users\n"
                output += "whoelsesince <time> - see all users who have logged in since <time> seconds ago\n"
            else:
                output = "Invalid command. Type 'help' for list of available commands"

            # send output
            if self.sock:
                self.sock.sendall(bytes(output, 'utf-8'))

def serve(port, timeout, blockduration):
    global welcomesocket
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
                clientsocket.sendall(bytes("Hello! ", 'utf-8'))
                newUser = User(address, clientsocket)
                usermap[clientsocket] = newUser
                usermap[clientsocket].process()

            else:
                try:
                    data = sock.recv(2048)
                    if data:
                        usermap[sock].process(str(data, 'utf-8').rstrip())
                    else:
                        if sock in socketlist:
                            socketlist.remove(sock)
                        if sock in usermap:
                            user = usermap[sock]
                            broadcast(sock, "\r" + user.name + " has logged out")
                            usermap[sock] = None
                except:
                    if sock in socketlist:
                        socketlist.remove(sock)
                    if sock in usermap:
                        user = usermap[sock]
                        broadcast(sock, "\r" + user.name + " has logged out")
                        usermap[sock] = None


    welcomesocket.close()

def broadcast (sourcesocket, message):
    for socket in socketlist:
        if socket != welcomesocket and socket != sourcesocket:
            try:
                socket.send(bytes(message, 'utf-8'))
            except Exception as err:
                print (err)
                socket.close()
                if socket in socketlist:
                    socketlist.remove(socket)

def getOnlineUsers (sourcesocket):
    output = ""
    for sock in usermap:
        if sock != sourcesocket:
            user = usermap[sock]
            if user:
                output += user.name + "\n"
    if len(output) == 0:
        output = "No other users online.\n"
    else:
        output = "== Currently Online ==\n" + output
    return output

def getUsersSince (sourcesocket, sec):
    currentuser = usermap[sourcesocket].name
    output = ''
    now = datetime.now()
    timesince = now - timedelta(seconds=sec)
    for username in loginhistory:
        if username != currentuser:
            if loginhistory[username] > timesince:
                difference = (now - loginhistory[username]).total_seconds()
                difference = int(difference)
                output += username + " - " + str(difference) + " seconds ago\n"

    if len(output) == 0:
        output = "No other users online since " + str(sec) + " seconds ago.\n"
    else:
        header = "== Users logged since %s seconds ago ==\n" % (sec)
        output = header + output

    return output

if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug
        debug = False


        port = int(args[0])
        blockduration = int(args[1])
        timeout = int(args[2])

        if (len(args) > 3):
            if args[3] == '-d':
                debug = True
        serve(port, timeout, blockduration)


    else:
        print ("Usage: python3 server.py server_port block_duration timeout [-d]")

