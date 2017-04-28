# COMP3331 Assignment
# Server
# Weilon Ying (z5059444)
# Credits: Written with some assistance from code.activestate.com/recipes/531824-chat-server-client-using-selectselect/

import os
import select
import socket
import sys
import signal
import threading
import time
import traceback

from datetime import datetime, timedelta


# Global current online users and connected sockets list
usermap = {}
socketlist = []

# Global dictionary to store blocked users/IP's and time of their blocking
blockedFromServer = {}

# Global dictionary to store users' last login times since server start
loginhistory = {}

# Global dictionary to store user's blocklists
blocklists = {}

# Offline messages
offlineMessages = {}

# Status code for user messaging
SUCCESS = 0
BLOCKED = 1
OFFLINE = 2

# Arbitrarily defined message to tell client to close connection
EOF_FLAG = "0xDEADBEEF"
MAX_TRIES = 3

# Global timeout variable
timeout = 300 # default value 300
blockDuration = 300 # default value 300

# User object. Has user-specfic functions and attributes.
class User(object):
    def __init__(self, host, sock):
        self.name = ''
        self.address = host[0]
        self.port = host[1]
        self.sock = sock

        self.loggedIn = False
        self.username = None
        self.password = None
        self.numTries = 0
        self.lastReceived = datetime.now() # stores last time we heard from this user
        self.initBlocklistIfNotExists()

    def initBlocklistIfNotExists(self):
        if self.name not in blocklists:
            blocklists[self.name] = []

    def block(self, username):
        self.initBlocklistIfNotExists()

        blocklist = blocklists[self.name]

        if (username == self.name):
            return "You cannot block yourself!"
        elif (username in blocklist):
            return username + " has already been blocked."
        else:
            with open("credentials.txt") as f:
                for line in f:
                    credential = line.split(" ")
                    if credential[0].rstrip() == username:
                        blocklist.append(username)
                        return username + " has been blocked"
            return username + " does not exist and cannot be blocked."

    def unblock(self, username):
        self.initBlocklistIfNotExists()

        blocklist = blocklists[self.name]
        if (username == self.name):
            return "You cannot unblock yourself!"
        if (username not in blocklist):
            return username + " is not on your block list."
        else:
            blocklist.remove(username)
            return username + " has been unblocked."

    def getBlockList(self):
        self.initBlocklistIfNotExists()

        blocklist = blocklists[self.name]

        if len(blocklist) == 0:
            return "You are not blocking anyone."
        else:
            output = ''
            for username in blocklist:
                output += username + "\n"
            header = "== Users you have blocked ==\n"
            output = header + output

            return output

    def isBlocking(self, username):
        self.initBlocklistIfNotExists()

        blocklist = blocklists[self.name]

        if (username in blocklist):
            return True
        else:
            return False

    # if user is not logged in, we first go through the authentication process
    def authenticate(self, message=None):
        output = 'null'
        # if we get a blank message, remind the user what to do
        if not message:
            if not self.username:
                output = "Please enter your username"
            elif not self.password:
                output = "Please enter your password"
        else:
            # if we haven't received username and password, first valid message will be taken as username
            if not self.username and not self.password:
                self.username = message
                validUsername = False
                with open("credentials.txt") as f:
                    for line in f:
                        credential = line.split(" ")
                        if (self.username == credential[0].rstrip()):
                            validUsername = True
                            break

                if validUsername:
                    self.numTries = 0

                    if isOnline(self.username):
                        self.sock.send(bytes(self.username + " is already online on another session.", 'utf-8'))
                        self.logout()
                        return
                    output = "Please enter your password"
                else:
                    self.numTries += 1
                    if (self.numTries >= MAX_TRIES):
                        self.sock.send(bytes("Too many incorrect tries. Your IP has been blocked for " + str(blockDuration) + " seconds.", 'utf-8'))
                        blockFromServer(self.address)
                        self.logout()
                        return
                    self.username = None
                    output = "Invalid username. Please enter your username."

            # if only the password isn't received, then the next valid message will be the password
            elif not self.password:
                self.password = message
                with open("credentials.txt") as f:
                    for line in f:
                        credential = line.split(" ")

                        if (self.username == credential[0].rstrip()) and (self.password == credential[1].rstrip()):
                            # check if account blocked for multiple login failure
                            if (self.username in blockedFromServer and blockedFromServer[self.username]):
                                self.sock.send(bytes("Your account is currently blocked due to multiple login failures. Please try again later. ", 'utf-8'))
                                self.logout()
                                return
                            self.numTries = 0

                            self.loggedIn = True
                            self.name = self.username
                            output = "You have logged in as " + self.name

                            loginhistory[self.name] = datetime.now()
                            self.sock.sendall(bytes(output, 'utf-8'))
                            broadcast(self.sock, self.name + " has logged in")
                            self.getOfflineMessages()
                            return
                if (not self.loggedIn):
                    self.numTries += 1
                    if (self.numTries >= MAX_TRIES):
                        self.sock.send(bytes("Too many incorrect tries. Your account has been blocked for " + str(blockDuration) + " seconds.", 'utf-8'))
                        blockFromServer(self.username)

                        self.logout()
                        return
                    output = "Incorrect password. Please try again."
                    self.password = None

            # if we somehow end up in neither of the situations above, then reset the login procedure
            else:
                output = "An error has occurred. Please try again."
                output += "Please enter your username"
                self.username = None
                self.password = None
        self.sock.sendall(bytes(output, 'utf-8'))

    # check and receive offline messages sent to this user
    def getOfflineMessages(self):
        if self.name in offlineMessages:
            messageList = offlineMessages[self.name]
            if len(messageList) > 0:
                header = "\n== You received messages while you were offline ==\n"
                self.sock.sendall(bytes(header, 'utf-8'))

                for message in messageList:
                    self.sock.sendall(bytes(message + "\n", 'utf-8'))

        offlineMessages[self.name] = []


    def logout(self, timeoutDisconnect=False):
        if (self.loggedIn):
            broadcast(self.sock, self.name + " has logged out")
            loginhistory[self.name] = datetime.now()

        usermap[self.sock] = None
        socketlist.remove(self.sock)
        self.loggedIn = False
        if (timeoutDisconnect):
            self.sock.sendall(bytes(EOF_FLAG, 'utf-8'))
        self.sock.close()
        self.sock = None

    def process(self, message=None):
        self.lastReceived = datetime.now()

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

            elif (command == "message"):
                if parameter:
                    try:
                        target, rawcontent = parameter.split(" ", maxsplit=1)
                        prefix = "[" + self.name + " -> me]: "
                        content = prefix + rawcontent

                        if (target != self.name):
                            result = sendmessage(self.sock, target, content)
                            if (result == SUCCESS):
                                output = "[me -> " + target + "]: " + rawcontent
                                now = datetime.now()
                                nowstr = "[" + now.strftime("%Y-%m-%d %H:%M:%S") + "] "
                                output = nowstr + output
                            elif (result == BLOCKED):
                                output = target + " has blocked you. You cannot send messages to them."
                            elif (result == OFFLINE):
                                output = target + " is offline. They will receive the message when they next log in."
                            else:
                                output = "[me -> " + target + "]: " + content + "(" + result + ")"
                                now = datetime.now()
                                nowstr = "[" + now.strftime("%Y-%m-%d %H:%M:%S") + "]"
                                output = nowstr + output
                        else:
                            output = "You cannot send messages to yourself."
                    except Exception as err:
                        output = "Invalid parameter. Usage: message <user> <message content>"
                else:
                    output = "Usage: message <user> <message content>"

            elif (command == "broadcast"):
                if parameter:
                    try:
                        broadcastMessage = "[Broadcast] " + self.name + ": " + parameter
                        sentToAll = broadcast(self.sock, broadcastMessage)
                        if not sentToAll:
                            output = "\nYour broadcast message could not be sent to some users."
                        else:
                            output = " " # empty message, since broadcast will be sending the message instead
                    except Exception as err:
                        output = "Invalid parameter. Usage: broadcast <message>"
                else:
                    output = "Usage: broadcast <message>"

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

            elif (command == "block"):
                if parameter:
                    try:
                        output = self.block(parameter)
                    except Exception as err:
                        output = "Invalid parameter. Usage: block <user to block>\n"
                else:
                    output = "Usage: block <user to block>"

            elif (command == "unblock"):
                if parameter:
                    try:
                        output = self.unblock(parameter)
                    except Exception as err:
                        output = "Invalid parameter. Uage: unblock <user to unblock>"
                else:
                    output = "Usage: unblock <user to unblock>"

            elif (command == "blocklist"):
                output = self.getBlockList()

            elif (command == "help"):
                output = "== Available Commands ==\n"
                output += "logout - logs you out of the server\n"
                output += "message <user> <message> - send a message to a specific user\n"
                output += "broadcast <message> - send a message to all current online users\n"
                output += "whoelse - see all currently online users\n"
                output += "whoelsesince <time> - see all users who have logged in since <time> seconds ago\n"
                output += "block <user to block> - block a user from sending messages to you\n"
                output += "unblock <user to unblock> - unblock a user\n"
                output += "blocklist - get a list of users that you've blocked\n"
            else:
                output = "Invalid command. Type 'help' for list of available commands"

            # send output
            if self.sock:
                self.sock.sendall(bytes(output, 'utf-8'))

def serve(port):
    global welcomesocket
    welcomesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostaddress = getHostAddress()
    welcomesocket.bind((hostaddress, port))
    welcomesocket.listen(20)

    socketlist.append(welcomesocket)

    print ("Server started. Listening on " + hostaddress + ":" + str(port))

    try:
        checktimeout()

        while True:
            readready, writeready, exceptionready = select.select(socketlist, [], [])

            for sock in readready:
                if sock == welcomesocket:
                    clientsocket, address = welcomesocket.accept()
                    if address[0] in blockedFromServer and blockedFromServer[address[0]] is not None:
                            clientsocket.sendall(bytes("Your IP is currently blocked. Please try again later. ", 'utf-8'))
                            clientsocket.close()
                    else:
                        socketlist.append(clientsocket)
                        #clientsocket.sendall(bytes("Hello! ", 'utf-8'))
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
                                if user and len(user.name) > 0:
                                    loginhistory[user.name] = datetime.now()
                                    broadcast(sock, user.name + " has logged out")
                                    usermap[sock] = None
                    except:
                        if sock in socketlist:
                            socketlist.remove(sock)
                        if sock in usermap:
                            user = usermap[sock]
                            if user and len(user.name) > 0:
                                loginhistory[user.name] = datetime.now()
                                broadcast(sock, user.name + " has logged out")
                                usermap[sock] = None
    except KeyboardInterrupt: # close everything
        for sock in socketlist:
            sock.close()
        os._exit(0)

    welcomesocket.close()

# check if any of the users have timed out, then reshedules itself to check
# again after 1 second
def checktimeout():
    try:
        threading.Timer(1.0, checktimeout).start() # set a timer to call itself in 1 second

        now = datetime.now()
        # timeout currently logged in users
        for sock in usermap:
            user = usermap[sock]
            if user:
                difference = (now - user.lastReceived).total_seconds()
                if (difference > timeout):
                    user.logout(True)

        # timeout blocked users and IP addresses
        for name in blockedFromServer:
            blockedTime = blockedFromServer[name]
            if blockedTime:
                difference = (now - blockedTime).total_seconds()
                if (difference > blockDuration):
                    blockedFromServer[name] = None

    except KeyboardInterrupt:
        return # simply exit the repetition

def blockFromServer(name):
    now = datetime.now()
    blockedFromServer[name] = now

def sendmessage (sourcesocket, targetuser, message):
    sourceuser = usermap[sourcesocket]

    now = datetime.now()
    nowstr = "[" + now.strftime("%Y-%m-%d %H:%M:%S") + "] "
    message = nowstr + message

    if targetuser in blocklists:
        blocklist = blocklists[targetuser]
        if sourceuser.name in blocklist:
            return BLOCKED

    for sock in socketlist:
        if sock != welcomesocket and sock != sourcesocket:
            if sock in usermap:
                user = usermap[sock]
                if (user.name == targetuser):
                    sock.sendall(bytes("\r" + message, 'utf-8'))
                    return SUCCESS

    offlineMessage(targetuser, message)
    return OFFLINE

def offlineMessage(targetuser, message):
    if targetuser not in offlineMessages:
        offlineMessages[targetuser] = []

    offlineMessages[targetuser].append(message)
    print (offlineMessages)


def broadcast (sourcesocket, message):
    sentToAll = True

    now = datetime.now()
    nowstr = "[" + now.strftime("%Y-%m-%d %H:%M:%S") + "] "
    message = "\r" + nowstr + message

    sourceuser = usermap[sourcesocket]
    for sock in socketlist:
        if sock != welcomesocket:
            try:
                # if source socket and target sockets are linked to users
                # only send message if target user is not blocking source user
                if usermap[sock] and sourceuser:
                    user = usermap[sock]
                    if user.name in blocklists:
                        if user.isBlocking(sourceuser.name):
                            sentToAll = False
                        else:
                            sock.send(bytes(message, 'utf-8'))
                    else:
                        sock.send(bytes(message, 'utf-8'))
                else:
                    sock.send(bytes(message, 'utf-8'))
            except Exception as err:
                print (err)
                sock.close()
                if sock in socketlist:
                    socketlist.remove(sock)

    return sentToAll

def isOnline (name):
    for sock in usermap:
        user = usermap[sock]
        if user:
            if user.name == name:
                return True
    return False

def getOnlineUsers (sourcesocket):
    output = ""
    for sock in usermap:
        if sock != sourcesocket:
            user = usermap[sock]
            if user and len(user.name) > 0:
                output += user.name + "\n"
    if len(output) == 0:
        output = "No other users online.\n"
    else:
        output = "== Currently Online ==\n" + output
    return output

def getUsersSince (sourcesocket, sec):
    if sec < 0:
        sec = 0
    currentuser = usermap[sourcesocket].name
    output = ''
    now = datetime.now()
    timesince = now - timedelta(seconds=sec)

    onlineUserList = []
    for sock in usermap:
        user = usermap[sock]
        if user and user.name != currentuser:
            onlineUserList.append(user.name)
            output += user.name + " - online now\n"

    for username in loginhistory:
        if username != currentuser and username not in onlineUserList:
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

# Get the IP address of this server
# Written with help from http://stackoverflow.com/a/28950776
def getHostAddress ():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable
        sock.connect(("10.255.255.255", 80)) # Dummy IP address
        address = sock.getsockname()[0]
    except:
        address = "127.0.0.1"
    finally:
        sock.close()

    return address

if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug
        debug = False

        port = int(args[0])
        blockDuration = int(args[1])
        timeout = int(args[2]) # timeout is a global variable

        if (len(args) > 3):
            if args[3] == '-d':
                debug = True
        serve(port)

    else:
        print ("Usage: python3 server.py server_port block_duration timeout [-d]")

