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

# Global timeout variable
timeout = 300 # default value 300

# User object. Has user-specfic functions and attributes.
class User(object):
    def __init__(self, host, sock):
        self.name = ''
        self.host = host
        self.sock = sock

        self.loggedIn = False
        self.username = None
        self.password = None
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
            blocklist.append(username)
            return username + " has been blocked."

    def unblock(self, username):
        self.initBlocklistIfNotExists()

        blocklist = blocklists[self.name]
        if (username == self.name):
            return "You cannot unblock yourself!"
        if (username not in blocklist):
            return username + " is already unblocked."
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
                        broadcast(self.sock, self.name + " has logged in")

                        loginhistory[self.name] = datetime.now()
                        self.sock.sendall(bytes(output, 'utf-8'))
                        self.getOfflineMessages()
                        return
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

    def getOfflineMessages(self):
        if self.name in offlineMessages:
            messageList = offlineMessages[self.name]
            if len(messageList) > 0:
                header = "\n== You received messages while you were offline ==\n"
                self.sock.sendall(bytes(header, 'utf-8'))

                for message in messageList:
                    self.sock.sendall(bytes(message + "\n", 'utf-8'))

        offlineMessages[self.name] = []


    def logout(self):
        loginhistory[self.name] = datetime.now()
        broadcast(self.sock, self.name + " has logged out")
        usermap[self.sock] = None
        socketlist.remove(self.sock)
        self.loggedIn = False
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
                        target, content = parameter.split(" ", maxsplit=1)
                        prefix = "[" + self.name + " -> me]: "
                        content = prefix + content

                        if (target != self.name):
                            result = sendmessage(self.sock, target, content)
                            if (result == SUCCESS):
                                output = "[me -> " + target + "]: " + content
                                now = datetime.now()
                                nowstr = "[" + now.strftime("%Y-%m-%d %H:%M:%S") + "]"
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
                        if sentToAll:
                            output = "Broadcast message sent"
                        else:
                            output = "Broadcast message sent\n"
                            output += "This message could not be sent to some recipients."
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

def serve(port, blockduration):
    global welcomesocket
    welcomesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    welcomesocket.bind(('localhost', port))
    welcomesocket.listen(20)

    socketlist.append(welcomesocket)

    print ("Server started")

    try:
        checktimeout()

        while True:
            readready, writeready, exceptionready = select.select(socketlist, [], [])

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
                                loginhistory[user.name] = datetime.now()
                                broadcast(sock, user.name + " has logged out")
                                usermap[sock] = None
                    except:
                        if sock in socketlist:
                            socketlist.remove(sock)
                        if sock in usermap:
                            user = usermap[sock]
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
        threading.Timer(1.0, checktimeout).start()
        message = "You have timed out. Logging you out."

        now = datetime.now()
        for sock in usermap:
            user = usermap[sock]
            if user:
                difference = (now - user.lastReceived).total_seconds()
                if (difference > timeout):
                    sock.sendall(bytes("\r" + message, 'utf-8'))
                    user.logout()
                    sock.sendall(None)
    except KeyboardInterrupt:
        return # simply exit the repetition

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
        if sock != welcomesocket and sock != sourcesocket:
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

if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug
        debug = False

        port = int(args[0])
        blockduration = int(args[1])
        timeout = int(args[2]) # timeout is a global variable

        if (len(args) > 3):
            if args[3] == '-d':
                debug = True
        serve(port, blockduration)

    else:
        print ("Usage: python3 server.py server_port block_duration timeout [-d]")

