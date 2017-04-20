#!/usr/bin/python3
# COMP3331 17s1 Assignment 1 - Instant Messaging Server
# Weilon Ying z5059444
# This is a Python 3 program.

import sys
import socketserver

class TCPHandler (socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    #loggedIn = False
    def __init__(self, functions, *args, **keys):
        self.authenticate = functions['authenticate']
        self.sendMessage = functions['sendMessage']
        self.recvMessage = functions['recvMessage']

        socketserver.BaseRequestHandler.__init__(self, *args, **keys)


    def handle(self):
        self.loggedIn = False
        # self.request is the TCP socket connected to the client
        #self.data = self.request.recv(1024).strip()
        keepRunning = True

        while (keepRunning):
            if (not self.loggedIn):
                self.loggedIn = self.authenticate(self, self.recvMessage, self.sendMessage)
            else:
                command = str(self.recvMessage(self), "utf-8")
                print(command)
                if (command == "logout"):
                    keepRunning = False
                    self.sendMessage(self, "Goodbye!")
                elif (command == "hello"):
                    sendMessage(self, "Hello there!")

def authenticate(self, recvMessage, sendMessage):
    self.sendMessage(self, "Welcome! \nPlease enter your username: ")
    user = self.recvMessage(self)
    self.sendMessage(self, "Please enter your password: ")
    password = recvMessage(self)

    self.sendMessage(self, "Congrats. You have logged in! (%s, %s)" %
            (user, password))
    return True

def recvMessage(self):
    return self.request.recv(1024).strip()
def sendMessage(self, message):
    self.request.sendall(message.encode('utf-8'))

# Debug print - only print if debug enabled
def dPrint(message):
    if debug == True:
        print(message)

def createHandler():
    def make(*args, **keys):
        functions = {}
        functions['authenticate'] = authenticate
        functions['recvMessage'] = recvMessage
        functions['sendMessage'] = sendMessage

        return TCPHandler(functions, *args, **keys)
    return make

# main function
if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug # global debugging variable
        debug = False

        # arg order: server port, block duration, timeout
        try:
            port = int(args[0])
            blockDuration = int(args[1])
            timeout = int(args[2])

            if (len(args) > 3):
                if args[3] == "-d":
                    debug = True
                    dPrint ("Debugging enabled")
                    dPrint ("Port = %d, Block duration = %d, Timeout = %d"
                            % (port, blockDuration, timeout))
            dPrint("Hello World!")
            host = "localhost"
            server = socketserver.TCPServer((host, port), createHandler())
            server.serve_forever()

        except Exception as err:
            print ("Error parsing arguments")
            print (err)
    else:
        print ("Usage: ./server.py server_port block_duration timeout [-d]")


