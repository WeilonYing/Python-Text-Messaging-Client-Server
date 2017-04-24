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


    def handle(self):
        self.loggedIn = False
        # self.request is the TCP socket connected to the client
        #self.data = self.request.recv(1024).strip()
        keepRunning = True
        numEmptyCommand = 0

        while (keepRunning and numEmptyCommand < 100):
            try:
                if (not self.loggedIn):
                    self.loggedIn = authenticate(self)
                else:
                    output = ' '
                    command = str(recvMessage(self), "utf-8")

                    # command validation
                    if len(command) == 0:
                        numEmptyCommand += 1
                        continue

                    if (command == "logout"):
                        keepRunning = False
                        output = "Goodbye!"

                    elif (command == "hello"):
                        output = "Hello there!"
                    sendMessage(self, output)
            except Exception as err:
                dPrint("Exception occurred. Closing connection")
                break

def authenticate(self):
    sendMessage(self, "Welcome! \nPlease enter your username: ")
    user = str(recvMessage(self), "utf-8").rstrip()
    sendMessage(self, "Please enter your password: ")
    password = str(recvMessage(self), "utf-8").rstrip()

    # credential format = <user> <password>
    try:
        with open ("credentials.txt") as f:
            for line in f:
                credential = line.split(" ")
                if user == credential[0].rstrip():
                    if password == credential[1].rstrip():
                        sendMessage(self, "Congrats. You have logged in!")
                        return True

    except Exception as err:
        sendMessage(self, "Internal Server Error")
        dPrint("An exception has occurred")
        dPrint(err)

    sendMessage(self, "Invalid username or password\n")
    return False

def recvMessage(self):
    return self.request.recv(1024).strip()
def sendMessage(self, message):
    self.request.sendall(message.encode('utf-8'))

# Debug print - only print if debug enabled
def dPrint(message):
    if debug == True:
        print(message)

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
            server = socketserver.TCPServer((host, port), TCPHandler)
            server.serve_forever()

        except Exception as err:
            print ("Error parsing arguments")
            print (err)
    else:
        print ("Usage: ./server.py server_port block_duration timeout [-d]")


