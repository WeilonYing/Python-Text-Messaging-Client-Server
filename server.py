# COMP3331 Assignment
# Server
# Weilon Ying (z5059444)
# Written with some assistance from code.activestate.com/recipes/531824-chat-server-client-using-selectselect/

import select
import socket
import sys
import signal

class User(object):
    def __init__(self, name, host, sock, server):
        self.name = name
        self.host = host
        self.sock = sock
        self.server = server
        self.loggedIn = False

    def process(self, message):
        output = "You said: " + message + "\n"
        sock.sendall(output)

class Server(object):
    def __init__(self, port=12500):
        # initialise instance variables
        self.numclients = 0 # track number of clients
        self.usermap = {} # map sockets to user objects
        self.outputs = [] # list of output sockets
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('localhost', port))

        self.server.listen(20) # maximum connection backlog of 20
        #signal.signal(signal.SIGINT, self.finish())

    def finish(self):
        # shutdown the server
        print ("Shutting down")
        for o in self.outputs:
            o.close()
        self.server.close()

    def serve(self):
        inputs = [self.server, sys.stdin]
        running = True

        while (running):
            try:
                inputready, outputready, exceptready = select.select(inputs, self.outputs, [])
            except Exception as err:
                print ("An error has occurred")
                print (err)
                break

            for sock in inputready:
                if (sock == self.server):
                    clientsocket, address = self.server.accept()
                    self.numclients += 1
                    newuser = User("Test User", address, clientsocket, self)
                    self.usermap[clientsocket] = newuser
                    newuser.process("Hello")
                    self.outputs.append(client)

                if (sock == sys.stdin):
                    pass
                else:
                    try:
                        message = receiveText(sock)
                        if (message):
                            user = self.usermap[sock]
                            user.process(message)
                        else:
                            user = self.usermap[sock]
                            print ("User + " + user.name + " has logged out")
                            self.numclients -= 1
                            inputs.remove(sock)
                            self.outputs.remove(sock)
                    except Exception as err:
                        inputs.remove(sock)
                        self.outputs.remove(sock)

        self.server.close()

    def receiveText(self, sock):
        try:
            message = str(sock.recv(2048), "utf-8").rstrip()
        except:
            message = None
        return message



if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        args = sys.argv[1:]
        global debug
        debug = False

        try:
            port = int(args[0])
            blockduration = int(args[1])
            timeout = int(args[2])

            if (len(args) > 3):
                if args[3] == '-d':
                    debug = True
            Server(port).serve()
        except Exception as err:
            print(err)

    else:
        print ("Usage: python3 server.py server_port block_duration timeout [-d]")

