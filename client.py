#!/usr/bin/python3
# COMP 3331 17s1 Assignment 1 - Instant Messaging Client
# Weilon Ying z5059444
# This is a Python 3 program

import os
import socket
import sys
import select


# Establish connection with message server and send commands
def connect (host, port):
    # Create a socket (SOCK_STREAM = TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((host, port))
        # received = str(sock.recv(1024), "utf-8")
        # print (received)
        try:
            while (True):
                socket_list = [sys.stdin, sock]

                inputready, outputready, exceptready = select.select(socket_list, [], [])

                for s in inputready:
                    if s == sock:
                        # we have incoming message
                        message = sock.recv(2048)
                        if not message:
                            print ("Disconnected from server")
                            sys.exit(0)
                        else:
                            message = str(message, "utf-8").rstrip()
                            print (message)
                    else:
                        # we have a message to send out
                        message = sys.stdin.readline()
                        if len(message) > 0:
                            sock.send(bytes(message, "utf-8"))
                            print ("Sent " + message)
        except KeyboardInterrupt:
            print ("Closing connection")
            sock.close()
        except Exception as err:
            print ("An error has occurred")
            print (err)
            sock.close()

if (len(sys.argv[1:]) >= 2):
    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
        connect(host, port)

    except Exception as err:
        print ("An error has occurred")
        print (err)

else:
    print ("Usage: python3 client.py <server IP> <server port>")

#print ("Sent:       {}".format(data))
#print ("Received:   {}".format(received))
