#!/usr/bin/python3
# NOTE: This requires Python 3 to run
# COMP 3331 17s1 Assignment 1 - Instant Messaging Client
# client.py
# This is the client program for the COMP3331 Networks Assignment 1
# Written by Weilon Ying (z5059444)
# Credits:
#   Some of the code was written with assistance from http://code.activestate.com/recipes/531824-chat-server-client-using-selectselect/.
#   This included the use of select to accept connections from multiple clients, and establishing connection from the client side.
#   The function getHostAddress() was written with some assistance from http://stackoverflow.com/a/28950776

import os
import socket
import sys
import select

EOF_FLAG = "0xDEADBEEF" # arbitrarily defined message to tell client to close connection

# Get the IP address of this client
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

# Establish connection with message server and send commands
def connect (host, port):
    # Create a socket (SOCK_STREAM = TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((host, port))
        try:
            while (True):
                socket_list = [sys.stdin, sock]

                inputready, outputready, exceptready = select.select(socket_list, [], [])

                for s in inputready:
                    if s == sock:
                        # we have incoming message
                        message = sock.recv(2048)
                        if not message:
                            sock.close()
                            print ("\nDisconnected from server")
                            sys.exit(0)
                        else:
                            message = str(message, "utf-8").rstrip()
                            if (message == EOF_FLAG):
                                sock.close()
                                print("\nDisconnected from server due to timeout")
                                sys.exit(0)

                            print (message)
                            print (" > ", end="", flush=True)
                    else:
                        # we have a message to send out
                        message = sys.stdin.readline()
                        if len(message) > 0:
                            sock.send(bytes(message, "utf-8"))
                            #print ("Sent " + message)
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
        if host == "localhost" or host == "127.0.0.1":
            host = getHostAddress()
        port = int(sys.argv[2])
        connect(host, port)

    except Exception as err:
        print ("An error has occurred")
        print (err)

else:
    print ("Usage: python3 client.py <server IP> <server port>")

