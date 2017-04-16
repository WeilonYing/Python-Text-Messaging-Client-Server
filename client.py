#!/usr/bin/python3
# COMP 3331 17s1 Assignment 1 - Instant Messaging Client
# Weilon Ying z5059444
# This is a Python 3 program

import socket
import sys
HOST, PORT = "localhost", 12999
data = " ".join(sys.argv[1:])

# Create a socket (SOCK_STREAM = TCP socket)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # Connect to server and send data
    sock.connect((HOST, PORT))
    sock.sendall(bytes(data + "\n", "utf-8"))

    # Receive data from the server and shut down
    received = str(sock.recv(1024), "utf-8")

print ("Sent:       {}".format(data))
print ("Received:   {}".format(received))
