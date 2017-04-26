#!/usr/bin/python3
# COMP 3331 17s1 Assignment 1 - Instant Messaging Client
# Weilon Ying z5059444
# This is a Python 3 program

import os
import socket
import sys
import _thread



# Receive messages from messenging server
def receive (sock):
    while (True):
        received = str(sock.recv(1024), "utf-8")
        if (len(received) == 0):
            sock.close()
            break

        print (received)
        if (received == "Goodbye!"):
            sock.close()
            break
    os._exit(0) #exit all threads once we stop receiving

# Establish connection with message server and send commands
def connect (host, port):
    # Create a socket (SOCK_STREAM = TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((host, port))
        # received = str(sock.recv(1024), "utf-8")
        # print (received)
        _thread.start_new_thread(receive, (sock,))
        while (True):
            data = input()
            if (len(data) > 0):

                sock.sendall(bytes(data + "\n", "utf-8"))

                # Receive data from the server and shut down
                # received = str(sock.recv(1024), "utf-8")
                # print (received)
                #if (received == "Goodbye!"):
                #    sock.close()
                #    break

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
