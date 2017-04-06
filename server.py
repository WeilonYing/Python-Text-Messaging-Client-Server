#!/usr/bin/python3
# COMP3331 17s1 Assignment 1 - Instant Messaging Server
# Weilon Ying z5059444
# This is a Python 3 program.

import sys


def runServer(port, blockDuration, timeout):
    dPrint("Hello World!")


def setupParameters(args):
    global debug # global debugging variable
    debug = False

    # arg order: server port, block duration, timeout
    try:
        port = int(args[0])
        blockDuration = int(args[1])
        timeout = int(args[2])

        if args[3] == "-d":
            debug = True
            dPrint ("Debugging enabled")
            dPrint ("Port = %d, Block duration = %d, Timeout = %d"
                    % (port, blockDuration, timeout))

        runServer(port, blockDuration, timeout)

    except Exception as err:
        print ("Error parsing arguments")
        print (err)

# Debug print - only print if debug enabled
def dPrint(message):
    if debug == True:
        print(message)

# main function
if __name__ == "__main__":
    if (len(sys.argv[1:]) >= 3):
        setupParameters(sys.argv[1:])
    else:
        print ("Usage: ./server.py server_port block_duration timeout [-d]")


