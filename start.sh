#!/bin/sh

python3 server.py 12999 10 10 &
python3 client.py localhost 12999
