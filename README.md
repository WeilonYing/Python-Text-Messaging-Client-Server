# Python-Text-Messaging-Client-Server
## Overview
A TCP text-messaging server and client written in Python 3. Supports basic authentication, blocking and offline messaging. Written as part of a Networks assignment project in April 2017.

## Usage
### Client
`python3 client.py <server IP> <server port>`
* Server IP - The IP address that the chat server is located at
* Server port - The port of the char server
### Server
`python3 server.py <server_port> <block_duration> <timeout>`
 * Server port - The port that this server should listen on.
 * Block duration - The period of time (in seconds) where the IP of a client is blocked if they failed 3 login attempts consecutively.
 * Timeout - The period of time (in seconds) where a client is automatically logged out if no activity is detected from them in that period.


