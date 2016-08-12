#!/usr/bin/env python

import sys
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)

sock.listen(1)

while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'
    connection, client_address = sock.accept()
    try:
        print >>sys.stderr, 'connection from', client_address
        while True:
			# Receive the data in small chunks and retransmit it:
			data = connection.recv(256)
			if data == "read database":
				print "they want da data mon"

    finally:
        # Clean up the connection
        connection.close()
