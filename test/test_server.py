import socket
import sys
import ssl

import socket
import sys

def main():

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind(('0.0.0.0', 8888))

    server_socket.listen(1)

    while True:

        new_client_socket, address = server_socket.accept()
        secured_client_socket = ssl.wrap_socket(new_client_socket,
                                                server_side=True,
                                                certfile='../cert.pem',
                                                keyfile='../cert.pem',
                                                ssl_version=ssl.PROTOCOL_TLSv1)

        print new_client_socket, address
        buffer = secured_client_socket.recv()
        print len(buffer)
        print buffer

if __name__ == "__main__":
    main()
