import socket
import sys

PORT_SERVER = 5006
EXPECTED_DATA_LEN = 100
PROBING_PORT = 6006

IP_DEST_SERVER = 'localhost'


def create_socket_and_connect(ip_addr, port):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (ip_addr, port)
    print "connecting to port: " + str(port) + " server_address %s" % server_address[0]
    sock.connect(server_address)

    return sock


def main():
    # ========================
    # connect to server
    # ========================
    sock = create_socket_and_connect(IP_DEST_SERVER, PORT_SERVER)

    try:
        # ==================
        # send probing port
        # ==================
        message = str(PROBING_PORT)
        print 'sending "%s"' % message
        sock.sendall(message)

        # =======================
        # wait server reponse
        # =======================

        # after sending port probing, the server will send a msg to ack that now is listen to probe port,
        # other, trigger timeout
        # todo add timeout
        data = sock.recv(EXPECTED_DATA_LEN)
        print "received data: %s" % data

        # case recv fail
        if data == 0:
            # TODO this case
            print("ERROR")
            exit(2)

        # ===========================
        # connecting to probing port
        # ===========================
        sock_probe = create_socket_and_connect(IP_DEST_SERVER, PROBING_PORT)
        # todo check sock probe failures
        print "succes probing port: %s" % PROBING_PORT


    finally:
        print "closing socket"
        sock.close()


if __name__ == '__main__':
    main()
