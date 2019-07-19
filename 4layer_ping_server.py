"""
Program goal:
support 4layer ping
How is work:
The program is a listener server, that waiting for client connection.
the first msg receive is a "port probing", in other words,
this server will use this port number and create addition listener on this port for probing.
if client succsess to connect to probing port, its mean ping success, other, not success.(i.e: port is block by iptable)
"""
import socket
import sys
import threading
PORT_LISTEN = 5006
ADDRESS_LISTEN = 'localhost'


FLAG_THREAD = 0
# 0 still no change
# 1 success probe
# 2 fail testing probe


def create_socket_and_bind(ip_addr, port):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # just DEBUG: permits reusing address
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the port
    server_address = (ip_addr, port)
    sock.bind(server_address)

    return sock


def listen_probe_port(port_probe):

    global FLAG_THREAD
    print "creating socket in thread for probing port"
    sock_probe = create_socket_and_bind(ADDRESS_LISTEN, port_probe)
    # todo if socket probe not create because problem need to send error msg to client

    sock_probe.listen(100)
    FLAG_THREAD = 1

    connection, client_address = sock_probe.accept()

    if connection:
        print "accept probe sock: client_addr %s" % str(client_address)
        print "probing port %s success" % str(port_probe)
        sock_probe.close()
    else:
        print "TODO!"


def main():
    global FLAG_THREAD
    # create welcome socket
    sock_wel = create_socket_and_bind(ADDRESS_LISTEN, PORT_LISTEN)
    sock_wel.listen(100)

    while True:
        # =======================
        # Wait for a connection
        # =======================
        print "server listen on port :" + str(PORT_LISTEN)
        connection, client_address = sock_wel.accept()

        if connection:
            # ====================
            # receive port probing
            # ====================
            data = connection.recv(1000)
            print 'received data: "%s"' % data
            print("try to listen to probing port")
            data = int(data)

            # =========================================
            #  create listener on port probing
            #  report status of connection on port probing
            # =========================================
            threading.Thread(target=listen_probe_port, args=(data,)).start()
            if data != 0:
                print "sending msg to client about probing port status .."

                while True:
                    # this while is sampling the thread to know is socket_probe is in listen/error, etc
                    print("success to listen probing port")
                    # 1 mean that second listener is waiting
                    if FLAG_THREAD == 1:
                        connection.sendall("success to listen probing port")
                        # TODO maybe add join to here
                        break

                    if FLAG_THREAD == 2:
                        pass


if __name__ == '__main__':
    main()