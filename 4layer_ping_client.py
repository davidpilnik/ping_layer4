"""
Program task
creating client for ping over tcp/udp
the program create client with "ping server socket"
pass msg that contain port probing , timeout, protocol and size,
the server should create a listener probe_socket for this port probing.
the server will ack with 9999, mean that probe_socket is OK
and finally the client will connect.
(case of udp I write a simple echo to know that probing over udp is ok)
"""
import socket
import sys
import argparse


EXPECTED_DATA_LEN = 100
MSG_SERVER_READY = '9999'
MSG_UDP_CLIENT = '8888'
# PORT_SERVER = 5001
# PROBING_PORT = 6006
# IP_DEST_SERVER = 'localhost'
# PING_TIMEOUT = 10
# PING_PACKET_SIZE = 10
# PING_PROTOCOL = 'tcp'
CLIENT_UDP_IP_PORT = ('localhost', 60000)
DEBUG = True


def log(v):
    if DEBUG:
        print("[DEBUG]"+str(v))


def add_args():
    parser = argparse.ArgumentParser(description='ping layer4 by probing port',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--server_addr', type=str, default='localhost', help="server listener address")
    parser.add_argument('--server_port', type=int, default=5001, help="port server")
    parser.add_argument('--port_probe', type=int, default=6001, help="port probe")
    parser.add_argument('--timeout', type=int , default=15, help="timeout that client wait for server response")
    parser.add_argument('--protocol', type=str, default='tcp', help="support tcp & udp")
    parser.add_argument('--packet_size', type=int, default=10, help="unused")
    return parser


def create_socket_and_connect(ip_addr, port, timeout=30, protocol='tcp'):
    sock = None
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log("Socket successfully created")

    except socket.error as err:
        print "[ERROR] Socket creation failed with error %s" % err
        exit(-1)

    try:
        sock.settimeout(timeout)
        # Connect the socket to the port where the server is listening
        server_address = (ip_addr, port)
        print "Connecting to %s " % str(server_address)
        if protocol == 'tcp':
            sock.connect(server_address)
        elif protocol == 'udp':
            # send msg=8888 and recv from server for make udp more reliable.
            # todo set my ip and port not hard coded
            sock.bind(CLIENT_UDP_IP_PORT)
            sock.sendto(MSG_UDP_CLIENT, server_address)
            data_udp_from_server = sock.recv(EXPECTED_DATA_LEN)

            # udp test for reliabilty
            if int(data_udp_from_server) != int(MSG_UDP_CLIENT):
                print "[ERROR] udp ack data sent to server probe: %s not equal to recv: %s" % (MSG_UDP_CLIENT, data_udp_from_server)
                return "[ERROR] udp ack data sent to server probe not equal to recv"

            log("probing socket udp ACK is OK: %s" % data_udp_from_server)

    except socket.error as err:
        print "[ERROR] socket connect failed with error %s" % err
        sock.close()
        return err

    return sock


def run(server_addr, server_port, ping_port, ping_protocol, ping_timeout, ping_packet_size):

    # ========================
    # connect to server
    # ========================
    res_conn_probe = None
    sock = create_socket_and_connect(server_addr, server_port, ping_timeout)
    if not isinstance(sock, socket._socketobject):
        exit(-1)
    try:

        # ===========================
        # send probing port, protocol
        # ===========================
        message = str(ping_port) + '#' + str(ping_protocol) + '#' + str(ping_packet_size) + '#' + str(ping_timeout)
        print "Sending %s .." % message

        sock.sendall(message)

        # =======================
        # wait server reponse
        # =======================
        data = sock.recv(EXPECTED_DATA_LEN)
        # after sending port probing, the server will send a msg "9999" to ack that now is listen to probe port.
        # case not response trigger timeout
        # case data not equal 9999 the server send the error

        if data == MSG_SERVER_READY:
            print "received server response: %s\n" \
                  "server is ready, listen to probing port %s protocol %s \n" % (int(data), ping_port, ping_protocol)
        else:
            print "[ERROR:] server response not equal \'9999\'.\nServer is not ready," \
                  " no listen to probing port %s error msg from SERVER: %s\nExit." % (ping_port, data)
            exit(-1)

    except socket.error as err:
        print "[ERROR] socket failed with error %s" % err
        sock.close()
        exit(-1)

    # ===========================
    # connecting to probing port
    # ===========================
    res_conn_probe = create_socket_and_connect(server_addr, ping_port, ping_timeout, ping_protocol)

    if isinstance(res_conn_probe, socket._socketobject):
        print "SUCCESS! probing port: %s, protocol: %s \n" % (ping_port, ping_protocol)
        log("Closing probe socket ..")
        res_conn_probe.close()
    else:
        print "Fail! probing port, protocol %s : %s" % (ping_port, ping_protocol)
        # print(str(res_conn_probe))
    log("Closing socket")
    if isinstance(sock, socket._socketobject):
        sock.close()


def main():
    parser = add_args()
    args = parser.parse_args()
    log(args.server_addr)
    log(args.server_port)
    log(args.port_probe)
    log(args.protocol)
    log(args.timeout)
    log(args.packet_size)

    # todo check server ip adderss is a real ip
    run(args.server_addr, args.server_port, args.port_probe, args.protocol, args.timeout, args.packet_size)


if __name__ == '__main__':
    main()
