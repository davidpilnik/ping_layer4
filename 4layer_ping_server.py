"""
Program goal:
support 4layer ping
How is work:
The program is a listener server, that waiting for client connection.
the first msg receive contain "port probing", protocol and size, in other words,
this server will use this port number and create addition listener on this port - for probing.
if client success to connect to probing port, its mean ping success, other, fail (i.e: port is block by iptable).
"""
import socket
import time
import sys
import argparse
import errno

EXPECTED_DATA_LEN = 1024
DEBUG = True


def log(v):
    if DEBUG:
        print("[DEBUG]"+str(v))


def add_args():
    parser = argparse.ArgumentParser(description='ping layer4 server'
                                                 'Run example:\n python 4layer_ping_server.py --server_addr 192.168.1.174 --server_port 5003',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--server_addr', type=str, default='localhost', help="server listener address")
    parser.add_argument('--server_port', type=int, default=5001, help="port server")
    return parser


def parser_data(data):
    # TODO case parser fail
    data = data.split('#')
    return data[0], data[1], data[2], data[3]


def loop_reply_ping(conne_probe, size_probe, protocol_probe, client_address):
    data_ping = '0' * int(size_probe)
    seq = 0
    while True:
        try:

            pre_time = time.time()

            stopper = conne_probe.recv(int(size_probe))
            conne_probe.send(data_ping)

            curr_time = time.time()

            time_ping = curr_time - pre_time
            print "reply: %s bytes from %s:%s %s seq=%s time=%s ms" % (size_probe, client_address[0], client_address[1], protocol_probe, seq, time_ping)

            time.sleep(1)
            seq = seq + 1

            if stopper == 'stop':
                break
        except socket.error as err:
            print "[ERROR] socket failed with error %s" % err
            exit(-1)

        except IOError as e:
            if e.errno == errno.EPIPE:
                pass


def create_socket_and_bind(ip_addr, port, protocol='tcp', timeout=None):
    """
    At start function try to create socket accoding params, if fail: exit code.
    case creation socket success: the function try to bind port,
    case bind succeed - return socket obj bind,
    case fail, return string error socket.

    :param ip_addr:
    :param port:
    :param protocol:
    :return: socket obj or socket error msg
    """
    sock = None
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if timeout is not None:
                sock.settimeout(timeout)
            if DEBUG:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        elif protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if timeout is not None:
                sock.settimeout(timeout)
            if DEBUG:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        log("Socket protocol %s successfully created" % protocol)

    except socket.error as err:
        print "socket creation failed with error %s" % err
        exit(-1)

    try:
        # Bind the socket to the port
        log("socket bind succeed")
        server_address = (ip_addr, port)
        sock.bind(server_address)

    except socket.error as err:
        print "socket bind failed with error %s" % err
        sock.close()
        return err

    return sock


def run(server_addr, server_port):
    sock_wel = None
    sock_probe = None

    # create welcome socket
    sock_wel = create_socket_and_bind(server_addr, server_port)
    if not isinstance(sock_wel, socket._socketobject):
        exit(-1)

    sock_wel.listen(100)

    while True:
        try:
            # =====================================
            # Welcome socket wait for a connection
            # =====================================
            print "Server listen on ip: " + str(server_addr) + ", port: " + str(server_port)
            connection, client_address = sock_wel.accept()

            if connection:
                # ============================================
                # receive [port, protocol, timeout] for  probing
                # ============================================
                data = connection.recv(EXPECTED_DATA_LEN)
                port_probe, protocol_probe, size_probe, timeout_probe = parser_data(data)
                print "Data recv: port_probe: %s protocol_probe %s size_probe %s timeout_probe %s " \
                      % (port_probe, protocol_probe, size_probe, timeout_probe)

                # =========================================
                #  create listener on port probing
                # =========================================
                print "Creating socket for probing port"
                sock_probe = create_socket_and_bind(server_addr, int(port_probe), protocol_probe, int(timeout_probe))

                if isinstance(sock_probe, socket._socketobject):
                    # case socket probe is ok
                    if protocol_probe == 'tcp':
                        sock_probe.listen(10)

                    # ============================================
                    # ack client that probe socket listen
                    # ============================================
                    print "Sending msg=9999 to client that probe_port on listen"
                    connection.sendall("9999")

                    # ===============================
                    # wait client connection &
                    # report connection status
                    # ================================
                    if protocol_probe == 'tcp':
                        conne_probe, client_address_probe = sock_probe.accept()
                        if conne_probe:
                            log("Accept probe_sock from client_addr: %s" % str(client_address))
                            print "SUCCESS! probing port: %s, protocol: %s" % (str(port_probe), str(protocol_probe))

                            loop_reply_ping(conne_probe, size_probe, protocol_probe, client_address)
                            sock_probe.close()
                        else:
                            # case when not success to probe
                            print "[ERROR]: connection to probe port FAIL"

                    elif protocol_probe == 'udp':
                        udp_data, udp_client_addr = sock_probe.recvfrom(int(size_probe))
                        sock_probe.connect(udp_client_addr)

                        print "SUCCESS! probing port %s , protocol %s" % (str(port_probe), str(protocol_probe))
                        log("Sending \'udp ack\' to client")
                        sock_probe.send(udp_data)

                        loop_reply_ping(sock_probe, size_probe, protocol_probe, udp_client_addr)
                        sock_probe.close()

                else:
                    # case socket probe FAIL
                    print "Sending error msg to client that probe_port FAIL!"
                    connection.sendall(str(sock_probe))

        except KeyboardInterrupt:
            sys.exit(-3)

        except BaseException as e:
            print "[ERROR] SERVER CRASH! " + str(e)

            if isinstance(sock_probe, socket._socketobject):
                sock_probe.close()

            if not isinstance(sock_wel, socket._socketobject):
                # create welcome socket
                sock_wel = create_socket_and_bind(server_port, server_port)
                if not isinstance(sock_wel, socket._socketobject):
                    exit(-1)
                sock_wel.listen(100)


def main():
    parser = add_args()
    args = parser.parse_args()

    log(args.server_addr)
    log(args.server_port)

    run(args.server_addr, args.server_port)


if __name__ == '__main__':
    main()

