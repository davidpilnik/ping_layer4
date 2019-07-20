# ping_layer4
ping over tcp/udp, probing ports

Client:
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

Server:
"""
Program goal:
support 4layer ping
How is work:
The program is a listener server, that waiting for client connection.
the first msg receive contain "port probing", protocol and size, in other words,
this server will use this port number and create addition listener on this port - for probing.
if client success to connect to probing port, its mean ping success, other, fail (i.e: port is block by iptable).
"""