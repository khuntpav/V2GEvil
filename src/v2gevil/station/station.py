"""Module for the station implementation."""

import logging
import socket
import struct


logger = logging.getLogger(__name__)

V2G_UDP_SDP_SERVER_PORT = 15118


def start():
    """Start station."""
    # After Data-Link is established
    # TODO: SECC shall configure the IP address of the station (static of dynamic)

    # After the IP address is assigned, the station should start the SDP server
    # TODO: Start SDP
    start_sdp_server()
    # TODO: After SDP server started successfully, wait for TCP/TLS connection
    # initialization depending on the SDP response message
    # Wait until the TCP/TLS connection is established

    # After the TCP/TLS connection is established, SECC shall wait for init
    # of the V2G communication session

    # After TLS/TCP connection is established, SECC can stop SDP server
    stop_sdp_server()


def start_sdp_server():
    """Start SDP server.

    The SDP server is started on UDP (multicast) port 15118 (defined in ISO15118-2).
    Should accepts UDP packets with a local-link IP multicast destination address
    """

    # Create a UDP socket
    SDP_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
    # Bind the socket to the port
    SDP_socket.bind(("", V2G_UDP_SDP_SERVER_PORT))

    # Join the multicast group
    # IPv6 multicast group address for all nodes on the local network segment
    multicast_addr = "ff02::1"
    # Convert the multicast address to binary format
    mcast_bin = socket.inet_pton(socket.AF_INET6, multicast_addr)
    # ! stands for network (= big-endian) order
    # mreq = struct.pack("!16s", mcast_bin)
    mreq = struct.pack("16s", mcast_bin)
    print(mcast_bin)
    print(mreq)
    SDP_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    exit(0)


def stop_sdp_server():
    """Stop SDP server."""
