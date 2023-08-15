"""Module for car implementation."""

import logging
import socket
import struct

logger = logging.getLogger(__name__)


def start(interface: str = "eth_car"):
    """Start car."""
    logger.debug("Starting car")
    # After the IP address is at
    start_sdp_client(interface=interface)


def start_sdp_client(interface: str = "eth_car"):
    """Start SDP client."""
    # SECC Discovery Protocol Server port
    V2G_UDP_SDP_SERVER_PORT = 15118
    port = V2G_UDP_SDP_SERVER_PORT

    # Create a UDP socket
    SDP_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

    # IPv6 multicast group address for all nodes on the local network segment
    # TODO: Check with %eth_car, seems to work both ways
    multicast_address = "ff02::1"
    link_local_address = "fe80::d237:45ff:fe88:b12a"

    # Get the interface index of the interface with the specified name
    interface_index = socket.if_nametoindex(interface)
    # Port number 0 => let the system choose a free port
    # flowinfo is set to 0 also
    # Bind for the link-local address is necessary, because the SDP server
    # sends the response to the link-local address of the client
    # SDP_socket.bind((link_local_address, 0, 0, interface_index))

    # Set the interface for sending multicast packets
    # Seems to be not necessary if SDP_socket.bind() is used
    # otherwise the socket is not bound to the interface
    SDP_socket.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_IF,
        struct.pack("I", interface_index),
    )

    # Set socket options to allow multicast, Not necessary
    # SDP_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

    sock_addr = socket.getaddrinfo(
        multicast_address, port, socket.AF_INET6, socket.SOCK_DGRAM
    )[0][4]
    print(f"Send to:{sock_addr}")

    SDP_socket.sendto(b"Hello", sock_addr)
    print(SDP_socket.getsockname())

    # Receive response
    response, server_address = SDP_socket.recvfrom(1024)
    print(
        f"Received response: {response.decode('utf-8')} from {server_address}"
    )
