"""Module for car implementation.

This implementation will be done by using socket library."""

import logging
import socket
import struct
import random

logger = logging.getLogger(__name__)


# Port number for SDP server
V2G_UDP_SDP_SERVER = 15118
# Possible ports for SDP client
V2G_UDP_SDP_CLIENT = range(49152, 65535)
# Possible ports for TCP server/client
V2G_DST_TCP_DATA = range(49152, 65535)
V2G_SRC_TCP_DATA = V2G_DST_TCP_DATA


def start(interface: str = "eth_car"):
    """Start car."""
    logger.debug("Starting car")
    # After the IP address is assigned to the interface
    # For now, the IP address is assigned manually
    # Or automatically from bash script: config_boards.sh

    start_sdp_client(interface=interface)
    start_tcp_client()


def start_sdp_client(interface: str = "eth_car"):
    """Start SDP client."""
    # SECC Discovery Protocol Server port
    port = V2G_UDP_SDP_SERVER

    # Create a UDP socket
    SDP_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

    # IPv6 multicast group address for all nodes on the local network segment
    # Check with %eth_car, seems to work both ways
    multicast_address = "ff02::1"
    link_local_address = "fe80::d237:45ff:fe88:b12a"

    # Get the interface index of the interface with the specified name
    interface_index = socket.if_nametoindex(interface)
    # Port number 0 => let the system choose a free port
    # flowinfo is set to 0 also
    # Bind for the link-local address is necessary, because the SDP server
    # sends the response to the link-local address of the client
    src_port = random.choice(V2G_UDP_SDP_CLIENT)
    SDP_socket.bind((link_local_address, src_port, 0, interface_index))

    # Set the interface for sending multicast packets
    # Seems to be not necessary if SDP_socket.bind() is used
    # I use also bind() because of the setting port number and link-local address
    # Withou bind():
    # getsockname() ('::', 48982, 0, 0)
    # with bind():
    # getsockname() ('fe80::d237:45ff:fe88:b12a', 48982, 0, 16)
    # If setsockopt() or bind() isn't used =>
    # the socket is not bound to the interface
    # TODO: Add bind because of the setting port number
    SDP_socket.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_IF,
        struct.pack("I", interface_index),
    )

    sock_addr = socket.getaddrinfo(
        multicast_address, port, socket.AF_INET6, socket.SOCK_DGRAM
    )[0][4]
    print(f"Send to:{sock_addr}")

    # TODO: Send regular V2G SDP request message
    SDP_socket.sendto(b"SDP hello from client", sock_addr)
    print(SDP_socket.getsockname())

    # Sending request until response is received
    while True:
        response, server_address = SDP_socket.recvfrom(1024)
        if response:
            # TODO: Add parser for SDP response
            print(f"Received response: {response} from {server_address}")
            break

    SDP_socket.close()
    print("SDP client finished")


def start_tcp_client():
    """Start TCP client."""
    print("TCP client started")
    interface = "eth_car"
    interface_index = socket.if_nametoindex(interface)
    # TCP server port and address will be received from SDP response
    # For now, it's hardcoded
    tcp_server_port = 15119
    tcp_server_address = "fe80::d237:45ff:fe88:b12b"

    link_local_address = "fe80::d237:45ff:fe88:b12a"
    src_port = random.choice(V2G_SRC_TCP_DATA)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.bind((link_local_address, src_port, 0, interface_index))
        sock.connect((tcp_server_address, tcp_server_port, 0, 0))
        sock.sendall(b"TCP Hello from client")
        data = sock.recv(1024)

    sock.close()

    print(f"Received {data.decode('utf-8')}")
