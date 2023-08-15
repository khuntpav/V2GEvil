"""Module for the station implementation."""

import logging
import socket
import struct

logger = logging.getLogger(__name__)


def start(interface: str = "eth_station"):
    """Start station."""
    # After Data-Link is established
    # TODO: SECC shall configure the IP address of the station (static of dynamic)

    # After the IP address is assigned, the station should start the SDP server
    # TODO: Start SDP
    start_sdp_server(interface=interface)
    # TODO: After SDP server started successfully, wait for TCP/TLS connection
    # initialization depending on the SDP response message
    # Wait until the TCP/TLS connection is established

    # After the TCP/TLS connection is established, SECC shall wait for init
    # of the V2G communication session

    # After TLS/TCP connection is established, SECC can stop SDP server
    stop_sdp_server()


def start_sdp_server(interface: str = "eth_station"):
    """Start SDP server.

    The SDP server is started on UDP (multicast) port 15118 (defined in ISO15118-2).
    Should accepts UDP packets with a local-link IP multicast destination address
    """
    # TODO: Get the IP address of the station

    logger.debug(
        "Starting SDP server, interface: %s interface-index: %s",
        interface,
        socket.if_nametoindex(interface),
    )

    # Create a UDP socket
    SDP_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

    # IPv6 multicast group address for all nodes on the local network segment
    # multicast_addr = r"ff02::1%eth_station"
    # IPv6 link-local address
    # link_local_address = r"fe80::d237:45ff:fe88:b12b%eth_station"
    interface_index = socket.if_nametoindex(interface)

    # link_local_address = socket.inet_ntop(
    #    socket.AF_INET6,
    #    socket.inet_pton(socket.AF_INET6, f"fe80::{interface_index}"),
    # )

    # Bind to the multicast group address
    V2G_UDP_SDP_SERVER_PORT = 15118
    port = V2G_UDP_SDP_SERVER_PORT

    # Bind for IPv6 should use 4-tuple (host, port, flowinfo, scopeid)
    # For AF_INET6 address family, a four-tuple (host, port, flowinfo, scope_id)
    # is used, where flowinfo and scope_id represent the sin6_flowinfo
    # and sin6_scope_id members in struct sockaddr_in6 in C
    # From getaddrinfo() documentation:
    # The function returns a list of 5-tuples with the following structure:
    # (family, type, proto, canonname, sockaddr), interesting is sockaddr
    # sockaddr is a tuple describing a socket address, whose format depends
    # on the returned family (a (address, port) 2-tuple for AF_INET,
    # a (address, port, flowinfo, scope_id) 4-tuple for AF_INET6),
    # and is meant to be passed to the socket.connect() method or bind()
    # The scope_id is a number that identifies the interface in a scope.
    # can be obtained from if_nametoindex() or from the ip link show in linux
    multicast_address = "ff02::1"
    link_local_address = "fe80::d237:45ff:fe88:b12b"
    logger.debug(socket.getaddrinfo(link_local_address, port))
    logger.debug(
        socket.getaddrinfo(
            multicast_address,
            port,
            socket.AF_INET6,
            socket.SOCK_DGRAM,
            socket.SOL_UDP,
        )
    )
    # Cannot bind to link-local address, TODO: why?
    # OSError: [Errno 99] Cannot assign requested address => multicast_addr
    # do with multicast or "::" (any address) or ""
    sockaddr = socket.getaddrinfo(
        multicast_address,
        port,
        socket.AF_INET6,
        socket.SOCK_DGRAM,
        socket.SOL_UDP,
    )[0][4]
    logger.debug(sockaddr)

    # SDP_socket.bind(sockaddr)
    # TODO: Check bind above, check if communication is received for
    # multicast_address instead of the link_local_address
    # To receive multicast packets, the socket must be bound to the multicast_address
    SDP_socket.bind((multicast_address, port, 0, interface_index))

    print(SDP_socket.getsockname())
    # print(SDP_socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
    # Without this was not possible to listen on multicasdt
    multicast_addr_bin = socket.inet_pton(socket.AF_INET6, multicast_address)
    join_multicast_group = multicast_addr_bin + struct.pack(
        "I", interface_index
    )
    SDP_socket.setsockopt(
        socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_multicast_group
    )

    print(
        f"UDP server listening on [{multicast_address}]:{port} interface: {interface}"
    )

    try:
        while True:
            data, addr = SDP_socket.recvfrom(1024)
            print(f"Received {len(data)} bytes from {addr}: {data.decode()}")
            # Construct a response message
            response_message = b"Response to " + data

            # Send the response message back to the sender
            SDP_socket.sendto(response_message, addr)

    except KeyboardInterrupt:
        print("Stopping SDP server")
        SDP_socket.close()
    exit(0)

    # When using setsockopt() with IPV6_JOIN_GROUP, the value you provide
    # should be a bytes object that contains both the multicast group address and the interface index.

    # BSD socket API: https://docs.python.org/3/library/socket.html,
    # Missing some constants so to find description of the constants:
    # https://www.ibm.com/docs/en/i/7.4?topic=ssw_ibm_i_74/apis/ssocko.html

    # Join the multicast group
    # Convert the multicast address to binary format
    # inet_aton() does not support IPv6 => use inet_pton() instead
    # Convert an IP address from its family-specific string format to a packed, binary format.

    # multicast_addr_bin = socket.inet_pton(socket.AF_INET6, multicast_addr)

    # socket.IPPROTO_IPV6:
    #   This is the protocol level at which the option resides.
    #   It indicates that the option pertains to the IPv6 protocol.
    # socket.IPV6_JOIN_GROUP:
    #   It indicates that you want to join a multicast group on the given socket
    # join_multicast_group:
    #   It's a bytes-like object that represents the information needed to
    #   specify the multicast group and the interface on which you want to
    #   join the group. This value is constructed by concatenating the binary
    #   representations of the multicast group address and the interface index.
    # ! stands for network (= big-endian) order, for struct.pack()
    # so maybe use !I instead of I

    # join_multicast_group = multicast_addr_bin + struct.pack(
    #    "I", interface_index
    # )

    # SDP_socket.setsockopt(
    #    socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_multicast_group
    # )

    # Bind the socket to the port
    # Hardcoded for now
    # ip_address = "fe80::d237:45ff:fe88:b12b"
    # SDP_socket.bind((ip_address, V2G_UDP_SDP_SERVER_PORT))
    # It's possible to bind single socket to multiple host addresses


def stop_sdp_server():
    """Stop SDP server."""
