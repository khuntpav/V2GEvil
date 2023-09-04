"""
Module for station implementation.

"""


import logging
import socket
import struct
import asyncio
import random

from ..v2gtp.v2gtp import V2GTPMessage
from ..v2gtp.v2gtp_enums import (
    V2GTPMessageType,
    V2GTPProtocols,
    V2GTPPorts,
    V2GTPAddress,
)

logger = logging.getLogger(__name__)


class ServerManager:
    """
    Class for managing the servers

    Class for managing the servers (SDP, TCP, TLS)
    """

    def __init__(
        self,
        interface: str = "eth_station",
        ipv6_address: str = V2GTPAddress.STATION.value,
        protocol: bytes = V2GTPProtocols.TCP.value,
        sdp_port: int = V2GTPPorts.V2G_UDP_SDP_SERVER.value,
        tcp_port: int = random.choice(
            range(
                V2GTPPorts.V2G_DST_TCP_DATA_START.value,
                V2GTPPorts.V2G_DST_TCP_DATA_END.value,
            )
        ),
        tls_flag: bool = False,
    ):
        """Initialize Server Manager."""
        # Can be defined by user
        self.interface = interface
        self.ipv6_address = ipv6_address
        self.protocol = protocol
        self.tcp_port = tcp_port
        self.sdp_port = sdp_port
        self.tls_flag = tls_flag

        # Cannot be defined by user
        self.udp_stop_flag = asyncio.Event()
        self.tcp_continue_flag = asyncio.Event()
        self.tcp_connection = None

    async def start(self):
        """Start station.

        To handle stop of SDP server after TCP connection is established,
        it's necessary to use threading (or maybe asyncio)."""

        # After Data-Link is established
        udp_task = asyncio.create_task(self.sdp_server())
        await udp_task

        # OR
        # udp_task = asyncio.create_task(self.sdp_server())
        # tcp_task = asyncio.create_task(self.tcp_server())
        # await asyncio.gather(udp_task, tcp_task)

    async def sdp_server(self):
        """Start SDP server.

        The SDP server is started on UDP (multicast) port 15118 (defined in ISO15118-2).
        Should accepts UDP packets with a local-link IP multicast destination address
        """
        print("SDP server started")

        # Create a UDP socket
        sdp_socket = socket.socket(
            family=socket.AF_INET6, type=socket.SOCK_DGRAM
        )
        # Get interface index
        interface_index = socket.if_nametoindex(self.interface)
        # Bind to the multicast group address
        port = self.sdp_port

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
        multicast_address = V2GTPAddress.MULTICAST_ADDRESS.value

        logger.debug(
            socket.getaddrinfo(
                multicast_address,
                port,
                socket.AF_INET6,
                socket.SOCK_DGRAM,
                socket.SOL_UDP,
            )
        )
        # Bind socket to multicast_address
        sdp_socket.bind((multicast_address, port, 0, interface_index))

        logger.debug(sdp_socket.getsockname())

        # Without this was not possible to listen on multicast
        multicast_addr_bin = socket.inet_pton(
            socket.AF_INET6, multicast_address
        )
        mreq = multicast_addr_bin + struct.pack("I", interface_index)
        sdp_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq
        )

        logger.debug(
            "Starting SDP server, interface: %s interface-index: %s",
            self.interface,
            socket.if_nametoindex(self.interface),
        )

        try:
            while not self.udp_stop_flag.is_set():
                print("SDP server is running in while loop")
                data, addr = sdp_socket.recvfrom(1024)
                # TODO: Add parser for SDP request
                print(f"Received {len(data)} bytes from {addr}: {data}")
                sdp_request = V2GTPMessage(data)
                sdp_response = sdp_request.create_response(
                    ipv6=self.ipv6_address,
                    port=self.tcp_port,
                    protocol=self.protocol,
                    tls_flag=self.tls_flag,
                )

                # TODO: Create proper SDP response message
                response_message = sdp_response
                sdp_socket.sendto(response_message, addr)

                if not self.tcp_continue_flag.is_set():
                    try:
                        # TODO: Add option, user can set timeout in seconds
                        await asyncio.wait_for(self.tcp_server(), timeout=5)
                        print("TCP server connection established")
                        # Process TCP data without timeout
                        await self.v2gtp_comm_handler()
                    except asyncio.TimeoutError:
                        print("TCP server connection timeout")
        except KeyboardInterrupt:
            print("Stopping SDP server by KeyboardInterrupt")
        finally:
            print("SDP server stopped")
            sdp_socket.close()

    async def tcp_server(self):
        """Run TCP server.

        Wait for connection from EVCC.
        After connection is established, stop the SDP server
        and wait for V2G communication session
        """
        logger.debug("TCP server started")

        with socket.socket(
            family=socket.AF_INET6, type=socket.SOCK_STREAM
        ) as server_sock:
            # Get interface index
            interface_index = socket.if_nametoindex(self.interface)
            # Bind to the multicast group address
            # TODO: Use port in bind, and inform the EVCC on which port to connect
            port = self.tcp_port
            link_local_address = self.ipv6_address

            # Add that to sdp_server cause it will inform the EVCC on which
            # port to connect to the TCP server

            # Avoid bind() exception: OSError: [Errno 48] Address already in use
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((link_local_address, port, 0, interface_index))
            server_sock.listen()
            # This will accept only one client
            #  server doesn't accept new connections for each iteration of the loop
            # if i want that i should use while True and accept() in the loop

            server_sock.setblocking(False)
            while not self.tcp_continue_flag.is_set():
                try:
                    conn, addr = server_sock.accept()
                    print("Connected by: ", addr)
                    self.tcp_continue_flag.set()
                    self.tcp_connection = conn
                except BlockingIOError:
                    # No incoming connection, perform other tasks or wait
                    await asyncio.sleep(0.1)  # Non-blocking wait
            print("TCP server loop ended after connection established")

    def tls_server(self):
        """Run TLS server.

        Wait for connection from EVCC.
        After connection is established, stop the SDP server
        and wait for V2G communication session.
        """

    async def v2gtp_comm_handler(self):
        """Handle V2GTP communication.

        After V2G communication session is established, handle V2GTP communication.
        """

        if self.tcp_connection is None:
            return

        logger.debug("V2GTP communication handler started")

        conn = self.tcp_connection
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received from client: {data}")
                response_message = b"Hello from Server"
                conn.sendall(response_message)
        except Exception as error:
            print(f"Error processing TCP data: {error}")
        finally:
            self.tcp_continue_flag.clear()
            conn.close()  # Close the connection when done


def start_async(interface: str = "eth_station"):
    """Start station.

    To handle stop of SDP server after TCP connection is established,
    it's necessary to use asyncio."""

    manager = ServerManager(interface=interface)
    asyncio.run(manager.start())


def start(interface: str = "eth_station"):
    """
    Start station in manual mode. There is no use of asyncio.

    This method suppose normal flow of the V2G communication.
    Sequentially:
        => SDP server is started
        => SDP request is received
        => SDP response is sent
        => SDP server is stopped
        => TCP server waits for connection
        => TCP connection is established on request from EVCC
        => V2G communication session is established
    """

    # After Data-Link is established
    # TODO: SECC shall configure the IP address of the station (static of dynamic)

    # After the IP address is assigned, the station should start the SDP server
    # TODO: Start SDP server thread

    sdp_server(interface=interface)

    # TODO: After SDP server started successfully, wait for TCP/TLS connection
    # initialization depending on the SDP response message
    # Wait until the TCP/TLS connection is established

    # After the TCP/TLS connection is established, SECC shall wait for init
    # of the V2G communication session

    # After TLS/TCP connection is established, SECC can stop SDP server
    # stop_sdp_server()


def sdp_server(interface: str = "eth_station"):
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
    port = V2GTPPorts.V2G_UDP_SDP_SERVER

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
    multicast_address = V2GTPAddress.MULTICAST_ADDRESS
    link_local_address = V2GTPAddress.STATION
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
            # TODO: Check if the received message is SDP request message
            # For now just check if the message is not empty
            if data:
                print(f"Received {len(data)} bytes from {addr}: {data}")
                print(f"Received from: {addr} data: {data}")
                # Construct a response message
                response_message = b"Response to " + data

                # Send the response message back to the sender
                SDP_socket.sendto(response_message, addr)
                break

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
