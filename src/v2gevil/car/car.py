"""
V2GEvil - Tool for testing and evaluation of V2G communication.
Copyright (C) 2024 Pavel Khunt

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
"""

"""Module for car implementation (EVCC).

This implementation will be done by using socket library."""

import logging
import socket
import struct
import random

from ..v2gtp.v2gtp import V2GTPMessage
from ..v2gtp.v2gtp_enums import V2GTPProtocols, V2GTPAddress, V2GTPPorts

logger = logging.getLogger(__name__)


# Port number for SDP server
V2G_UDP_SDP_SERVER = 15118
# Possible ports for SDP client
V2G_UDP_SDP_CLIENT = range(49152, 65535)
# Possible ports for TCP server/client
V2G_DST_TCP_DATA = range(49152, 65535)
V2G_SRC_TCP_DATA = V2G_DST_TCP_DATA


class ClientManager:
    """Class for managing client (car/EVCC)."""

    def __init__(
        self,
        interface: str = "eth_car",
        ipv6_address: str = V2GTPAddress.CAR.value,
        protocol: bytes = V2GTPProtocols.TCP.value,
        tls_flag: bool = False,
        accept_security: bool = True,
    ):
        """Initialize."""
        self.interface = interface
        self.ipv6_address = ipv6_address
        self.protocol = protocol
        self.tls_flag = tls_flag
        self.accept_security = accept_security
        self.tcp_server_address = None
        self.tcp_server_port = None

    def sdp_client(self):
        """Start SDP client."""

        # SECC Discovery Protocol Server port
        port = V2G_UDP_SDP_SERVER

        # Create a UDP socket
        SDP_socket = socket.socket(
            family=socket.AF_INET6, type=socket.SOCK_DGRAM
        )

        # IPv6 multicast group address for all nodes on the local network segment
        # Check with %eth_car, seems to work both ways
        # Have to have .value, because otherwise it's not a string type, but Enum type
        # str type is needed for socket.getaddrinfo(), otherwise it will raise Error
        multicast_address = V2GTPAddress.MULTICAST_ADDRESS.value
        link_local_address = V2GTPAddress.CAR.value

        # Get the interface index of the interface with the specified name
        interface_index = socket.if_nametoindex(self.interface)

        src_port = random.choice(V2G_UDP_SDP_CLIENT)
        SDP_socket.bind((link_local_address, src_port, 0, interface_index))
        SDP_socket.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_MULTICAST_IF,
            struct.pack("I", interface_index),
        )

        sock_addr = socket.getaddrinfo(
            multicast_address, port, socket.AF_INET6, socket.SOCK_DGRAM
        )[0][4]
        print(f"Send to:{sock_addr}")

        msg = V2GTPMessage()
        sdp_request = msg.create_v2gtp_sdp_request(
            protocol=self.protocol, tls_flag=self.tls_flag
        )
        SDP_socket.sendto(sdp_request, sock_addr)
        print(SDP_socket.getsockname())

        # Sending request until response is received
        while True:
            data, server_address = SDP_socket.recvfrom(1024)
            if data:
                security_byte, protocol_byte = self.sdp_response_handler(
                    data, server_address
                )
                # If True, TLS will be used if is in SDP response from server
                if self.accept_security:
                    if security_byte == V2GTPProtocols.TLS:
                        self.tls_flag = True
                    elif security_byte == V2GTPProtocols.NO_TLS:
                        self.tls_flag = False
                # False => security byte has to be the same as in SDP request
                # If security byte is different, raise ValueError
                else:
                    if security_byte == V2GTPProtocols.TLS and self.tls_flag:
                        pass
                    elif (
                        security_byte == V2GTPProtocols.NO_TLS
                        and not self.tls_flag
                    ):
                        pass
                    else:
                        raise ValueError(
                            "TLS flag in SDP response is different"
                            "than in SDP request and user chose not to accept"
                        )
                break

        SDP_socket.close()
        print("SDP client finished")
        return security_byte, protocol_byte

    def sdp_response_handler(self, data: bytes, server_address: str):
        """Handle SDP response from SDP server."""
        sdp_response = V2GTPMessage(data)
        print(f"Received response: {data} from {server_address}")
        (
            self.tcp_server_address,
            self.tcp_server_port,
            security_byte,
            protocol_byte,
        ) = sdp_response.parse_v2gtp_sdp_response()

        # Convert from bytes to int
        self.tcp_server_port = int.from_bytes(
            self.tcp_server_port, byteorder="big"
        )
        # Convert from packet binary format to IPv6 address string format
        self.tcp_server_address = socket.inet_ntop(
            socket.AF_INET6, self.tcp_server_address
        )

        print(
            f"Server address: {self.tcp_server_address}, "
            f"server port: {self.tcp_server_port}, "
            f"security byte: {security_byte}, "
            f"protocol byte: {protocol_byte}\n"
        )

        return security_byte, protocol_byte

    def tcp_client(self, security_byte: bytes):
        """Start TCP client."""

        print("TCP client started")
        interface_index = socket.if_nametoindex(self.interface)
        # TCP server port and address will be received from SDP response
        # For now, it's hardcoded
        if security_byte == V2GTPProtocols.NO_TLS:
            # TODO: Run on plain TCP
            link_local_address = self.ipv6_address
            src_port = random.choice(
                range(
                    V2GTPPorts.V2G_SRC_TCP_DATA_START.value,
                    V2GTPPorts.V2G_SRC_TCP_DATA_END.value,
                )
            )

            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.bind((link_local_address, src_port, 0, interface_index))
                sock.connect(
                    (self.tcp_server_address, self.tcp_server_port, 0, 0)
                )
                sock.sendall(b"TCP Hello from client")
                data = sock.recv(1024)
                print(f"Received {data}")

            sock.close()

            # print(f"Received {data.decode('utf-8')}")
        elif security_byte == V2GTPProtocols.TLS:
            # TODO: Add TLS support, TLS server, it's not implemented yet
            raise NotImplementedError("TLS server is not implemented yet")
        else:
            raise ValueError("Unknown security byte")


def start(
    interface: str = "eth_car",
    ipv6_address: str = V2GTPAddress.CAR.value,
    protocol: bytes = V2GTPProtocols.TCP.value,
    tls_flag: bool = False,
    accept_security: bool = True,
):
    """Start car."""
    logger.debug("Starting car")
    # After the IP address is assigned to the interface
    # For now, the IP address is assigned manually
    # Or automatically from bash script: config_boards.sh
    testing_tcp_timeout = False
    # Class testing
    testing_class = True

    if testing_class:
        client = ClientManager(
            interface=interface,
            ipv6_address=ipv6_address,
            protocol=protocol,
            tls_flag=tls_flag,
            accept_security=accept_security,
        )
        # security and protocol byte are returned from server in SDP response
        security_byte, protocol_byte = client.sdp_client()
        if protocol_byte == V2GTPProtocols.TCP:
            client.tcp_client(security_byte)
        elif protocol_byte == V2GTPProtocols.UDP:
            raise NotImplementedError("UDP is not used for V2G EXI messages")
        else:
            raise ValueError(
                "Unknown protocol byte, provided value is reserved"
            )

    # TODO: Delete this part, it's only for testing
    else:
        if testing_tcp_timeout:
            start_sdp_client(
                interface=interface, protocol=protocol, tls_flag=tls_flag
            )
        else:
            start_sdp_client(
                interface=interface, protocol=protocol, tls_flag=tls_flag
            )
            start_tcp_client()


def start_sdp_client(
    interface: str = "eth_car",
    protocol: bytes = V2GTPProtocols.TCP.value,
    tls_flag: bool = False,
):
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
    msg = V2GTPMessage()
    sdp_request = msg.create_v2gtp_sdp_request(
        protocol=protocol, tls_flag=tls_flag
    )
    SDP_socket.sendto(sdp_request, sock_addr)
    print(SDP_socket.getsockname())

    # Sending request until response is received
    while True:
        data, server_address = SDP_socket.recvfrom(1024)
        if data:
            # TODO: Use server_address and port in start_tcp_client method
            sdp_response = V2GTPMessage(data)
            print(f"Received response: {data} from {server_address}")
            (
                server_address,
                server_port,
                security_byte,
                protocol_byte,
            ) = sdp_response.parse_v2gtp_sdp_response()
            print(
                f"Server address: {server_address}, "
                f"server port: {server_port}, "
                f"security byte: {security_byte}, "
                f"protocol: {protocol_byte}"
            )
            break

    SDP_socket.close()
    print("SDP client finished")


def start_tcp_client(
    interface: str = "eth_car",
    server_address: str = V2GTPAddress.STATION.value,
    server_port: int = 15119,
):
    """Start TCP client."""
    print("TCP client started")
    interface = "eth_car"
    interface_index = socket.if_nametoindex(interface)
    # TCP server port and address will be received from SDP response
    # For now, it's hardcoded
    # TODO: Use server_address and port from SDP response

    link_local_address = V2GTPAddress.CAR.value
    src_port = random.choice(
        range(
            V2GTPPorts.V2G_SRC_TCP_DATA_START.value,
            V2GTPPorts.V2G_SRC_TCP_DATA_END.value,
        )
    )

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.bind((link_local_address, src_port, 0, interface_index))
        sock.connect((server_address, server_port, 0, 0))
        sock.sendall(b"TCP Hello from client")
        data = sock.recv(1024)

    sock.close()

    print(f"Received {data.decode('utf-8')}")
