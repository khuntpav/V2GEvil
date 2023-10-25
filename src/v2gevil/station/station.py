"""
Module for station implementation.

"""


import logging
import socket
import struct
import asyncio
import random
from typing import Optional
from enum import Enum

from ..v2gtp.v2gtp import V2GTPMessage
from ..v2gtp.v2gtp_enums import (
    V2GTPMessageType,
    V2GTPProtocols,
    V2GTPPorts,
    V2GTPAddress,
)
from ..modules.enumerator import EVEnumerator, EVEnumMode
from ..messages.generator import EVSEMessageGenerator

logger = logging.getLogger(__name__)


class EVSEChargingMode(str, Enum):
    """Enum for EVSE charging type."""

    AC = "AC"
    DC = "DC"


class EVSEDetails(str, Enum):
    """Enum for EVSE details."""

    # If an SECC cannot provide such ID data,
    # the value of the EVSEID is set to zero ("ZZ00000").
    # Value taken from ISO 15118-2, page 280
    EVSE_ID = "FRA23E45B78C"
    # Default SchemaID, value from ISO 15118-2, page 59
    SCHEMA_ID = "10"
    PROTOCOL_NAMESPACE = "urn:iso:15118:2:2013:MsgDef"
    INTERFACE = "eth_station"


class ServerManager:
    """Class for managing the servers

    Class for managing the servers (SDP, TCP, TLS)

    Attributes:
        interface: Interface of the station
        ipv6_address: IPv6 address of the station, link-local address
        protocol: Protocol to use for V2GTP communication, TCP or UDP
        sdp_port: Port for SDP server
        tcp_port: Port for TCP server
        tls_flag: Flag for TLS communication
        accept_security: Flag for accepting security from EVCC
        udp_stop_flag: Flag for stopping SDP server
        tcp_continue_flag: Flag for continuing TCP server
        tcp_connection: TCP connection, used by V2GTP communication handler

    """

    def __init__(
        self,
        # Need to .value because of the Enum and some socket methods raise error
        # if enum is passed instead
        interface: str = EVSEDetails.INTERFACE.value,
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
        accept_security: bool = False,
        charging_mode: Optional[EVSEChargingMode] = EVSEChargingMode.AC,
        # Maybe remove enum_flag and leave only ev_enumerator and default to None
        enum_flag: bool = False,
        ev_enumerator: Optional[EVEnumerator] = None,
        # TODO: Add message dict, which will be used to configure the station
        # which content in the V2G responses should be
        # TODO: Add charging mode or maybe handle that only by messages dict
        # TODO: rename to messages_mapping_dict
        messages_mapping_dict: Optional[dict] = None,
        # TODO: also implement method load_config_dict from file, loading json
        # or yaml file, probably json
    ):
        """
        Initialize Server Manager.

        Args:
            interface: Interface of the station
            ipv6_address: IPv6 address of the station, link-local address
            protocol: Protocol to use for V2GTP communication, TCP or UDP
            sdp_port: Port for SDP server
            tcp_port: Port for TCP server
            tls_flag: Flag for TLS communication
            accept_security: Flag for accepting security from EVCC
            charging_mode: Charging mode of the station, AC or DC. Default AC.
        """
        # TODO: Think about used config dict for all these attributes
        # instead of passing them as arguments
        # So maybe use something like config dict for some these parameters
        # and message dict for the V2GTP messages: pairs request-response
        # Can be defined by user
        self.interface = interface
        self.ipv6_address = ipv6_address
        self.protocol = protocol
        self.tcp_port = tcp_port
        self.sdp_port = sdp_port
        # Station will use TLS if flag is True
        self.tls_flag = tls_flag
        # If True: Station will follow the security flag from the EVCC => override tls_flag
        self.accept_security = accept_security
        self.charging_mode = charging_mode
        self.messages_mapping_dict = messages_mapping_dict
        # If True: Station will enumerate all possible information about the EV
        self.enum_flag = enum_flag

        if self.enum_flag:
            # Everything what can be enumerated, will be saved in this enumerator
            # then it can be extracted and displayed to the user, after the
            # station is stopped
            self.ev_enumerator = ev_enumerator

        # Cannot be defined by user
        self.udp_stop_flag = asyncio.Event()
        self.tcp_continue_flag = asyncio.Event()
        self.tcp_connection = None

    def load_messages_dict(self) -> None:
        """Load messages dict for request-response pairs/mapping."""
        if self.messages_mapping_dict is None:
            msg_generator = EVSEMessageGenerator(
                charging_mode=self.charging_mode
            )
            self.messages_mapping_dict = msg_generator.default_dict

    async def start(self):
        """Start station.

        To handle stop of SDP server after TCP connection is established,
        it's necessary to use asyncio."""

        # Load messages dict for request-response pairs/mapping
        self.load_messages_dict()
        logger.debug("Messages dict loaded:")
        logger.debug(self.messages_mapping_dict)

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
                requested_security, _ = sdp_request.parse_v2gtp_sdp_request()

                # TODO:
                # if self.enum_flag:
                #    if EVEnumMode.TLS_CHECK_ONLY in self.ev_enumerator.enum_modes:

                # True => the station use same security as the EVCC requested
                if self.accept_security:
                    if requested_security == V2GTPProtocols.TLS:
                        self.tls_flag = True
                    elif requested_security == V2GTPProtocols.NO_TLS:
                        self.tls_flag = False
                else:
                    if (
                        requested_security == V2GTPProtocols.TLS
                        and self.tls_flag
                    ):
                        pass
                    elif (
                        requested_security == V2GTPProtocols.NO_TLS
                        and not self.tls_flag
                    ):
                        pass
                    else:
                        continue

                # Create proper SDP response message
                sdp_response = sdp_request.create_response(
                    ipv6=self.ipv6_address,
                    port=self.tcp_port,
                    protocol=self.protocol,
                    tls_flag=self.tls_flag,
                )
                response_message = sdp_response
                # Following line just for IDE, because it cannot recognize
                assert isinstance(response_message, bytes)
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
                # TODO: forward the config dict to V2GTPMessage
                # and make all work in V2GTPMessage
                v2gtp_req = V2GTPMessage(data)
                # TODO: v2gtp_req.create_response() add malicious option and messages_dict
                # malicious option indicates no validation when creating pydantic models
                # which allows us to pass for ex. string value to int
                # message_dict, based on this dict corresponding response is created
                # TODO: For some other malicious modules will be some mapping for malicious module name and function
                # which will be called for that module in this V2GTP communication handler
                if self.ev_enumerator is not None:
                    v2gtp_res, req_name = v2gtp_req.create_response(
                        messages_dict=self.messages_mapping_dict,
                        enum_flag=True,
                    )
                    if req_name in self.ev_enumerator.msgs_for_enum:
                        self.ev_enumerator.v2g_requests_dict[
                            req_name
                        ] = v2gtp_req
                        # TODO: Probably not necessary to remove it from the list
                        self.ev_enumerator.msgs_for_enum.remove(req_name)
                        # TODO: Maybe implement in the FUTURE
                        # Some exiting for the station when all messages are enumerated
                        # OR print it to the user and continue with station behavior
                        # OR just print it after the station is stopped - normal behavior
                        # Using some force_stop_flag in the EVEnumerator

                else:
                    v2gtp_res = v2gtp_req.create_response(
                        messages_dict=self.messages_mapping_dict,
                        enum_flag=False,
                    )

                # TODO: Not sure if this is the best way to do it - DONE SEE ABOVE
                # because I need to parse the message again, so it can be slowed down
                # another approach is to save the message in the EVEnumerator without any info of name
                # but for that approach i cannot filter here what messages to save without the names
                # another approach is to return obj_name from create_response(), but it's hacky...
                # Maybe add option to the create_response() enum_flag=True which will return also obj_name

                response_message = v2gtp_res
                # Following line just for IDE, because it cannot recognize
                assert isinstance(response_message, bytes)
                conn.sendall(response_message)
                # TODO: Maybe add del for v2gtp_req and v2gtp_res instances
        except Exception as error:
            print(f"Error processing TCP data: {error}")
        finally:
            self.tcp_continue_flag.clear()
            conn.close()  # Close the connection when done


def start_async(
    interface: str = EVSEDetails.INTERFACE.value,
    accept_security: bool = False,
    charging_mode: Optional[EVSEChargingMode] = EVSEChargingMode.AC,
    enum_flag: bool = False,
    ev_enumerator: Optional[EVEnumerator] = None,
):
    """Start station.

    To handle stop of SDP server after TCP connection is established,
    it's necessary to use asyncio."""

    manager = ServerManager(
        interface=interface,
        accept_security=accept_security,
        charging_mode=charging_mode,
        enum_flag=enum_flag,
        ev_enumerator=ev_enumerator,
    )
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
