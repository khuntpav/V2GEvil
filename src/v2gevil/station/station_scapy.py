"""Module for station implementation.

This implementation will be done by using Scapy library."""


import logging

from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.sendrecv import sniff as scapy_sniff

logger = logging.getLogger(__name__)


def start(interface: str = "eth_station"):
    """Start car."""
    logger.debug("Starting station")
    # After the IP address is assigned to the interface
    # For now, the IP address is assigned manually
    # Or automatically from bash script: config_boards.sh

    start_sdp_server(interface=interface)


def packet_callback(packet):
    print(packet.summary())


def start_sdp_server(interface: str = "eth_station"):
    """Start SDP server.

    The SDP server is started on UDP (multicast) port 15118 (defined in ISO15118-2).
    Should accepts UDP packets with a local-link IP multicast destination address
    """
    # Kind of mess using sniff, because we need to stop sniffing after
    # we receive SDP packet
    # I think it's better to use socket library for this
    scapy_sniff(
        iface=interface,
        prn=packet_callback,
        filter="ip6 and udp and port 15118",
    )

    # Possible stop of sniffing
    # sniff(filter="ip6 and udp and port 15118", prn=packet_callback,
    #  stop_filter=lambda x: stop_sequence in x[UDP].payload, iface=interface)
