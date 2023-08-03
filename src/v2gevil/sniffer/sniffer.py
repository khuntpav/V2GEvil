""" Module for sniffing packets.

This module is used for sniffing packets.
It can sniff packets live on interface or analyze pcap file.
"""
import logging

# This import really slows down the CLI, so use only some features from that later
# Not importing here, because it slows down the CLI. Importing in functions instead.
# import scapy.all as scapy
from scapy.all import rdpcap
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw  # Used for PDU of packet
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sniff as scapy_sniff

from ..v2gtp import v2gtp

logger = logging.getLogger(__name__)


def sniff(
    live: bool,
    pcap: bool,
    interface: str,
    file: str,
    ipv6: bool,
    v2gtp_flag: bool,
):
    """Sniff packets live"""
    print("Sniffing packets...")
    logger.debug("Sniffing packets")

    if live:
        live_sniff(interface, ipv6, v2gtp_flag)
    elif pcap:
        analyze(file, ipv6)
    else:
        print("Invalid mode!")


# @sniffer_tools.command(name="analyze")
# @click.option("--file", "-f", default=None, show_default=True, help="File to analyze")
def analyze(file: str, ipv6: bool, print_summary: bool = True):
    """Analyze packets from pcap file"""

    print("Analyzing packets from file %s", file)
    logger.debug("Analyzing packets")

    packets = rdpcap(file)
    # Only IPv6 packets
    if ipv6:
        filtered_packets = packets.filter(
            lambda pkt: pkt[IPv6] if IPv6 in pkt else None
        )
    # Both IPv4 and IPv6 packets
    else:
        # TODO: Maybe change it to use like: --ipv4/--ipv6
        filtered_packets = packets

    if print_summary:
        filtered_packets.nsummary()
        return None
    else:
        return filtered_packets


# TODO: I have to find a way how to run poetry as root, because it needs root to sniff packets on interface
def live_sniff(interface: str, ipv6: bool, v2gtp_flag: bool):
    """Sniff packets live on interface"""

    print("Sniffing packets live on interface %s", interface)
    logger.debug("Sniffing packets live on interface %s", interface)
    # Only IPv6 packets
    if ipv6:
        scapy_sniff(iface=interface, filter="ip6")
        if v2gtp_flag:
            scapy_sniff(iface=interface, filter="ip6 and tcp port 15118")
        # TODO: Write prn function to print only V2GTP packets
    # Both IPv4 and IPv6 packets, probably not needed in case of V2GTP
    else:
        scapy_sniff(iface=interface, filter="ip")


def inspect(file: str, ipv6: bool, packet_num: int, show: str, decode: bool):
    """Method for inspecting one packet with given number of the packet"""

    packets = analyze(file, ipv6, print_summary=False)
    if packets is None:
        logger.error("Packets are None!")
        exit(1)

    print("Inspecting packet number %s, using packet.show()", packet_num)
    logger.debug("Number of packets: %s", len(packets))
    if packet_num < len(packets) and packet_num >= 0:
        pkt = packets[packet_num]
    else:
        logger.error("Invalid packet number!")
        exit(1)

    if show == "all":
        pkt.show()
    elif show == "raw":
        if v2gtp.has_raw_layer(pkt):
            logger.debug("Packet has Raw layer!")
            pkt[Raw].show()
            print(pkt[Raw].fields)
            if decode is True:
                logger.debug("Trying to decode packet as V2GTP packet...")
                v2gtp.decode_v2gtp_pkt(pkt)

        else:
            print("Packet doesn't have Raw layer!")
    elif show == "ipv6":
        # Maybe change to if pkt.haslayer(IPv6): Don't know what is faster
        if IPv6 in pkt:
            logger.debug("Packet has IPv6 layer!")
            pkt[IPv6].show()
            print(pkt[IPv6].fields)
        else:
            print("Packet doesn't have IPv6 layer!")
    elif show == "tcp":
        if TCP in pkt:
            logger.debug("Packet has TCP layer!")
            pkt[TCP].show()
            print(pkt[TCP].fields)
        else:
            print("Packet doesn't have TCP layer!")
    else:
        print("Invalid show option!")

    # Testing packets is following:
    # 1. V2GTP SECC discovery request: packet_num=115,116
    # 2. V2GTP SECC discovery response: packet_num=121,122
    # 3. V2GTP V2GEXI request - supportedAppProtocolReq: packet_num=133
    # 4. V2GTP V2GEXI response - supportedAppProtocolRes: packet_num=144
    # 5. V2GTP V2GEXI(ISO1 in Wireshark) request - sessionSetupReq: packet_num=156
    # Number of packet is from Wireshark start from 1, but in scapy it starts from 0, so we need to add 1
