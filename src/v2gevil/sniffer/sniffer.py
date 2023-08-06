""" Module for sniffing packets.

This module is used for sniffing packets.
It can sniff packets live on interface or analyze pcap file.
"""
import logging
import os.path
from scapy.all import rdpcap
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw  # Used for PDU of packet
from scapy.layers.inet import TCP
from scapy.sendrecv import sniff as scapy_sniff

from ..v2gtp import v2gtp

logger = logging.getLogger(__name__)


# TODO: Think about to use pyshark instead of scapy for sniffing
def pyshark_sniff():
    """Sniff packets using pyshark.

    It will be implemented in future, because I will need to check if pyshark
    is faster / more reliable than scapy for sniffing packets.
    It's also handy because it's wrapper around tshark, so i can use dissectors
    from wireshark. I already use one dissector from wireshark for V2GTP packets.
    """
    raise NotImplementedError


# Because pyshark is wrapper around tshark, so i can use dissectors from wireshark
def sniff(
    live: bool,
    interface: str,
    file: str,
    ipv6: bool,
    v2gtp_flag: bool,
):
    """Sniff packets live or from pcap file

    Only one of live or pcap can be True, not both at the same time.
    Will call live_sniff or analyze method based on live or pcap flag.
    """
    print("Sniffing packets...")
    logger.debug("Sniffing packets")

    if live:
        live_sniff(interface, ipv6, v2gtp_flag)
    else:
        analyze(
            file=file, ipv6=ipv6, print_summary=True, v2gtp_flag=v2gtp_flag
        )


def analyze(
    file: str,
    ipv6: bool,
    print_summary: bool = True,
    v2gtp_flag: bool = False,
):
    """Analyze packets from pcap file
    Args:
        file: pcap file to analyze
        ipv6: True if only IPv6 packets should be analyzed
        print_summary: True if only summary of packets should be printed

    Returns:
        Depending on print_summary flag, it will return None or filtered packets
    """

    if not os.path.isfile(file):
        logger.error("File %s does not exists!", file)
        exit(1)

    print("Analyzing packets from file %s", file)
    logger.debug("Analyzing packets")

    # TODO: Probably, change to use scapy.sniff(offline=file), test speed of both
    packets = rdpcap(file)
    # Only IPv6 packets
    if ipv6:
        filtered_packets = packets.filter(
            lambda pkt: pkt[IPv6] if IPv6 in pkt else None
        )
    # Both IPv4 and IPv6 packets
    else:
        filtered_packets = packets

    if print_summary:
        if v2gtp_flag:
            print("Printing only V2GTP packets summary")
            logger.debug("Printing only V2GTP packets summary")
            filtered_packets = filtered_packets.filter(
                lambda pkt: v2gtp.has_v2gtp_layer(pkt)
            )
            v2gtp.decode_v2gtp_packets(filtered_packets)
        filtered_packets.nsummary()
        return None

    return filtered_packets


def live_sniff(interface: str, ipv6: bool, v2gtp_flag: bool):
    """Sniff packets live on interface

    Args:
        interface: Interface to sniff on
        ipv6: True if only IPv6 packets should be sniffed
        v2gtp_flag: True if only V2GTP packets should be sniffed

    Returns:
        None
    """

    print("Sniffing packets live on interface %s", interface)
    logger.debug("Sniffing packets live on interface %s", interface)
    # Only IPv6 packets
    if ipv6:
        logger.debug("Performing sniffing only for IPv6 packets")
        scapy_sniff(iface=interface, filter="ip6")
        if v2gtp_flag:
            # TODO: Write prn function to print only V2GTP packets
            logger.debug("Performing sniffing only for V2GTP packets")
            scapy_sniff(
                iface=interface,
                filter="ip6 and tcp port 15118",
                prn=v2gtp.prn_v2gtp_pkt,
            )
    # Both IPv4 and IPv6 packets, probably not needed in case of V2GTP
    else:
        logger.debug("Performing sniffing for both IPv4 and IPv6 packets")
        scapy_sniff(iface=interface, filter="ip")


def inspect(file: str, packet_num: int, show: str, decode: bool):
    """Method for inspecting one packet with given number of the packet.

    Method will inspect packet with given number from pcap file.
    It will show only given part of packet, depending on show flag.
    If decode flag is True and show flag is "raw",
    then it will try to decode packet as V2GTP packet.

    Args:
        file: pcap file from which to inspect packet
        packet_num: Number of packet to inspect
        show: Show only given part of packet
            - all: Show all layers of packet
            - raw: Show only Raw layer of packet
                - If decode is True, then it will try to decode packet as V2GTP packet
            - ipv6: Show only IPv6 layer of packet
            - tcp: Show only TCP layer of packet
    """

    # Check if isFile() if in analyze method
    packets = analyze(file, ipv6=False, print_summary=False)
    if packets is None:
        logger.error("Packets are None!")
        exit(1)

    print("Inspecting packet number %s, using packet.show()", packet_num)
    logger.debug("Number of packets: %s", len(packets))
    if 0 <= packet_num < len(packets):
        pkt = packets[packet_num]
    else:
        logger.error("Invalid packet number!")
        exit(1)

    show_enum = {"all", "raw", "ipv6", "tcp"}
    if show not in show_enum:
        logger.error("Invalid show option! Exiting...")
        exit(1)
        # Maybe switch to raise ValueError instead of exit
        # For now it will be exit because whole stack trace is long and not needed
        # raise ValueError("Invalid show option!")

    if show == "all":
        pkt.show()
    elif show == "raw":
        if v2gtp.has_raw_layer(pkt):
            logger.debug("Packet has Raw layer!")
            pkt[Raw].show()
            print(pkt[Raw].fields)
            if decode is True:
                logger.debug("Trying to decode packet as V2GTP packet...")
                # TODO: implement print_decoded_v2gtp_pkt instead of decode_v2gtp_pkt
                # in print function use decode_v2gtp_pkt, maybe just add
                # another parameter to decode_v2gtp_pkt, something like print_decoded
                v2gtp.decode_v2gtp_pkt(pkt, payload_type="auto")
        return
    elif show == "ipv6":
        # Maybe change to if pkt.haslayer(IPv6): Don't know what is faster
        # or if IPv6 in pkt:
        if v2gtp.has_ipv6_layer(pkt):
            logger.debug("Packet has IPv6 layer!")
            pkt[IPv6].show()
            print(pkt[IPv6].fields)
        return

    elif show == "tcp":
        if v2gtp.has_tcp_layer(pkt):
            logger.debug("Packet has TCP layer!")
            pkt[TCP].show()
            print(pkt[TCP].fields)
        return
