"""Module for V2GTP related commands.

Here is the implementation of the V2GTP protocol,
which is used for communication between EV and EVSE. 
The implementation is based on ISO 15118-2:2014.
"""
import os.path
import logging
import requests

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import linehexdump
from scapy.all import rdpcap


logger = logging.getLogger(__name__)

# TODO: Create class called V2GTP Packet, ihnerit from scapy.Packet
# Rewrite .show() function to show only V2GTP header and payload
# .decode_payload() function for decoding payload
# @Packet.register_packet_class
# class V2GTP(Packet):
# TODO: is_ functions should return True or False, and also return header and payload
# TODO: Later do from is_methods, maybe also some decode methods
#  => methods for Class V2GTPPacket


# Important: The communication between EV and EVSE is also include other IPv6 packets, not only V2GTP packets
# So if we want whole communication, we need to sniff all IPv6 packets and then check them
# There are ICMPv6 packets, which are used for Neighbor Discovery Protocol (NDP)
# NDP is used for IPv6 address autoconfiguration and for IPv6 router discovery
# NDP is also used for Duplicate Address Detection (DAD)
# There are also UDP packets for SECC Discovery Protocol (SDP)
# This function will extract only V2GTP packets from pcap file not whole IPv6 communication
# To extract whole IPv6 communication, use function "analyze" from sniffer module
def extract_v2gtp_pkts_from_file(file: str):
    """Extract V2GTP packets from pcap file"""
    if os.path.isfile(file) is False:
        logger.error("File doesn't exist!")
        exit(1)
    extract_v2gtp_pkts(rdpcap(file))


def extract_v2gtp_pkts(packets):
    """Extract V2GTP packets"""

    for pkt in packets:
        if has_v2gtp_layer(pkt):
            pkt_num = packets.index(pkt) + 1
            print(
                "Packet number: %s is V2GTP packet (Wireshark num.)", pkt_num
            )
            # TODO: Format output like src, dst, payload, etc. usefull for further analysis


# Following methods with has_ prefix are here because of logging
# Without logging, it's not needed to have them
# And just use pkt.haslayer() instead of has_ functions
# TODO: Probably it will be better to use pkt.haslayer() instead of has_ functions
# TODO: Add rewrite haslayer functions to use logging for my class V2GTPPacket
def has_raw_layer(pkt: Packet):
    """Check if packet has Raw layer. Added because check if Raw layer is in packet is used multiple times"""

    if not pkt.haslayer(
        Raw
    ):  # or not Raw in pkt[Raw] what is more efficient/faster?
        logger.warning("Packet doesn't have Raw layer!")
        return False

    return True


def has_tcp_layer(pkt: Packet):
    """Check if packet has TCP layer. Added because check if TCP layer is in packet is used multiple times"""
    if not pkt.haslayer(TCP):
        logger.warning("Packet doesn't have TCP layer!")
        return False
    return True


def has_ipv6_layer(pkt: Packet):
    """Check if packet has IPv6 layer. Added because check if IPv6 layer is in packet is used multiple times"""
    if not pkt.haslayer(IPv6):
        logger.warning("Packet doesn't have IPv6 layer!")
        return False
    return True


def has_v2gtp_layer(pkt: Packet):
    """Check if packet has V2GTP layer."""
    if not has_raw_layer(pkt):
        return False

    # V2GTP uses IPv6 from my understanding of ISO15118-2:2014
    if not has_ipv6_layer(pkt):
        return False

    # TODO: In future check versions of V2GTP protocol, for now it's only version 1
    # V2GTP Header field: Protocol Version
    v2gtp_version = b"\x01"
    # V2GTP Header field: Inverse Protocol Version
    v2gtp_inverse_version = b"\xFE"
    version_bytes = v2gtp_version + v2gtp_inverse_version

    logger.debug("V2GTP version bytes: %s", version_bytes)

    v2gtp_pdu = pkt[Raw].load
    if v2gtp_pdu.startswith(version_bytes):
        return True
    return False


def is_v2gtp_exi_msg(pkt: Packet):
    """Check if payload type in header is V2GTP EXI message."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    # From byte 3 to byte 4 is payload type [2:4] from 2. position to 3. position
    # 4. position is not included, so it's byte 3 and 4
    # Bytes in ISO, number of byte starts from 1, not from 0
    # So byte 3 and 4 is here 2. and 3. position
    payload_type = header[2:4]
    if payload_type == b"\x80\x01":
        return True

    return False


def is_v2gtp_sdp_request(pkt: Packet):
    """Check if payload type in header is V2GTP SDP request."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if payload_type == b"\x90\x00":
        return True

    return False


def is_v2gtp_sdp_response(pkt: Packet):
    """Check if payload type in header is V2GTP SDP response."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if payload_type == b"\x90\x01":
        return True

    return False


def is_v2gtp_manufacturer_use(pkt: Packet):
    """Check if payload type in header is V2GTP Manufacturer Specific Use."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    manufacturer_start = b"\xa0\x00"
    manufacturer_end = b"\xff\xff"
    if manufacturer_start <= payload_type <= manufacturer_end:
        logger.debug("Manufacturer specific use payload type!")
        return True


def is_v2gtp_reserved(pkt: Packet):
    """Check if payload type in header is V2GTP Reserved."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if (
        b"\x00\x00" <= payload_type <= b"\x80\x00"
        or b"\x80\x02" << payload_type <= b"\x8f\xff"
        or b"\x90\x02" << payload_type <= b"\x9f\xff"
    ):
        logger.debug("Reserved payload type!")
        return True

    return False


def check_v2gtp_payload_types(pkt: Packet):
    """Check V2GTP payload type, which is defined in the V2GTP PDU header"""

    if is_v2gtp_exi_msg(pkt):
        payload_type = "exi_message"
        return payload_type
    if is_v2gtp_sdp_request(pkt):
        payload_type = "sdp_request"
        return payload_type
    if is_v2gtp_sdp_response(pkt):
        payload_type = "sdp_response"
        return payload_type
    if is_v2gtp_manufacturer_use(pkt):
        payload_type = "manufacturer_specific_use"
        return payload_type
    if is_v2gtp_reserved(pkt):
        payload_type = "reserved"
        return payload_type

    logger.warning("Unknown payload type!")
    raise ValueError("Unknown payload type!")


def parse_v2gtp_pkt(pkt: Packet):
    """Parse V2GTP packet => Separate the V2GTP header from the payload

    Check if the packet has Raw layer, then check if it's V2GTP packet
    and then separate the V2GTP header from the payload
    """
    logger.debug("Trying to parse packet as V2GTP packet...")

    if not has_v2gtp_layer(pkt):
        return None, None

    header = pkt[Raw].load[:8]
    payload = pkt[Raw].load[8:]

    logger.debug("V2GTP header: %s", header)
    logger.debug("V2GTP payload: %s", payload)
    logger.debug("V2GTP header hex(): %s", header.hex())
    logger.debug("V2GTP payload hex(): %s", payload.hex())

    return header, payload


# For now use this function for decoding V2GTP packet in combination with
# V2GDecoder.jar
# source of V2GDecoder.jar:
def decode_v2gtp_exi_msg(pkt: Packet) -> tuple[bytes, bytes, str]:
    """Decode V2GTP EXI message payload type"""

    # Sending separated payload from previous step to V2GDecoder
    # Important! V2GDecoder needs to be first started, before running this command
    # V2GDecoder will be run as a web server by following command:
    # java -jar V2GDecoder.jar -w

    # TODO: Maybe write my own decoder
    if not is_v2gtp_exi_msg(pkt):
        logger.warning("Packet is not V2GTP EXI message!")
        raise ValueError("Packet is not V2GTP EXI message!")

    header, payload = parse_v2gtp_pkt(pkt)
    # Unnecessary check if None,
    # because it's already checked in is_v2gtp_exi_msg function
    # IDE needs it, because it doesn't know that it's already checked
    # cause hex() method is not defined for None
    if header is None or payload is None:
        logger.warning("Header or Payload is None!")
        raise ValueError("Header or Payload is None!")

    # print("Trying to decode packet as V2GTP EXI message...\n")
    logger.debug("Trying to decode packet as V2GTP EXI message...")

    try:
        response = requests.post(
            "http://localhost:9000",
            headers={"Format": "EXI"},
            data=payload.hex(),
            timeout=10,
        )
        if response.status_code == 200:
            logger.debug("Response from V2GDecoder:\n")
            logger.debug(response.text)
        else:
            logger.warning("Error: %s", response.status_code)
            logger.warning("Error: %s", response.text)
    except requests.exceptions.Timeout:
        logger.error("Timeout! Is V2GDecoder running?")
        exit(1)
        # raise requests.exceptions.Timeout("Timeout! Is V2GDecoder running?")
    except requests.exceptions.ConnectionError:
        logger.error("Connection refused! Is V2GDecoder running?")
        exit(1)
        # raise requests.exceptions.ConnectionError(
        #    "Connection refused! Is V2GDecoder running?"
        # )

    return header, payload, response.text


def decode_v2gtp_sdp_request(pkt: Packet):
    """Decode V2GTP SDP request payload type"""
    # TODO: Add decoding of SDP request / or some interpretation of it
    raise NotImplementedError("Not implemented yet! Exiting...")


def decode_v2gtp_sdp_response(pkt: Packet):
    """Decode V2GTP SDP response payload type"""
    # TODO: Add decoding of SDP response / or some interpretation of it
    raise NotImplementedError("Not implemented yet! Exiting...")


def decode_v2gtp_manufacturer_use(pkt: Packet):
    """Decode V2GTP Manufacturer Specific Use payload type"""
    raise NotImplementedError(
        "Depends on manufacturer docs, so it's not implemented yet! Exiting..."
    )


def decode_v2gtp_reserved(pkt: Packet):
    """Decode V2GTP Reserved payload type"""
    raise NotImplementedError(
        "Reserved payload type by ISO 15118-2:2014, "
        "so it's not implemented yet! Exiting..."
    )


def prn_v2gtp_pkt(pkt: Packet):
    """Methon for printing V2GTP packet as prn function in scapy sniff function

    Method for printing V2GTP packet.
    It will be used as prn function in scapy sniff function.

    Args:
        pkt (Packet): V2GTP packet
    """

    header, payload = parse_v2gtp_pkt(pkt)
    # It means that packet doesn't have v2gtp layer
    if header is None or payload is None:
        logger.debug("Packet doesn't have V2GTP layer!")
        return f"Packet doesn't have V2GTP layer!\n{pkt.show()}"

    return f"V2GTP header: {header.hex()}\nV2GTP payload: {payload.hex()}"


def decode_v2gtp_pkt(pkt, payload_type: str = "auto"):
    """Decode V2GTP packet as given payload type

    Args:
        pkt (Packet): Packet to decode
        payload_type (str, optional): Payload type to decode. Defaults to "auto".

    """
    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        logger.warning(
            "Packet doesn't have Raw layer! So, no decoding is possible!"
        )
        return

    data = pkt[Raw].load
    logger.debug("Packet data: %s\n", data)

    print()
    print("Trying to decode following raw data as V2GTP packet:")
    linehexdump(data)
    logger.debug("Packet data hex(): %s", data.hex())

    print(100 * "-")
    print(f"V2GTP header: {header.hex()}")
    print(f"V2GTP payload: {payload.hex()}")
    print(100 * "-")

    if payload_type == "auto":
        payload_type = check_v2gtp_payload_types(pkt)
        logger.debug("Payload type: %s", payload_type)

    # Otherwise Pylance will complain about variable is possibly unbound
    decoded = None
    match (payload_type):
        case "exi_message":
            _, _, decoded = decode_v2gtp_exi_msg(pkt)
        case "sdp_request":
            decode_v2gtp_sdp_request(pkt)
        case "sdp_response":
            decode_v2gtp_sdp_request(pkt)
        case "manufacturer_specific_use":
            decode_v2gtp_manufacturer_use(pkt)
        case "reserved":
            decode_v2gtp_reserved(pkt)
        case _:
            logger.warning("Unknown payload type!")
            raise ValueError("Unknown payload type!")

    return decoded


def decode_v2gtp_pkt_from_file(file: str, packet_num: int = 0):
    """Decode V2GTP packet from pcap file"""

    if os.path.isfile(file) is False:
        logger.error("File doesn't exist!")
        exit(1)

    packets = rdpcap(file)
    if 0 <= packet_num < len(packets):
        pkt = packets[packet_num]
    else:
        logger.error("Invalid packet number!")
        exit(1)

    decode_v2gtp_pkt(pkt)


# TODO: Resolve printing of decoded V2GTP packet based on print_flag
def decode_v2gtp_packets(packets, print_flag: bool = False):
    """Decode V2GTP packets"""
    for pkt in packets:
        pkt_num = packets.index(pkt) + 1
        logger.debug(
            "Trying to decode %s. packet(Wireshark numbering style) "
            "as V2GTP packet",
            pkt_num,
        )
        decode_v2gtp_pkt(pkt)
