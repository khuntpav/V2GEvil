"""Module for V2GTP related commands.

Here is the implementation of the V2GTP protocol,
which is used for communication between EV and EVSE. 
The implementation is based on ISO 15118-2:2014.
"""
import logging
import requests

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import linehexdump
from scapy.all import rdpcap


logger = logging.getLogger(__name__)


# Important: The communication between EV and EVSE is also include other IPv6 packets, not only V2GTP packets
# So if we want whole communication, we need to sniff all IPv6 packets and then check them
# There are ICMPv6 packets, which are used for Neighbor Discovery Protocol (NDP)
# NDP is used for IPv6 address autoconfiguration and for IPv6 router discovery
# NDP is also used for Duplicate Address Detection (DAD)
# There are also UDP packets for SECC Discovery Protocol (SDP)
# This function will extract only V2GTP packets from pcap file not whole IPv6 communication
# To extract whole IPv6 communication, use function "analyze" from sniffer module
# TODO: Add exctract_v2gtp_pkts_from_file function
# Replace extract_v2gtp_pkts function with extract_v2gtp_pkts_from_file function
# Add extract_v2gtp_pkts function, which will take packets as argument
def extract_v2gtp_pkts_from_file(file: str):
    """Extract V2GTP packets from pcap file"""
    extract_v2gtp_pkts(rdpcap(file))


def extract_v2gtp_pkts(packets):
    """Extract V2GTP packets"""

    # Testing packets is following:
    # 1. V2GTP SECC discovery request: packet_num=115,116
    # 2. V2GTP SECC discovery response: packet_num=121,122
    # 3. V2GTP V2GEXI request - supportedAppProtocolReq: packet_num=133
    # 4. V2GTP V2GEXI response - supportedAppProtocolRes: packet_num=144
    # 5. V2GTP V2GEXI(ISO1 in Wireshark) request - sessionSetupReq: packet_num=156
    # Number of packet is from Wireshark start from 1, but in scapy it starts from 0, so we need to add 1
    for pkt in packets:
        if has_v2gtp_layer(pkt):
            pkt_num = packets.index(pkt) + 1
            # +1 because index starts from 0, so make it same as in Wireshark
            # print("Packet payload: %s" % payload_bytes)
            # print("Packet show: %s", pkt.show())
            # TODO: Not sure if it's needed to drop retransmission packets and DUP ACK packets
            # Retrassmision detection for ex.: packet_num=594
            # TCP DUP ACK detection for ex.: packet_num=598
            # TODO: Detect if next packet has same sequence number as packet before
            # TODO: In this case, it's retransmission packet or DUP ACK packet - I hope so

            print("Packet number: %s is V2GTP packet", pkt_num)

    # TODO: Format output like src, dst, payload, etc. usefull for further analysis


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

    # XOR in python cannot be applied to bytes, write function for it or use hardcoded values
    # v2gtp_inverse_version = bytes(v2gtp_version ^ b'\xFF')
    # XOR in python cannot be applied to bytes, write function for it or use hardcoded values
    # v2gtp_inverse_version = bytes(v2gtp_version ^ b'\xFF')

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


payload_type_enum = {
    "sdp_request",
    "sdp_response",
    "exi_message",
    "reserved",
    "manufacturer_use",
}


def v2gtp_payload_type(pkt: Packet):
    """Check V2GTP payload type, which is defined in the V2GTP PDU header"""
    # TODO: Add check using calling is_v2gtp_exi_msg function
    # Will return which payload type is in the packet from enum

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

    logger.debug("Unknown payload type!")
    return None


def parse_v2gtp_pkt(pkt: Packet):
    """Parse V2GTP packet => Separate the V2GTP header from the payload

    Check if the packet has Raw layer, then check if it's V2GTP packet
    and then separate the V2GTP header from the payload
    """
    if not has_v2gtp_layer(pkt):
        return None, None

    header = pkt[Raw].load[:8]
    payload = pkt[Raw].load[8:]

    # print("V2GTP header: %s", header)
    # print("V2GTP payload: %s", payload)
    logger.debug("V2GTP header: %s", header)
    logger.debug("V2GTP payload: %s", payload)
    logger.debug("V2GTP header hex(): %s", header.hex())
    logger.debug("V2GTP payload hex(): %s", payload.hex())

    return header, payload


# For now it will use V2GDecoder
# V2GDecoder has to run as a web server
# V2GDecoder source: https://github.com/FlUxIuS/V2Gdecoder
# TODO: Change name of this function because it's decoding only EXI messages
def decode_v2gtp_pkt(pkt):
    """Decode V2GTP packet"""

    if not has_raw_layer(pkt):
        return

    data = pkt[Raw].load

    print("Parsing following raw data as V2GTP packet:")
    linehexdump(data)

    # Calling parse_v2gtp_pkt function to separate V2GTP header from payload
    logger.debug("Trying to parse packet as V2GTP packet...")
    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return

    logger.debug(f"Packet data: {data}")
    logger.debug("Packet hex(): %s", data.hex())
    logger.debug("Packet header: %s", header.hex())
    logger.debug("Packet payload: %s", payload.hex())

    # Sending separated payload from previous step to V2GDecoder
    # Important! V2GDecoder needs to be first started, before running this command
    # V2GDecoder will be run as a web server by following command:
    # java -jar V2GDecoder.jar -w

    # TODO: Try/catch for check if V2GDecoder is running

    # TODO: Maybe write my own decoder
    logger.debug("Trying to decode packet as V2GTP packet...")
    # TODO: add timeout for request
    r = requests.post(
        "http://localhost:9000", headers={"Format": "EXI"}, data=payload.hex()
    )
    if r.status_code == 200:
        print("Response from V2GDecoder:")
        print(r.text)
    else:
        logger.warning("Error: %s", r.status_code)
        logger.warning("Error: %s", r.text)


def decode_v2gtp_pkt_from_file(file: str, packet_num: int = 0):
    """Decode V2GTP packet from pcap file"""
    # TODO: Add check if file exists
    packets = rdpcap(file)
    if 0 <= packet_num < len(packets):
        pkt = packets[packet_num]
    else:
        logger.error("Invalid packet number!")
        exit(1)
    # Testing only #
    # ---------------- #
    debug = True
    if debug is True:
        packet_num = 133
    # ---------------- #

    decode_v2gtp_pkt(pkt)


def decode_v2gtp_packets(packets):
    """Decode V2GTP packets"""
    for pkt in packets:
        pkt_num = packets.index(pkt) + 1
        logger.debug(
            "Trying to decode %s. packet(Wireshark numbering style) "
            "as V2GTP packet",
            pkt_num,
        )
        decode_v2gtp_pkt(pkt)
