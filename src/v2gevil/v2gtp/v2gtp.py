from __future__ import annotations

import platform
print(platform.python_version())

import logging
# For type checking, only true in IDEs and tools for type checking.
# It will not be used in runtime. Important to use: from __future__ import annotations 
from typing import TYPE_CHECKING, Union, overload

import rich_click as click

if TYPE_CHECKING:
    from scapy.packet import Packet 

"""Module for V2GTP related commands.
Here is the implementation of the V2GTP protocol,
which is used for communication between EV and EVSE. 
The implementation is based on ISO 15118-2:2014."""

logger = logging.getLogger(__name__)


@click.group()
def v2gtp_tools():
    """Tool related commands"""
    click.echo("V2GTP tools loaded successfully!")

@v2gtp_tools.command(name="extract")
@click.option("--file", "-p",
              default='./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng', 
              show_default=True,
              help="File to analyze")
# Important: The communication between EV and EVSE is also include other IPv6 packets, not only V2GTP packets
# So if we want whole communication, we need to sniff all IPv6 packets and then check them
# There are ICMPv6 packets, which are used for Neighbor Discovery Protocol (NDP)
# NDP is used for IPv6 address autoconfiguration and for IPv6 router discovery
# NDP is also used for Duplicate Address Detection (DAD)
# There are also UDP packets for SECC Discovery Protocol (SDP)
# This function will extract only V2GTP packets from pcap file not whole IPv6 communication
# To extract whole IPv6 communication, use function "analyze" from sniffer module
def extract_v2gtp_pkts(file):
    """Extract V2GTP packets from pcap file"""
    #from scapy.all import packet
    from scapy.packet import Raw
    from scapy.layers.inet import TCP, IP, UDP
    from scapy.utils import linehexdump
    
    # For testing purposes only
    from scapy.all import rdpcap
    packets = rdpcap(file)
    
    # Protocol Version
    v2gtp_version = b'\x01'
    # XOR in python cannot be applied to bytes, write function for it or use hardcoded values
    #v2gtp_inverse_version = bytes(v2gtp_version ^ b'\xFF')
    # V2GTP Header field: Inverse Protocol Version
    v2gtp_inverse_version = b'\xFE'
    version_bytes = v2gtp_version + v2gtp_inverse_version
    logger.debug("V2GTP version bytes: %s", version_bytes)

    # Testing packets is following:
    # 1. V2GTP SECC discovery request: packet_num=115,116
    # 2. V2GTP SECC discovery response: packet_num=121,122
    # 3. V2GTP V2GEXI request - supportedAppProtocolReq: packet_num=133
    # 4. V2GTP V2GEXI response - supportedAppProtocolRes: packet_num=144
    # 5. V2GTP V2GEXI(ISO1 in Wireshark) request - sessionSetupReq: packet_num=156
    # Number of packet is from Wireshark start from 1, but in scapy it starts from 0, so we need to add 1
    for pkt in packets:
        if Raw in pkt:
            payload_bytes = pkt[Raw].load
            if payload_bytes.startswith(version_bytes):
                pkt_num = packets.index(pkt) + 1 # +1 because index starts from 0, so make it same as in Wireshark
                #print("Packet payload: %s" % payload_bytes)
                #print("Packet show: %s", pkt.show())
                # TODO: Not sure if it's needed to drop retransmission packets and DUP ACK packets
                # Retrassmision detection for ex.: packet_num=594
                # TCP DUP ACK detection for ex.: packet_num=598
                # TODO: Detect if next packet has same sequence number as packet before
                # TODO: In this case, it's retransmission packet or DUP ACK packet - I hope so

                print("Packet number: %s is V2GTP packet", pkt_num)

    # TODO: Format output like src, dst, payload, etc. usefull for further analysis  

def has_raw_layer(pkt: Packet):
    """Check if packet has Raw layer. Added because check if Raw layer is in packet is used multiple times"""
    from scapy.packet import Raw

    if not pkt.haslayer(Raw): # or not Raw in pkt[Raw] what is more efficient/faster?
        logger.warning("Packet doesn't have Raw layer!")
        return False

    return True

def has_tcp_layer(pkt: Packet):
    """Check if packet has TCP layer. Added because check if TCP layer is in packet is used multiple times"""
    from scapy.layers.inet import TCP
    
    if not pkt.haslayer(TCP):
        logger.warning("Packet doesn't have TCP layer!")
        return False
    return True

def has_ipv6_layer(pkt: Packet):
    """Check if packet has IPv6 layer. Added because check if IPv6 layer is in packet is used multiple times"""
    from scapy.layers.inet6 import IPv6
    
    if not pkt.haslayer(IPv6):
        logger.warning("Packet doesn't have IPv6 layer!")
        return False
    return True

def parse_v2gtp_pkt(pkt: Packet):
    """Parse V2GTP packet => Separate the V2GTP header from the payload"""
    from scapy.packet import Raw

    if not has_raw_layer(pkt):
        return None, None
    
    header = pkt[Raw].load[:8]
    payload = pkt[Raw].load[8:]

    #print("V2GTP header: %s", header)
    #print("V2GTP payload: %s", payload)
    logger.debug("V2GTP header: %s", header)
    logger.debug("V2GTP payload: %s", payload)
    logger.debug("V2GTP header hex(): %s", header.hex())
    logger.debug("V2GTP payload hex(): %s", payload.hex())

    return header, payload

#@overload
#@v2gtp_tools.command(name="decode")
#@click.option("--packet-num", "-p",
#              default=0,
#              show_default=True,
#              help="Packet number to decode")
#def decode_v2gtp_pkt(packets, packet_num: int = 0,):
#    """Decode V2GTP packet"""
#    logger.debug("Trying to decode packet as V2GTP packet with packet number: %s", packet_num)
#    decode_v2gtp_pkt(packets[packet_num])


# For now it will use V2GDecoder
# V2GDecoder has to run as a web server
# V2GDecoder source: https://github.com/FlUxIuS/V2Gdecoder
def decode_v2gtp_pkt(pkt, packet_num: int = 0):
    """Decode V2GTP packet"""
    import requests
    from scapy.packet import Raw
    from scapy.utils import linehexdump

    #           Testing only        #
    # ----------------------------- #
    debug = False
    if debug:
        from scapy.all import rdpcap
        packets = rdpcap('./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng')
        packet_num = 133
        pkt = packets[packet_num]
    # ----------------------------- #
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
    
    logger.debug(f'Packet data: {data}')
    logger.debug("Packet hex(): %s", data.hex())
    logger.debug("Packet header: %s", header.hex())
    logger.debug("Packet payload: %s", payload.hex())

    # Sending separated payload from previous step to V2GDecoder
    # Important! V2GDecoder needs to be first started, before running this command
    # V2GDecoder will be run as a web server by following command:
    # java -jar V2GDecoder.jar -w



    # TODO: Maybe write my own decoder
    logger.debug("Trying to decode packet as V2GTP packet...")
    r = requests.post('http://localhost:9000', headers={"Format":"EXI"}, data=payload.hex())
    if r.status_code == 200:
        print("Response from V2GDecoder:")
        print(r.text)
    else:
        logger.warning("Error: %s", r.status_code)
        logger.warning("Error: %s", r.text)


def decode_v2gtp_packets(packets):
    """Decode V2GTP packets"""
    for pkt in packets:
        pkt_num = packets.index(pkt) + 1
        logger.debug("Trying to decode packet as V2GTP packet with packet number: %s", pkt_num)
        decode_v2gtp_pkt(pkt)
