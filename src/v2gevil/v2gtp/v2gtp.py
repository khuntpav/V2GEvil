import logging
import rich_click as click
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
    # V2GTP Header field: Inverse Protocol Version
    #v2gtp_inverse_version = bytes(v2gtp_version ^ b'\xFF')
    v2gtp_inverse_version = b'\xFE'
    version_bytes = v2gtp_version + v2gtp_inverse_version

    # Testing packets are following:
    # 1. V2GTP SECC discovery request: packet_num=115,116
    # 2. V2GTP SECC discovery response: packet_num=121,122
    # 3. V2GTP V2GEXI request - supportedAppProtocolReq: packet_num=133
    # 4. V2GTP V2GEXI response - supportedAppProtocolRes: packet_num=144
    # 5. V2GTP V2GEXI(ISO1 in Wireshark) request - sessionSetupReq: packet_num=156

    #print(v2gtp_version + v2gtp_inverse_version)
    #print(packets[133][Raw].load)

    for pkt in packets:
        if Raw in pkt:
            payload_bytes = pkt[Raw].load
            if payload_bytes.startswith(version_bytes):
                pkt_index = packets.index(pkt) + 1 # +1 because index starts from 0, so make it same as in Wireshark
                #print("Packet payload: %s" % payload_bytes)
                #print("Packet show: %s", pkt.show())
                # TODO: Not sure if it's needed to drop retransmission packets and DUP ACK packets
                # Retrassmision detection for ex.: packet_num=594
                # TCP DUP ACK detection for ex.: packet_num=598
                # TODO: Detect if next packet has same sequence number as packet before
                # TODO: In this case, it's retransmission packet or DUP ACK packet - I hope so

                print("Packet number: %s is V2GTP packet", pkt_index)

    # TODO: Format output like src, dst, payload, etc. usefull for further analysis  
        
   
    
  


    exit(0)

    debug = False
    if debug == True:      
        payload_bytes = packets[133][Raw].load
        print("Packet TCP using TCP.show()")
        packets[133][TCP].show()
        print("Packet PDU using Raw.show()")
        packets[133][Raw].show()

    #for pkt in packets:
    #    if Raw in pkt:
    #        if 
