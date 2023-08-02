import logging
# This import really slows down the CLI, so use only some features from that later
# Not importing here, because it slows down the CLI. Importing in functions instead.
# import scapy.all as scapy
import rich_click as click

logger = logging.getLogger(__name__)

@click.group()
def sniffer_tools():
    """Tool related commands"""
    click.echo("Sniffer tools loaded successfully!")

@sniffer_tools.command(name="banner")
def banner():
    """Prints a hello message. Testing purposes only. Test if module is loaded correctly."""
    print("Hello, from sniffer module!")
    logger.debug("Hello, from sniffer module!")

@sniffer_tools.command(name="sniff")
#@click.option("--mode", "-m",
#              type=(str, str),
#              default=(None, None),
#              show_default=True,
#              help="Mode to sniff in. Two options: analyze from pcap file"\
#                "nor sniff live on interface. "\
#                "First argument: pcap/live. "\
#                "Second argument: [file_name]/[interface_name]")
@click.option("--live", "-l",
              is_flag=True,
              default=False,
              show_default=True,
              help="Sniff live on interface")
@click.option("--pcap", "-p",
              is_flag=True,
              default=False,
              show_default=True,
              help="Analyze pcap file")
# TODO: Maybe change it to use like: --live $name_of_interface or --pcap $name_of_file and use it instead of flags
@click.option("--interface", "-i",
              default='eth_car',
              show_default=True,
              help="Interface to sniff on")
@click.option("--file", "-f",
              default='./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng', 
              show_default=True,
              help="File to analyze")
@click.option("--ipv6/--no-only-ipv6", "-6",
              is_flag=True,
              default=True,
              show_default=True,
              help="Sniff only IPv6 packets")
#@click.option("--IPversion",
#              # Used v2gevil
#              default=6,
#              # Used v2gevil --ipversion
#              flag_value="both",
#              show_default=True,
#              help="Sniff only given IP versions packets")
# I think there is no need to use ipv4, beacause V2G uses IPv6, so we can sniff both or only IPv6
# TODO: Still thinking about options:
#   1. --live --interface $name_of_interface
#   2. --pcap --file $name_of_file
# or maybe:
#   1. --live $name_of_interface
#   2. --pcap $name_of_file
# or maybe:
#   1. --online/--offline $name_of_interface/$name_of_file
# or maybe:
#  1. --only-ipv6/--only-ipv4
# or maybe:
#   the one with mode and tuple
#   def sniff(mode: (str,str)): # Use this in case of tuple for mode
def sniff(live: bool, pcap: bool, interface: str, file: str, ipv6: bool):
    """Sniff packets live"""
    print("Sniffing packets...")
    logger.debug('Sniffing packets')

    if live:
        live_sniff(interface, ipv6)
    elif pcap:
        analyze(file, ipv6)
    else:
        print("Invalid mode!")

    #if mode[0] == "pcap":
    #    file = mode[1]
    #    analyze(file)
    #    print("PCAP sniffing not implemented yet!")

    #elif mode[0] == "live":
    #    interface = mode[1]
    #    logger.debug('Sniffing packets on interface %s', interface)
    #    print("Sniffing packets on interface ... %s", interface)
    #    exit(1)z

#@sniffer_tools.command(name="analyze")
#@click.option("--file", "-f", default=None, show_default=True, help="File to analyze")
def analyze(file: str, ipv6: bool, print_summary: bool = True):
    """Analyze packets from pcap file"""
    # Importing here, because it slows down the CLI
    #import scapy.all as scapy OR do it like this:
    from scapy.all import rdpcap
    from scapy.all import IPv6
    from scapy.all import IP
    print("Analyzing packets from file %s", file)
    logger.debug('Analyzing packets')

    packets = rdpcap(file)
    # Only IPv6 packets
    if ipv6:
        filtered_packets = packets.filter(lambda pkt: pkt[IPv6] if IPv6 in pkt else None)
    # Both IPv4 and IPv6 packets
    else:
        # TODO: Maybe change it to use like: --ipv4/--ipv6 
        # filtered_packets = packets.filter(lambda pkt: pkt[scapy.IP] if scapy.IP in pkt else None)
        filtered_packets = packets

    if print_summary:
        filtered_packets.nsummary()
    else:
        return filtered_packets

# TODO: I have to find a way how to run poetry as root, because it needs root to sniff packets on interface
def live_sniff(interface: str, ipv6: bool):
    """Sniff packets live on interface"""
    # Importing here, because it slows down the CLI
    import scapy.all as scapy
    print("Sniffing packets live on interface %s", interface)
    logger.debug('Sniffing packets live on interface %s', interface)
    # Only IPv6 packets
    if ipv6:
        scapy.sniff(iface=interface, filter="ip6")
    # Both IPv4 and IPv6 packets
    else:
        scapy.sniff(iface=interface, filter="ip")

@sniffer_tools.command(name="inspect")
@click.option("--file", "-f",
              default='./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng',
              show_default=True,
              help="File to analyze")
@click.option("--ipv6/--no-only-ipv6", "-6",
              default=True,
              show_default=True,
              help="Sniff only IPv6 packets")
@click.option("--packet-num", "-p",
              default=0,
              show_default=True,
              help="Packet number to inspect")
@click.option("--show", "-s",
              default="all",
              show_default=True,
              help="Show only given part of packet")
def inspect(file: str, ipv6: bool, packet_num: int, show: str):
    """Inspect packet"""
    from scapy.packet import Raw # Used for PDU of packet
    from scapy.utils import linehexdump
    from scapy.layers.inet import TCP
    from scapy.layers.inet6 import IPv6
    packets = analyze(file, ipv6, print_summary=False)
    print("Inspecting packet number %s, using packet.show()", packet_num)
    if packet_num < len(packets) and packet_num >= 0:
        pkt = packets[packet_num]
    else:
        print("Invalid packet number!")
        exit(1)

    if show == "all":
        pkt.show()
        #pkt.show2()
    elif show == "raw":
        if Raw in pkt:
            pkt[Raw].show()
            print(pkt[Raw].load)
            linehexdump(pkt[Raw].load)
            print(pkt[Raw].fields)

    elif show == "ipv6":
        # Maybe change to if pkt.haslayer(IPv6): Don't know what is faster
        if IPv6 in pkt:
            pkt[IPv6].show()
            print(pkt[IPv6].fields)
    if show == "tcp":
        if TCP in pkt:
            pkt[TCP].show()
    
    # Testing packets are following:
    # 1. V2GTP SECC discovery request: packet_num=115,116
    # 2. V2GTP SECC discovery response: packet_num=121,122
    # 3. V2GTP V2GEXI request - supportedAppProtocolReq: packet_num=133
    # 4. V2GTP V2GEXI response - supportedAppProtocolRes: packet_num=144
    # 5. V2GTP V2GEXI(ISO1 in Wireshark) request - sessionSetupReq: packet_num=156

    # TODO: Maybe interactive mode? Like:
    # 1. Show packet
    # 2. Show packet summary
    # 3. Show packet layers
    # 4. Show packet layers summary
    # 5. Show packet layers fields
    # 6. Show packet layers fields summary
    # 7. Show packet layers fields values
    # 8. Show packet layers fields values summary
    # OR wait for user input and show only what user wants to see
    # OR maybe use loop and every time wait for packet number to inspect