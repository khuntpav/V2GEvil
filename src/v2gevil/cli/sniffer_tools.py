"""Sniffer tools.

Calling logic from sniffer module.
"""
import rich_click as click
from ..sniffer import sniffer


@click.group()
def sniffer_tools():
    """Sniffer tool related commands"""


@sniffer_tools.command(name="sniff")
@click.option(
    "--live/--pcap",
    "-l",
    is_flag=True,
    default=False,
    show_default=True,
    help="Sniff live on interface / analyze pcap file",
)
@click.option(
    "--interface",
    "-i",
    default="eth_car",
    show_default=True,
    help="Interface to sniff on",
)
@click.option(
    "--file",
    "-f",
    default="./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng",
    show_default=True,
    help="File to analyze",
)
@click.option(
    "--ipv6/--no-only-ipv6",
    "-6",
    is_flag=True,
    default=True,
    show_default=True,
    help="Sniff only IPv6 packets",
)
@click.option(
    "--v2gtp/--no-only-v2gtp",
    "v2gtp_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Sniff only V2GTP packets",
)
@click.option(
    "--decode/--no-decode",
    "decode_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Try to decode packet as V2GTP packet.",
)
def sniff(
    live: bool,
    interface: str,
    file: str,
    ipv6: bool,
    v2gtp_flag: bool,
    decode_flag: bool,
):
    """Call method for Sniffing packets live on interface or analyze pcap file"""

    sniffer.sniff(
        live=live,
        interface=interface,
        file=file,
        ipv6=ipv6,
        v2gtp_flag=v2gtp_flag,
        decode_flag=decode_flag,
    )


@sniffer_tools.command(name="inspect")
@click.option(
    "--file",
    "-f",
    default="./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng",
    show_default=True,
    help="File to analyze",
)
@click.option(
    "--packet-num",
    "-p",
    default=0,
    show_default=True,
    help="Packet number to inspect. Start from index=0. "
    "If you want to inspect packet with number from Wireshark, "
    "first subtract 1. If you want to inspect packet with number "
    "from sniff command, then leave it as is.",
)
@click.option(
    "--show",
    "-s",
    default="all",
    show_default=True,
    help="Show only given part of packet. "
    "Possible values: all, raw, ipv6, tcp.",
)
@click.option(
    "--decode",
    "-d",
    "decode_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Try to decode packet as V2GTP packet. "
    "Mandatory flag for decode is show=raw."
    "Only if raw layer is present, otherwise it will fail.",
)
def inspect(
    file: str,
    packet_num: int,
    show: str,
    decode_flag: bool,
):
    # TODO: Check if file exists
    """Method for inspecting one packet with given number of the packet"""
    sniffer.inspect(
        file=file, packet_num=packet_num, show=show, decode_flag=decode_flag
    )
