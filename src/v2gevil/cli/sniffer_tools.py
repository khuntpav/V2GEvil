"""Sniffer tools.

Calling logic from sniffer module.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

# For type checking, only true in IDEs and tools for type checking.
# It will not be used in runtime. Important to use: from __future__ import annotations
if TYPE_CHECKING:
    from scapy.packet import Packet
import rich_click as click
from ..sniffer import sniffer


@click.group()
def sniffer_tools():
    """Tool related commands"""
    pass


@sniffer_tools.command(name="sniff")
@click.option(
    "--live",
    "-l",
    is_flag=True,
    default=False,
    show_default=True,
    help="Sniff live on interface",
)
@click.option(
    "--pcap",
    "-p",
    is_flag=True,
    default=False,
    show_default=True,
    help="Analyze pcap file",
)
# TODO: Maybe change it to use like: --live $name_of_interface or --pcap $name_of_file and use it instead of flags
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
    name="v2gtp_flag",
    is_flag=True,
    default=True,
    show_default=True,
    help="Sniff only V2GTP packets",
)
def sniff(
    live: bool,
    pcap: bool,
    interface: str,
    file: str,
    ipv6: bool,
    v2gtp_flag: bool,
):
    """Call method for Sniffing packets live on interface or analyze pcap file"""
    sniffer.sniff(
        live=live,
        pcap=pcap,
        interface=interface,
        file=file,
        ipv6=ipv6,
        v2gtp_flag=v2gtp_flag,
    )


@sniffer_tools.command(name="inspect")
@click.option(
    "--file",
    "-f",
    default="./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng",
    show_default=True,
    name="file",
    help="File to analyze",
)
@click.option(
    "--ipv6/--no-only-ipv6",
    "-6",
    default=True,
    show_default=True,
    help="Sniff only IPv6 packets",
)
@click.option(
    "--packet-num",
    "-p",
    default=0,
    show_default=True,
    help="Packet number to inspect",
)
@click.option(
    "--show",
    "-s",
    default="all",
    show_default=True,
    help="Show only given part of packet",
)
@click.option(
    "--decode",
    "-d",
    is_flag=True,
    default=False,
    show_default=True,
    help="Try to decode packet as V2GTP packet."
    "Only if raw layer is present, otherwise it will fail.",
)
def inspect(
    file: str,
    ipv6: bool,
    packet_num: int,
    show: str,
    decode: bool,
):
    """Method for inspecting one packet with given number of the packet"""
    sniffer.inspect(
        file=file, ipv6=ipv6, packet_num=packet_num, show=show, decode=decode
    )
