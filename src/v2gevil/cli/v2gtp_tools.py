"""V2GTP tools.

Calling logic from V2GTP module.
"""
# from __future__ import annotations
# from typing import TYPE_CHECKING
import rich_click as click
from ..v2gtp import v2gtp

# For type checking, only true in IDEs and tools for type checking.
# It will not be used in runtime. Important to use: from __future__ import annotations
# if TYPE_CHECKING:
#    from scapy.packet import Packet


@click.group()
def v2gtp_tools():
    """V2GTP tool related commands"""


@v2gtp_tools.command(name="extract")
@click.option(
    "--file",
    "-p",
    default="./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng",
    show_default=True,
    help="File to analyze",
)
def extract(file: str):
    """Extract V2GTP packets from pcap file"""
    v2gtp.extract_v2gtp_pkts_from_file(file=file)


@v2gtp_tools.command(name="decode")
@click.option(
    "--file",
    "-f",
    default="./examples/pcap_files/Boards_connected_IPv6_and_localhost.pcapng",
    show_default=True,
    help="File from which to decode V2GTP packet",
)
@click.option(
    "--packet-num",
    "-p",
    default=0,
    show_default=True,
    help="Packet number to decode. Start from index=0. "
    "If you want to inspect packet with number from Wireshark, "
    "first subtract 1. If you want to inspect packet with number "
    "from sniff command, then leave it as is.",
)
def decode(file: str, packet_num: int):
    """Decode V2GTP packet from pcap file"""
    v2gtp.decode_v2gtp_pkt_from_file(
        file=file,
        packet_num=packet_num,
    )
