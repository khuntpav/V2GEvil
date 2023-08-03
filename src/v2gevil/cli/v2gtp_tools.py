"""V2GTP tools.

Calling logic from V2GTP module.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import rich_click as click
from ..v2gtp import v2gtp

# For type checking, only true in IDEs and tools for type checking.
# It will not be used in runtime. Important to use: from __future__ import annotations
if TYPE_CHECKING:
    from scapy.packet import Packet


@click.group()
def v2gtp_tools():
    """Tool related commands"""
    click.echo("V2GTP tools loaded successfully!")


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
    v2gtp.extract_v2gtp_pkts(file=file)


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
    name="pkt_num",
    default=0,
    show_default=True,
    help="Packet number (from Wireshark, start from index=1) to decode",
)
def decode(file: str, pkt_num: int):
    """Decode V2GTP packet from pcap file"""
    v2gtp.decode_v2gtp_pkt_from_file(
        file=file,
        packet_num=pkt_num,
    )
