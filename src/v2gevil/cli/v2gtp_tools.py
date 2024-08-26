"""
V2GEvil - Tool for testing and evaluation of V2G communication.
Copyright (C) 2024 Pavel Khunt

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
"""

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
    help="File from which to extract V2GTP packets",
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
    "-pn",
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
