"""Sender tools.

Calling logic from sender module.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

# For type checking, only true in IDEs and tools for type checking.
# It will not be used in runtime. Important to use: from __future__ import annotations
if TYPE_CHECKING:
    from scapy.packet import Packet
import rich_click as click



@click.group()
def sender_tools():
    """
    Sender tools
    """
    pass

