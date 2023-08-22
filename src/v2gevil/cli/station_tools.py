"""Station related tools.

Calling logic from car module.
"""
import rich_click as click
from ..station import station
from ..station import station_scapy


@click.group()
def station_tools():
    """Station tool related commands"""


@station_tools.command(name="start")
@click.option(
    "--interface",
    "-i",
    default="eth_station",
    show_default=True,
    help="Interface to run station on",
)
@click.option(
    "--async/--manual",
    "async_flag",
    default=True,
    show_default=True,
    help="Run station in async mode or manual mode",
)
def start_station(interface: str, async_flag: bool):
    """Start station."""
    if async_flag:
        station.start_async(interface=interface)
    else:
        station.start(interface=interface)
