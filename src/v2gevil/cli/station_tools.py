"""Station related tools.

Calling logic from car module.
"""
import rich_click as click
from ..station import station


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
    "--mode",
    "-m",
    default="normal",
    show_default=True,
    help="Mode to run station in. Options: normal, ...TODO",
)
def start_station(interface: str, mode: str):
    """Start station."""
    station.start()
