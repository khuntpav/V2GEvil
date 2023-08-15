"""Car related tools.

Calling logic from car module.
"""
import rich_click as click
from ..car import car


@click.group()
def car_tools():
    """Car tool related commands"""


@car_tools.command(name="start")
@click.option(
    "--interface",
    "-i",
    default="eth_car",
    show_default=True,
    help="Interface to run car on",
)
@click.option(
    "--mode",
    "-m",
    default="normal",
    show_default=True,
    help="Mode to run car in. Options: normal, ...TODO",
)
def start_car(interface: str = "eth_car", mode: str = "normal"):
    """Start car."""
    car.start(interface=interface)
