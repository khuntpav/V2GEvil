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
