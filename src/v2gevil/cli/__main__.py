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

"""Main entry point for the CLI

This module is as entry point for the CLI.
It will call other modules and their commands.
"""
# TODO: Some option called auto, that will automatically
#       load modules for automatic exploitation/evaluation

import logging
import random
from art import text2art
import rich.traceback
import rich_click as click
from rich.logging import RichHandler
from .v2gtp_tools import v2gtp_tools
from .sniffer_tools import sniffer_tools
from .sender_tools import sender_tools
from .station_tools import station_tools
from .car_tools import car_tools
from .console import console
from .message_tools import message_tools
from .modules_tools import modules_tools

logger = logging.getLogger(__name__)
fonts = [
    "epic",
    "doh",
    "diamond",
    "coinstak",
    "larry3d",
    "3-d",
    "3d_diagonal",
    "poison",
    "impossible",
    "colossal",
    "varsity",
    "arrows",
    "doom",
]


@click.group()
@click.version_option(message="%(version)s", package_name="v2gevil")
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable/Disable debug mode, default: Disabled",
)
def main(debug: bool):
    """Main entry point for the CLI"""

    rich.traceback.install(
        show_locals=debug, suppress=[click], console=console
    )
    logging.basicConfig(
        # Choose one of the following formats:
        # format="%(name)s: %(message)s",
        # handlers=[RichHandler(show_time=True, console=console)],
        format="%(asctime)s %(name)s: %(message)s",
        handlers=[RichHandler(show_time=False, console=console)],
        level=(logging.WARNING if not debug else logging.DEBUG),
    )
    if debug:
        click.secho("DEBUG MODE is ON", fg="green")
    logger.debug("Main entry point for the CLI")


# Print banner
# console.print(
#   text2art("V2GEvil", font="poison"),
#    style="red bold",
#    highlight=False,  # False => Delete highlights from some characters
#    # For some fonts looks better with False
# )
main.add_command(sniffer_tools)
main.add_command(v2gtp_tools)
main.add_command(sender_tools)
main.add_command(station_tools)
main.add_command(car_tools)
main.add_command(message_tools)
main.add_command(modules_tools)
