# Desc: Main entry point for the CLI
# TODO: Some option called auto, that will automatically
#       load modules for automatic exploitation/evaluation

import logging
import rich.traceback
import rich_click as click
from rich.logging import RichHandler
from ..sniffer import sniffer
from ..v2gtp import v2gtp
from .console import console

logger = logging.getLogger(__name__)

@click.group()
@click.version_option(message="%(version)s", package_name="v2gevil")
@click.option("--debug/--no-debug", default=False, help="Enable/Disable debug mode, default: Disabled")
def main(debug: bool):
    """Main entry point for the CLI"""

    rich.traceback.install(show_locals=debug, suppress=[click], console=console)
    logging.basicConfig(
        # Choose one of the following formats:
        #format="%(name)s: %(message)s",
        #handlers=[RichHandler(show_time=True, console=console)],
        format="%(asctime)s %(name)s: %(message)s",
        handlers=[RichHandler(show_time=False, console=console)],
        level=(logging.WARNING if not debug else logging.DEBUG),
    )

    logger.debug("Main entry point for the CLI")

@main.command(name="banner")
def banner():
    """Prints a basic banner from __main__.py"""
    print("Hello, from banner!")

main.add_command(v2gtp.v2gtp_tools)
main.add_command(sniffer.sniffer_tools)
