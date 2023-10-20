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
    "--async/--manual",
    "async_flag",
    default=True,
    show_default=True,
    help="Run station in async mode or manual mode",
)
@click.option(
    "--accept-security",
    "accept_security",
    default=False,
    show_default=True,
    help="Station should follow security provided by EVCC",
)
# TODO: Add option config file, in which will be load the file with dictionary
# Testing modules will also call this method and based on their purpose
# they will load different dictionaries
def start_station(interface: str, async_flag: bool, accept_security: bool):
    """Start station. By default is async (defined in click.option)"""
    # TODO: Here will be call of the logic to load/generate the dictionary,
    #       which contains the name of the request message type and the whole
    #       corresponding response message as key-value pair.
    # TODO: Add config option, in which will be load the file with dictionary
    # So first the user should generate dict in generate he specify what he wants to test
    # The station can have some defaults like test TLS enabled option
    # or some default test for ex for sessionID,
    # TODO: Maybe it will be better to have a another modules which will call the
    # station start_async with different dictionaries based on the testing module
    # or different setting for the TLS test and so on
    if async_flag:
        station.start_async(
            interface=interface, accept_security=accept_security
        )
    else:
        station.start(interface=interface)
