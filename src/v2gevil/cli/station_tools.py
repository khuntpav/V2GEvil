"""Station related tools.

Calling logic from car module.
"""
from typing import Optional
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
    is_flag=True,  # need to add is_flag, because i have no /--no-accept-security
    default=False,
    show_default=True,
    help="Station should follow security provided by EVCC",
)
@click.option(
    "--charging-mode",
    "charging_mode",
    default="AC",
    show_default=True,
    help="Charging mode of the EVSE. Possible values: AC, DC",
)
@click.option(
    "--custom-dict",
    "custom_dict_filename",
    default=None,
    show_default=True,
    help="Path to file with custom dictionary for mapping V2GTP requests to responses",
)
def start_station(
    interface: str,
    async_flag: bool,
    accept_security: bool,
    charging_mode: str,
    custom_dict_filename: str,
):
    """Start station. By default is async (defined in click.option)"""

    # Need to convert string to enum for charging_mode
    try:
        # charging_mode = EVEnumMode(enum_mode) => need to catch ValueError
        charging_mode = station.EVSEChargingMode[
            charging_mode.upper()
        ]  # => need to catch KeyError
    except KeyError:
        print(f"Invalid charging mode: {charging_mode}")
        return

    # Load custom config from file if provided
    # Responsibility of the user to provide correct file
    # No additional validation for the content of the file is done
    custom_dict = None
    if custom_dict_filename:
        custom_dict = station.load_custom_dict_from_file(
            filename=custom_dict_filename
        )

    # Run station in async mode or manual mode
    if async_flag:
        station.start_async(
            interface=interface,
            accept_security=accept_security,
            charging_mode=charging_mode,
            custom_dict=custom_dict,
        )
    else:
        # Deprecated
        station.start(interface=interface)
