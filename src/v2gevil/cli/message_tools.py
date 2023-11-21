"""Message tools.

Calling logic from messages module.
"""

import rich_click as click

# from tests import messages_tests
from ..messages import generator
from ..station.station_enums import (
    EVSEChargingMode,
)


@click.group()
def message_tools():
    """Message tool related commands"""


@message_tools.command(name="generate-default")
@click.option(
    "--charging-mode",
    "-cm",
    "charging_mode",
    default="AC",
    show_default=True,
    help="Charging mode of the EVSE",
)
@click.option(
    "--override-flag",
    "override_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="""Override flag for default dictionary.
    If set to True, default dictionary will be overwritten.
    Default dictionaries are in module called "messages", path to dictionaries:

    - AC: default_dictionaries/default_dict_AC.json
    
    - DC: default_dictionaries/default_dict_DC.json""",
)
def generate_default(charging_mode: str, override_flag: bool):
    """Generate messages"""

    # Need to convert string to enum for charging_mode
    try:
        # charging_mode = EVEnumMode(enum_mode) => need to catch ValueError
        charging_mode = EVSEChargingMode[
            charging_mode.upper()
        ]  # => need to catch KeyError
    except KeyError:
        print(f"Invalid charging mode: {charging_mode}")
        return

    # Create instance of message generator => default_dict is created
    # and saved to file if not exists or if override_flag is set to True
    generator.EVSEMessageGenerator(
        charging_mode=charging_mode, override_flag=override_flag
    )


# TODO: Delete some of the following commands
# @message_tools.command(name="testing2xml")
# def testing():
#     """Testing"""
#     messages_tests.testing()


# @message_tools.command(name="testing2instance")
# def testing2():
#     """Testing"""
#     messages_tests.testing_xml2class_instance()


# @message_tools.command(name="xml2instance")
# def xml2instance():
#     """Convert XML to instance"""
#     # messages.xml2class_instance()


# @message_tools.command(name="instance2xml")
# def instance2xml():
#     """Convert instance to XML"""
# messages.class_instance2xml()
