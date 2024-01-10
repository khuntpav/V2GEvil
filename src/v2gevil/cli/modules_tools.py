"""Calling logic for testing modules.

Testing modules in this context are modules which are testing some specific
functionality of the EV/EVSE. For example testing of the TLS or testing of the
invalid messages and other action related to enumeration and security testing.
"""

import rich_click as click

# from ..enumerator.enumerator import EVSEEnumerator
from ..enumerator import enumerate_ev as EV_enumerator
from ..enumerator.enumerator_enums import EVEnumMode
from ..fuzzer.fuzzer import EVFuzzer
from ..fuzzer.fuzzer_enums import EVFuzzMode
from ..station.station_enums import EVSEChargingMode, EVSEDetails


@click.group()
def modules_tools():
    """Modules tool related commands"""


# Modules for enumeration
@modules_tools.command(name="enumerate-EV")
@click.option(
    "--interface",
    "-i",
    default=EVSEDetails.INTERFACE.value,
    show_default=True,
    help="Interface to run station on",
)
@click.option(
    "--mode",
    "-m",
    "enum_mode",
    default="all",
    show_default=True,
    help="Mode of enumeration. Possible values: all, supported_protocols,\
        tls_check, tls_enum. Default: all",
)
def enumerate_ev(interface: str, enum_mode: str):
    """Enumerate EV"""

    # Need to convert string to enum for enum_mode
    try:
        # enum_mode = EVEnumMode(enum_mode) => need to catch ValueError
        # [] works because EVEnumMode searchs for key in enum names
        mode = EVEnumMode[enum_mode.upper()]  # => need to catch KeyError
    except KeyError:
        print(f"Invalid enum mode: {enum_mode}")
        return

    EV_enumerator.enumerate_ev(interface=interface, enum_mode=mode)


# Modules for fuzzing
@modules_tools.command(name="fuzz-EV")
@click.option(
    "--interface",
    "-i",
    default=EVSEDetails.INTERFACE.value,
    show_default=True,
    help="Interface to run station on",
)
@click.option(
    "--mode",
    "-m",
    default="all",
    show_default=True,
    help="""
        Mode of fuzzing. Possible values: all, custom, message, config.\n
        all fuzz all messages and all possible params\n
        custom: fuzz only specified params (specified by user)\n
        message: fuzz only specified message (specified by user)
        Message name must be specified by --message-name option.\n
        config: fuzz only messages and params specified in fuzzer config file.
        """,
)
@click.option(
    "--message-name",
    default="",
    show_default=True,
    help="""Name of message to fuzz. Only used in message mode.
        Fuzzed message will be only specified message not others.""",
)
@click.option(
    "--charging-mode",
    "-cm",
    default="AC",
    show_default=True,
    help="Charging mode of EVSE. Possible values: AC, DC.",
)
@click.option(
    "--custom-dict",
    "custom_dict_filename",
    default=None,
    show_default=True,
    help="Path to file with custom dictionary, which will be used for fuzzing.",
)
@click.option(
    "--config-filename",
    "config_filename",
    default="ev_fuzzer_config_default.toml",
    show_default=True,
    help="""Name of the fuzzer config file.
    File must be in the config directory of fuzzer module.
    Option is applicable only for config mode or message mode.
    For message mode: attributes for fuzzing for the specified message
    will be taken from the config file.""",
)
def fuzz_ev(
    interface: str,
    mode: str,
    message_name: str,
    charging_mode: str,
    custom_dict_filename: str,
    config_filename: str,
):
    """Fuzz EV"""
    try:
        mode = EVFuzzMode(mode)
    except ValueError:
        print(f"Invalid fuzz mode: {mode}")
        return
    try:
        charging_mode = EVSEChargingMode(charging_mode)
    except ValueError:
        print(f"Invalid charging mode: {charging_mode}")
        return

    ev_fuzzer = EVFuzzer(
        interface=interface,
        mode=mode,
        charging_mode=charging_mode,
        custom_dict_filename=custom_dict_filename,
        config_filename=config_filename,
    )
    # Fuzz
    # Depending on mode, different function will be called
    # message_name is only used in message mode
    # Only chosen message will be fuzzed, specified by message_name, in message mode
    ev_fuzzer.fuzz(message_name=message_name)
