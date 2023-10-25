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


@click.group()
def modules_tools():
    """Modules tool related commands"""


# Modules for enumeration
@modules_tools.command(name="enumerate-EV")
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
    "enum_mode",
    default="all",
    show_default=True,
    help="Mode of enumeration. Possible values: all, supported_protocols,\
        tls_check, tls_only_check. Default: all",
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
def fuzz_ev():
    """Fuzz EV"""
    # TODO: Implement
    raise NotImplementedError
    ev_fuzzer = EVFuzzer()
