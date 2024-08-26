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

"""This module contains enums for the station module."""
from enum import Enum


class EVSEChargingMode(str, Enum):
    """Enum for EVSE charging type."""

    AC = "AC"
    DC = "DC"


class EVSEDetails(str, Enum):
    """Enum for EVSE details."""

    # If an SECC cannot provide such ID data,
    # the value of the EVSEID is set to zero ("ZZ00000").
    # Value taken from ISO 15118-2, page 280
    EVSE_ID = "FRA23E45B78C"
    # Default SchemaID, value from ISO 15118-2, page 59
    SCHEMA_ID = "10"
    PROTOCOL_NAMESPACE = "urn:iso:15118:2:2013:MsgDef"
    INTERFACE = "eth_station"
    # CERT_FILE = "certs/evse_cert.pem"
    # KEY_FILE = "certs/evse_key.key"
    # TODO change, just to test with switchEV EVCC implementation
    CERT_FILE = "certs/cpoCertChain.pem"
    KEY_FILE = "certs/seccLeaf.key"


class EVSEDefaultDictPaths(str, Enum):
    """Enum for default station dictionary filepath."""

    AC_MODE_PATH = "default_dictionaries/default_dict_AC.json"
    DC_MODE_PATH = "default_dictionaries/default_dict_DC.json"
