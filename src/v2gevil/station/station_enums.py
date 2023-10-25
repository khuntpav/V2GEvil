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
