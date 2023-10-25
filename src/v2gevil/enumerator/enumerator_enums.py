"""This module contains enums for the enumeration module."""
from enum import Enum


class EVEnumMode(str, Enum):
    """Enumeration of modes for EV enumeration."""

    ALL = "all"
    SUPPORTED_PROTOCOLS = "supported_protocols"
    TLS_CHECK = "tls_check"
    TLS_CHECK_ONLY = "tls_check_only"
    TLS_RECOGNITION = "tls_recognition"
