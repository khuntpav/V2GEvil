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

"""This module contains enums for the enumeration module."""
from enum import Enum


class EVEnumMode(str, Enum):
    """Enumeration of modes for EV enumeration."""

    ALL = "all"
    SUPPORTED_PROTOCOLS = "supported_protocols"
    TLS_CHECK = "tls_check"
    TLS_ENUM = "tls_enum"
