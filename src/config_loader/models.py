# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Data Models

Defines the data structures used throughout the configuration system.
"""

from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class ConfigParam:
    """Represents a configuration parameter."""

    namespace: Optional[str]
    name: str
    type: str
    required: bool = False
    default: Any = None
    accepts: Optional[List[Any]] = None
    obfuscated: bool = False
    protocol: Optional[str] = None


@dataclass
class ConfigArg:
    """Represents a positional argument."""

    name: str
    type: str
    required: bool = False
    default: Any = None
    protocol: Optional[str] = None
