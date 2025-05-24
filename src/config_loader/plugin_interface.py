# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Plugin Interface

Defines the protocol interface for configuration value plugins.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional, Union


@dataclass
class PluginManifest:
    """Plugin manifest containing metadata and constraints."""

    protocol: str
    type: str = "string"  # 'string', 'number', 'boolean'
    min_length: Optional[int] = None  # For strings only
    max_length: Optional[int] = None  # For strings only
    min_value: Optional[Union[int, float]] = None  # For numbers only
    max_value: Optional[Union[int, float]] = None  # For numbers only
    sensitive: bool = False  # Whether returned values are sensitive


class ConfigPlugin(ABC):
    """Abstract base class for configuration plugins."""

    @property
    @abstractmethod
    def manifest(self) -> PluginManifest:
        """Return the plugin manifest."""
        pass

    @abstractmethod
    def load_value(self, protocol_value: str) -> Any:
        """
        Load and return the configuration value.

        Args:
            protocol_value: The value part after the protocol (e.g., 'my_value' from 'my_protocol://my_value')

        Returns:
            The loaded configuration value

        Raises:
            ValueError: If the value cannot be loaded or is invalid
        """
        pass

    def validate_constraints(self, value: Any) -> None:
        """
        Validate that the loaded value meets the plugin's constraints.

        Args:
            value: The loaded value to validate

        Raises:
            ValueError: If the value doesn't meet the constraints
        """
        manifest = self.manifest

        if manifest.type == "string" and isinstance(value, str):
            if manifest.min_length is not None and len(value) < manifest.min_length:
                raise ValueError(
                    f"Value length {len(value)} is less than minimum {manifest.min_length}"
                )
            if manifest.max_length is not None and len(value) > manifest.max_length:
                raise ValueError(
                    f"Value length {len(value)} exceeds maximum {manifest.max_length}"
                )

        elif manifest.type == "number" and isinstance(value, (int, float)):
            if manifest.min_value is not None and value < manifest.min_value:
                raise ValueError(
                    f"Value {value} is less than minimum {manifest.min_value}"
                )
            if manifest.max_value is not None and value > manifest.max_value:
                raise ValueError(f"Value {value} exceeds maximum {manifest.max_value}")

        elif manifest.type == "boolean" and not isinstance(value, bool):
            raise ValueError(f"Expected boolean value, got {type(value).__name__}")
