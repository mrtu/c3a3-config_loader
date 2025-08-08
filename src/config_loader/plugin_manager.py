# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Plugin Manager

Manages registration and execution of configuration plugins.
"""

import re
from typing import Dict, Any, TYPE_CHECKING, Optional

from .plugin_interface import ConfigPlugin, PluginManifest
from .models import ConfigParam

if TYPE_CHECKING:
    from .main import Configuration


class PluginManager:
    """Manages configuration plugins."""

    def __init__(self, config: "Configuration"):
        self.config = config
        self._plugins: Dict[str, ConfigPlugin] = {}
        self._protocol_pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*):\/\/(.+)$")

    def register_plugin(self, plugin: ConfigPlugin) -> None:
        """
        Register a configuration plugin.

        Args:
            plugin: The plugin instance to register

        Raises:
            ValueError: If the plugin is invalid or protocol is already registered
        """
        manifest = plugin.manifest

        # Validate manifest
        self._validate_manifest(manifest)

        # Check for duplicate protocols
        if manifest.protocol in self._plugins:
            raise ValueError(
                f"Plugin for protocol '{manifest.protocol}' is already registered"
            )

        self._plugins[manifest.protocol] = plugin

    def _validate_manifest(self, manifest: PluginManifest) -> None:
        """Validate a plugin manifest."""
        # Validate protocol name
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", manifest.protocol):
            raise ValueError(f"Invalid protocol name: {manifest.protocol}")

        # Validate type
        if manifest.type not in ["string", "number", "boolean"]:
            raise ValueError(f"Invalid type: {manifest.type}")

        # Validate constraints
        if manifest.type != "string":
            if manifest.min_length is not None or manifest.max_length is not None:
                raise ValueError(
                    f"Length constraints only valid for string type, not {manifest.type}"
                )

        if manifest.type != "number":
            if manifest.min_value is not None or manifest.max_value is not None:
                raise ValueError(
                    f"Value constraints only valid for number type, not {manifest.type}"
                )

        # Validate constraint ranges
        if manifest.min_length is not None and manifest.max_length is not None:
            if manifest.min_length > manifest.max_length:
                raise ValueError("min_length cannot be greater than max_length")

        if manifest.min_value is not None and manifest.max_value is not None:
            if manifest.min_value > manifest.max_value:
                raise ValueError("min_value cannot be greater than max_value")

    def is_protocol_value(self, value: str) -> bool:
        """Check if a value uses protocol syntax."""
        if not isinstance(value, str):
            return False
        return bool(self._protocol_pattern.match(value))

    def parse_protocol_value(self, value: str) -> tuple[str, str]:
        """
        Parse a protocol value into protocol and value parts.

        Args:
            value: The protocol value (e.g., 'my_protocol://my_value')

        Returns:
            Tuple of (protocol, value_part)

        Raises:
            ValueError: If the value is not a valid protocol format
        """
        match = self._protocol_pattern.match(value)
        if not match:
            raise ValueError(f"Invalid protocol format: {value}")

        return match.group(1), match.group(2)

    def load_protocol_value(self, value: str, expected_type: Optional[str] = None) -> Any:
        """
        Load a value using the appropriate protocol plugin.

        Args:
            value: The protocol value to load
            expected_type: Expected parameter type for validation

        Returns:
            The loaded value

        Raises:
            ValueError: If protocol is not registered or value is invalid
        """
        protocol, value_part = self.parse_protocol_value(value)

        if protocol not in self._plugins:
            raise ValueError(f"No plugin registered for protocol: {protocol}")

        plugin = self._plugins[protocol]
        manifest = plugin.manifest

        # Validate type compatibility if expected type is provided
        if expected_type and expected_type != manifest.type:
            raise ValueError(
                f"Protocol '{protocol}' returns {manifest.type} but parameter expects {expected_type}"
            )

        # Load the value
        loaded_value = plugin.load_value(value_part)

        # Validate constraints
        plugin.validate_constraints(loaded_value)

        return loaded_value

    def get_plugin_manifest(self, protocol: str) -> PluginManifest:
        """Get the manifest for a registered protocol."""
        if protocol not in self._plugins:
            raise ValueError(f"No plugin registered for protocol: {protocol}")
        return self._plugins[protocol].manifest

    def is_protocol_registered(self, protocol: str) -> bool:
        """Check if a protocol is registered."""
        return protocol in self._plugins

    def get_registered_protocols(self) -> list[str]:
        """Get list of all registered protocols."""
        return list(self._plugins.keys())

    def validate_parameter_protocol_compatibility(self, param: ConfigParam, protocol: str) -> None:
        """
        Validate that a parameter is compatible with a required protocol.

        Args:
            param: ConfigParam instance
            protocol: Required protocol name

        Raises:
            ValueError: If parameter is not compatible with protocol
        """
        if not self.is_protocol_registered(protocol):
            raise ValueError(f"Required protocol '{protocol}' is not registered")

        manifest = self.get_plugin_manifest(protocol)

        # Check type compatibility
        if param.type != manifest.type:
            raise ValueError(
                f"Parameter {param.name} type '{param.type}' incompatible with protocol '{protocol}' type '{manifest.type}'"
            )

        # Check obfuscation requirement
        if manifest.sensitive and not param.obfuscated:
            raise ValueError(
                f"Parameter {param.name} must be obfuscated when using sensitive protocol '{protocol}'"
            )
