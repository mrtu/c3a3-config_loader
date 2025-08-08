# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Result Object

Contains processed configuration values with convenient access methods.
"""

import json
from typing import Dict, Any


class ConfigurationResult:
    """Result object containing processed configuration values."""

    def __init__(self, config_dict: Dict[str, Any], debug_info: Dict[str, str]):
        self._config = config_dict
        self._debug_info = debug_info

        # Create namespace objects dynamically
        for namespace, values in config_dict.items():
            if not hasattr(self, namespace):
                setattr(self, namespace, type("ConfigNamespace", (), values)())

    def export_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return self._config.copy()

    def export_json(self) -> str:
        """Export configuration as JSON string."""
        return json.dumps(self._config, indent=2)

    def debug(self) -> None:
        """Print debug information about configuration sources."""
        print("Configuration Debug Information:")
        print("=" * 40)
        for key, source in self._debug_info.items():
            value = self._get_nested_value(key)
            print(f"{key}: {value} (from {source})")

    def _get_nested_value(self, key: str) -> Any:
        """Get nested value using dot notation."""
        parts = key.split(".")
        value = self._config
        for part in parts:
            value = value.get(part, {})
        return value
