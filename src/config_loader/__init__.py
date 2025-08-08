# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader Package

A seamless configuration loading system that supports:
- Command line arguments
- Environment variables
- RC files (TOML format)
- Configurable precedence
- Type validation and restrictions
- AES256 obfuscation for sensitive values
- Plugin system for protocol-based value loading
"""

from .main import Configuration, load_config, load_configs
from .models import ConfigParam, ConfigArg
from .plugin_interface import ConfigPlugin, PluginManifest
from .result import ConfigurationResult

__version__ = "1.0.0"
__all__ = [
    "Configuration",
    "ConfigParam",
    "ConfigArg",
    "ConfigurationResult",
    "ConfigPlugin",
    "PluginManifest",
    "load_config",
    "load_configs",
]
