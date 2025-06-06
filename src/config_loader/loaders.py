# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Source Loaders

Handles loading configuration from different sources:
- Command line arguments
- Environment variables
- RC files (TOML format)
"""

import os
import argparse
from pathlib import Path
from typing import Dict, List, Any, TYPE_CHECKING

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("Warning: TOML support requires Python 3.11+ or 'tomli' package")
        tomllib = None

if TYPE_CHECKING:
    from .main import Configuration


class ArgumentLoader:
    """Loads configuration from command line arguments."""

    def __init__(self, config: "Configuration"):
        self.config = config

    def load(self, args: List[str]) -> Dict[str, Any]:
        """Load configuration from command line arguments."""
        parser = argparse.ArgumentParser(add_help=False)

        # Add configuration parameters
        for param in self.config.parameters:
            arg_name = f"--{self._get_arg_name(param)}"
            parser.add_argument(
                arg_name, dest=f"param_{param.namespace or 'default'}_{param.name}"
            )

        # Add positional arguments
        for arg in self.config.arguments:
            if arg.required:
                parser.add_argument(arg.name)
            else:
                parser.add_argument(arg.name, nargs="?", default=arg.default)

        # Add debug flag
        parser.add_argument("--debug", action="store_true")

        parsed, _ = parser.parse_known_args(args)
        return vars(parsed)

    def _get_arg_name(self, param) -> str:
        """Get command line argument name."""
        if param.namespace:
            return f"{param.namespace}.{param.name}"
        return param.name


class EnvironmentLoader:
    """Loads configuration from environment variables."""

    def __init__(self, config: "Configuration"):
        self.config = config

    def load(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        for param in self.config.parameters:
            env_name = self._get_env_name(param)
            if env_name in os.environ:
                namespace = param.namespace or "default"
                if namespace not in config:
                    config[namespace] = {}
                config[namespace][param.name] = os.environ[env_name]
        return config

    def _get_env_name(self, param) -> str:
        """Get environment variable name."""
        app = self.config.app_name.upper().replace("-", "_")
        namespace = (
            param.namespace.upper().replace("-", "_") if param.namespace else None
        )
        name = param.name.upper().replace("-", "_")

        if namespace:
            return f"{app}_{namespace}_{name}"
        return f"{app}_{name}"


class RCLoader:
    """Loads configuration from RC files."""

    def __init__(self, config: "Configuration"):
        self.config = config

    def load(self) -> Dict[str, Any]:
        """Load configuration from RC file."""
        if not tomllib:
            return {}

        rc_file = Path.home() / f".{self.config.app_name.lower()}rc"
        if not rc_file.exists():
            return {}

        try:
            with open(rc_file, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"Warning: Could not load RC file {rc_file}: {e}")
            return {}
