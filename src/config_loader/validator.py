# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Validator

Validates configuration specifications and ensures correctness.
"""

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .main import Configuration

class ConfigValidator:
    """Validates configuration specifications."""

    def __init__(self, config: "Configuration"):
        self.config = config

    def validate_spec(self) -> None:
        """Validate the configuration specification."""
        errors = []

        # Validate app_name
        if not re.match(r"^[a-z0-9_-]+$", self.config.app_name.lower()):
            errors.append(f"Invalid app_name: {self.config.app_name}")

        # Validate precedence
        valid_sources = {"args", "env", "rc"}
        if not all(p in valid_sources for p in self.config.precedence):
            errors.append(f"Invalid precedence values: {self.config.precedence}")

        # Validate parameters
        seen_params = set()
        for param in self.config.parameters:
            # Check name format
            if not re.match(r"^[a-z0-9_-]+$", param.name):
                errors.append(f"Invalid parameter name: {param.name}")

            # Check for duplicates
            key = f"{param.namespace or 'default'}.{param.name}"
            if key in seen_params:
                errors.append(f"Duplicate parameter: {key}")
            seen_params.add(key)

            # Validate type
            if param.type not in ["string", "number", "boolean"]:
                errors.append(f"Invalid type for {param.name}: {param.type}")

            # Validate required vs default
            if param.required and param.default is not None:
                errors.append(
                    f"Required parameter {param.name} cannot have default value"
                )

            # Validate accepts
            if param.accepts:
                if param.type == "boolean":
                    errors.append(
                        f"Boolean parameter {param.name} cannot have 'accepts' restriction"
                    )
                elif len(param.accepts) < 2:
                    errors.append(
                        f"Parameter {param.name} 'accepts' must have at least 2 values"
                    )
                elif param.default is not None and param.default not in param.accepts:
                    errors.append(
                        f"Default value for {param.name} not in accepted values"
                    )

            # Validate protocol
            if param.protocol and self.config.handle_protocol:
                try:
                    self.config.plugin_manager.validate_parameter_protocol_compatibility(
                        param, param.protocol
                    )
                except ValueError as e:
                    errors.append(str(e))

        # Validate arguments sequence
        found_optional = False
        for arg in self.config.arguments:
            if found_optional and arg.required:
                errors.append(
                    f"Required argument {arg.name} cannot follow optional arguments"
                )
            if not arg.required:
                found_optional = True

            # Validate argument protocol
            if arg.protocol and self.config.handle_protocol:
                if not self.config.plugin_manager.is_protocol_registered(arg.protocol):
                    errors.append(
                        f"Required protocol '{arg.protocol}' for argument {arg.name} is not registered"
                    )
                else:
                    manifest = self.config.plugin_manager.get_plugin_manifest(
                        arg.protocol
                    )

                    # Check type compatibility
                    if arg.type != manifest.type:
                        errors.append(
                            f"Argument {arg.name} type '{arg.type}' incompatible with protocol '{arg.protocol}' type '{manifest.type}'"
                        )

        if errors:
            raise ValueError(
                "Configuration specification errors:\n" + "\n".join(errors)
            )
