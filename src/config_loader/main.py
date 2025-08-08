# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Main Module

A seamless configuration loading system that supports:
- Command line arguments
- Environment variables
- RC files (TOML format)
- Configurable precedence
- Type validation and restrictions
- AES256 obfuscation for sensitive values
- Plugin system for protocol-based value loading
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, cast, IO

from .encryption import EncryptionManager
from .loaders import ArgumentLoader, EnvironmentLoader, RCLoader
from .models import ConfigParam, ConfigArg
from .plugin_interface import ConfigPlugin
from .plugin_manager import PluginManager
from .result import ConfigurationResult
from .validator import ConfigValidator

# Optional runtime imports are made inside functions to avoid module-typed None assignments.


class Configuration:
    """Configuration processor and validator."""

    def __init__(
        self, spec: Dict[str, Any], plugins: Optional[List[ConfigPlugin]] = None
    ):
        self.spec = spec
        self.app_name = spec.get("app_name", "app")
        self.print_help_on_err = spec.get("print_help_on_err", False)
        self.handle_protocol = spec.get("handle_protocol", True)
        self.sources = spec.get("sources", {"args": True, "rc": True, "env": True})
        self.precedence = spec.get("precedence", ["args", "env", "rc"])
        self.parameters = [ConfigParam(**p) for p in spec.get("parameters", [])]
        self.arguments = [ConfigArg(**a) for a in spec.get("arguments", [])]

        # Initialize components
        self.encryption = EncryptionManager()
        self.plugin_manager = PluginManager(self)
        self.validator = ConfigValidator(self)
        self.arg_loader = ArgumentLoader(self)
        self.env_loader = EnvironmentLoader(self)
        self.rc_loader = RCLoader(self)

        # Register plugins if provided
        if plugins:
            for plugin in plugins:
                self.register_plugin(plugin)

        self._validate_spec()

    def register_plugin(self, plugin: ConfigPlugin) -> None:
        """Register a configuration plugin."""
        self.plugin_manager.register_plugin(plugin)

    def _validate_spec(self) -> None:
        """Validate the configuration specification."""
        self.validator.validate_spec()

    def reveal(self, obfuscated_value: str) -> str:
        """Decrypt an obfuscated value."""
        return self.encryption.reveal(obfuscated_value)

    def validate(self, args: List[str]) -> bool:
        """Validate configuration without processing."""
        try:
            self.process(args)
            return True
        except Exception:
            return False

    def process(self, args: List[str]) -> ConfigurationResult:
        """Process and validate configuration from all sources."""
        # Load from all sources
        sources_data: Dict[str, Dict[str, Any]] = {}
        debug_info: Dict[str, str] = {}

        if self.sources.get("args", True):
            sources_data["args"] = self.arg_loader.load(args)

        if self.sources.get("env", True):
            sources_data["env"] = self.env_loader.load()

        if self.sources.get("rc", True):
            sources_data["rc"] = self.rc_loader.load()

        # Check for debug flag
        show_debug = sources_data.get("args", {}).get("debug", False)

        # Merge according to precedence
        final_config: Dict[str, Any] = {}

        for param in self.parameters:
            namespace = param.namespace or "default"
            value = None
            source = "default"

            # Check sources in precedence order
            for source_name in reversed(
                self.precedence
            ):  # Reverse for proper precedence
                if source_name == "args":
                    arg_key = f"param_{namespace}_{param.name}"
                    if sources_data.get("args", {}).get(arg_key) is not None:
                        value = sources_data["args"][arg_key]
                        source = "args"
                elif source_name == "env":
                    if (
                        namespace in sources_data.get("env", {})
                        and param.name in sources_data["env"][namespace]
                    ):
                        value = sources_data["env"][namespace][param.name]
                        source = "env"
                elif source_name == "rc":
                    if (
                        namespace in sources_data.get("rc", {})
                        and param.name in sources_data["rc"][namespace]
                    ):
                        value = sources_data["rc"][namespace][param.name]
                        source = "rc"

            # Use default if no value found
            if value is None:
                if param.required:
                    error_msg = (
                        f"Required parameter {namespace}.{param.name} not provided"
                    )
                    if self.print_help_on_err:
                        self.print_help()
                    raise ValueError(error_msg)
                value = param.default
                source = "default"

            # Validate required protocol BEFORE processing (skip for default values)
            if param.protocol and self.handle_protocol and source != "default":
                if not isinstance(
                    value, str
                ) or not self.plugin_manager.is_protocol_value(value):
                    error_msg = f"Parameter {namespace}.{param.name} requires protocol '{param.protocol}' but got non-protocol value"
                    if self.print_help_on_err:
                        self.print_help()
                    raise ValueError(error_msg)
                else:
                    # Validate that the correct protocol is used
                    protocol, _ = self.plugin_manager.parse_protocol_value(value)
                    if protocol != param.protocol:
                        error_msg = f"Parameter {namespace}.{param.name} requires protocol '{param.protocol}' but got '{protocol}'"
                        if self.print_help_on_err:
                            self.print_help()
                        raise ValueError(error_msg)

            # Process protocol values AFTER validation
            if value is not None and self.handle_protocol:
                value = self._process_protocol_value(value, param, source)

            # Parse and validate value (if not processed by protocol)
            if (
                value is not None
                and isinstance(value, str)
                and not (
                    self.handle_protocol
                    and self.plugin_manager.is_protocol_value(value)
                )
            ):
                value = self._parse_value(value, param.type)

                # Validate accepts
                if param.accepts and value not in param.accepts:
                    error_msg = f"Invalid value for {namespace}.{param.name}: {value} not in {param.accepts}"
                    if self.print_help_on_err:
                        self.print_help()
                    raise ValueError(error_msg)

            # Obfuscate if needed (after protocol processing)
            if param.obfuscated and value is not None:
                value = self.encryption.obfuscate(value)

            # Store in final config
            if namespace not in final_config:
                final_config[namespace] = {}
            final_config[namespace][param.name] = value
            debug_info[f"{namespace}.{param.name}"] = source

        # Process positional arguments
        if self.arguments:
            arg_values = []
            for i, arg in enumerate(self.arguments):
                arg_value = sources_data.get("args", {}).get(arg.name)
                if arg_value is None:
                    if arg.required:
                        error_msg = f"Required argument {arg.name} not provided"
                        if self.print_help_on_err:
                            self.print_help()
                        raise ValueError(error_msg)
                    arg_value = arg.default

                # Validate required protocol for arguments BEFORE processing
                if arg.protocol and self.handle_protocol and arg_value is not None:
                    if not isinstance(
                        arg_value, str
                    ) or not self.plugin_manager.is_protocol_value(arg_value):
                        error_msg = f"Argument {arg.name} requires protocol '{arg.protocol}' but got non-protocol value"
                        if self.print_help_on_err:
                            self.print_help()
                        raise ValueError(error_msg)
                    else:
                        # Validate that the correct protocol is used
                        protocol, _ = self.plugin_manager.parse_protocol_value(
                            arg_value
                        )
                        if protocol != arg.protocol:
                            error_msg = f"Argument {arg.name} requires protocol '{arg.protocol}' but got '{protocol}'"
                            if self.print_help_on_err:
                                self.print_help()
                            raise ValueError(error_msg)

                # Process protocol values for arguments AFTER validation
                if arg_value is not None and self.handle_protocol:
                    arg_value = self._process_protocol_value(arg_value, arg, "args")

                # Parse value if not processed by protocol
                if (
                    arg_value is not None
                    and isinstance(arg_value, str)
                    and not (
                        self.handle_protocol
                        and self.plugin_manager.is_protocol_value(arg_value)
                    )
                ):
                    arg_value = self._parse_value(arg_value, arg.type)

                arg_values.append(arg_value)

            # Add arguments to config
            if "arguments" not in final_config:
                final_config["arguments"] = {}
            for arg, value in zip(self.arguments, arg_values):
                final_config["arguments"][arg.name] = value
                debug_info[f"arguments.{arg.name}"] = "args"

        result = ConfigurationResult(final_config, debug_info)

        if show_debug:
            result.debug()

        return result

    def _process_protocol_value(self, value: Any, param_or_arg: ConfigParam | ConfigArg, source: str) -> Any:
        """Process a value that might use protocol syntax."""
        if not isinstance(value, str) or not self.plugin_manager.is_protocol_value(
            value
        ):
            return value

        try:
            # Load the value using the plugin
            loaded_value = self.plugin_manager.load_protocol_value(
                value, param_or_arg.type
            )

            # Check if the protocol returns sensitive data
            protocol, _ = self.plugin_manager.parse_protocol_value(value)
            manifest = self.plugin_manager.get_plugin_manifest(protocol)

            # Validate obfuscation requirement for sensitive protocols
            if (
                manifest.sensitive
                and hasattr(param_or_arg, "obfuscated")
                and not param_or_arg.obfuscated
            ):
                param_name = (
                    f"{param_or_arg.namespace or 'default'}.{param_or_arg.name}"
                    if hasattr(param_or_arg, "namespace")
                    else param_or_arg.name
                )
                raise ValueError(
                    f"Parameter {param_name} must be obfuscated when using sensitive protocol '{protocol}'"
                )

            return loaded_value

        except Exception as e:
            param_name = (
                f"{param_or_arg.namespace or 'default'}.{param_or_arg.name}"
                if hasattr(param_or_arg, "namespace")
                else param_or_arg.name
            )
            if self.print_help_on_err:
                self.print_help()
            raise ValueError(f"Failed to load protocol value for {param_name}: {e}")

    def _parse_value(self, value: str, param_type: str) -> Any:
        """Parse string value to appropriate type."""
        if param_type == "boolean":
            true_vals = {"true", "1", "yes", "on"}
            false_vals = {"false", "0", "no", "off"}
            v = value.strip().lower()
            if v in true_vals:
                return True
            if v in false_vals:
                return False
            raise ValueError(f"Invalid boolean: {value}")
        elif param_type == "number":
            try:
                if "." in value:
                    return float(value)
                return int(value)
            except ValueError:
                raise ValueError(f"Invalid number: {value}")
        return value

    def print_help(self) -> None:
        """Print CLI help information."""
        print(
            f"\nUsage: {self.app_name} [OPTIONS] {' '.join(arg.name.upper() if arg.required else f'[{arg.name.upper()}]' for arg in self.arguments)}"
        )

        print("\nOptions:")
        for param in self.parameters:
            arg_name = f"--{self._get_arg_name(param)}"
            description = f"{param.type}"
            if param.obfuscated:
                description += " [obfuscated]"
            if param.protocol:
                description += f" [protocol: {param.protocol}]"
            if param.accepts:
                description += f" (choices: {', '.join(map(str, param.accepts))})"
            if param.default is not None:
                description += f" [default: {param.default}]"
            if param.required:
                description += " [required]"

            print(f"  {arg_name:<30} {description}")

        print(f"  {'--debug':<30} Show configuration debug information")

        if self.arguments:
            print("\nPositional Arguments:")
            for arg in self.arguments:
                description = f"{arg.type}"
                if arg.protocol:
                    description += f" [protocol: {arg.protocol}]"
                if not arg.required and arg.default is not None:
                    description += f" [default: {arg.default}]"
                status = " [required]" if arg.required else " [optional]"
                print(f"  {arg.name:<30} {description}{status}")

        if self.handle_protocol and self.plugin_manager.get_registered_protocols():
            print("\nRegistered Protocols:")
            for protocol in sorted(self.plugin_manager.get_registered_protocols()):
                manifest = self.plugin_manager.get_plugin_manifest(protocol)
                sensitive_info = " [sensitive]" if manifest.sensitive else ""
                print(
                    f"  {protocol}://<value>          {manifest.type}{sensitive_info}"
                )

    def _get_arg_name(self, param: ConfigParam) -> str:
        """Get command line argument name."""
        if param.namespace:
            return f"{param.namespace}.{param.name}"
        return param.name


def _detect_script_name() -> str:
    """Detect the script name from sys.argv[0]."""
    script_path = sys.argv[0]
    script_name = os.path.splitext(os.path.basename(script_path))[0]
    return script_name


def _load_schema() -> Dict[str, Any]:
    """Load the configuration schema."""
    schema_path = Path(__file__).parent / "config_schema.json"
    with open(schema_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Schema file must contain a JSON object at the top level")
    return cast(Dict[str, Any], data)


def _validate_config_schema(config_data: Dict[str, Any]) -> None:
    """Validate configuration data against the schema."""
    try:
        import importlib
        jsonschema_mod: Any = importlib.import_module("jsonschema")
    except Exception:
        print("Warning: Schema validation requires 'jsonschema' package. Install with: pip install jsonschema")
        return
    
    try:
        schema = _load_schema()
        jsonschema_mod.validate(config_data, schema)
    except FileNotFoundError:
        # If the packaged schema is not available, warn and skip validation
        print("Warning: Schema file not found; skipping JSON schema validation.")
        return
    except Exception as e:
        # jsonschema.ValidationError is not typed here; report generically
        raise ValueError(f"Schema validation failed: {e}")


def _check_schema_version(config_data: Dict[str, Any]) -> None:
    """Check if the schema version is supported."""
    schema_version = config_data.get("schema_version")
    if not schema_version:
        raise ValueError("Configuration file must include 'schema_version' field")
    
    # For now, we support version 1.0 and 1.x
    supported_versions = ["1.0", "1.0.0"]
    if schema_version not in supported_versions:
        print(f"Warning: Schema version '{schema_version}' may not be fully supported. Supported versions: {supported_versions}")


def _load_config_file(config_path: Path) -> Dict[str, Any]:
    """Load configuration from JSON or YAML file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        if config_path.suffix.lower() in ['.yaml', '.yml']:
            try:
                import importlib
                yaml_mod: Any = importlib.import_module("yaml")
            except Exception:
                raise ImportError("YAML support requires 'pyyaml' package. Install with: pip install pyyaml")
            loaded = yaml_mod.safe_load(f)
        elif config_path.suffix.lower() == '.json':
            loaded = json.load(f)
        else:
            raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")
    
    if not isinstance(loaded, dict):
        raise ValueError("Configuration file must contain a top-level mapping/object")
    config_data = loaded

    # Validate schema version and structure
    _check_schema_version(config_data)
    _validate_config_schema(config_data)
    
    return config_data


def load_config_auto(plugins: Optional[List[ConfigPlugin]] = None) -> Configuration:
    """Automatically load configuration from script_name.json or script_name.yaml.

    Validation rules:
    - If none of {script}.json/.yaml/.yml exists in CWD, raise FileNotFoundError.
    - If more than one exists (e.g., both JSON and YAML), raise a ValueError about duplicate configs.
    - If exactly one exists, load it.
    """
    script_name = _detect_script_name()

    candidates = [Path(f"{script_name}{ext}") for ext in [".json", ".yaml", ".yml"]]
    present = [p for p in candidates if p.exists()]

    if not present:
        raise FileNotFoundError(
            f"No configuration file found for script '{script_name}'. Expected: {script_name}.json, {script_name}.yaml, or {script_name}.yml"
        )

    if len(present) > 1:
        # Duplicate configuration definitions found
        present_list = ", ".join(str(p) for p in present)
        raise ValueError(
            f"Multiple configuration files found for script '{script_name}': {present_list}. Please keep only one."
        )

    # Exactly one file to load
    config_data = _load_config_file(present[0])
    return Configuration(config_data, plugins)



def load_config(fp: IO[str], plugins: Optional[List[ConfigPlugin]] = None) -> Configuration:
    """Load configuration from file pointer."""
    config_data = json.load(fp)
    if not isinstance(config_data, dict):
        raise ValueError("Configuration file must contain a top-level mapping/object")
    return Configuration(config_data, plugins)


def load_configs(
    spec: Dict[str, Any], plugins: Optional[List[ConfigPlugin]] = None
) -> Configuration:
    """Load configuration from specification dictionary."""
    return Configuration(spec, plugins)
