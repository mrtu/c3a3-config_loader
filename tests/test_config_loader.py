"""Test suite for the `config_loader` package

Run with:
    pytest -q
"""

from __future__ import annotations

import os
import pytest

from config_loader.encryption import EncryptionManager
from config_loader.main import Configuration
from config_loader.plugin_interface import ConfigPlugin, PluginManifest


# ---------------------------------------------------------------------------
# Helper plugin definitions
# ---------------------------------------------------------------------------

class DummyPlugin(ConfigPlugin):
    """A simple plugin that returns a predictable value for testing."""

    def __init__(self, *, return_value: str = "resolved_value") -> None:
        self._return_value = return_value

    # The manifest is regenerated on every access; that's fine for tests
    @property
    def manifest(self) -> PluginManifest:  # type: ignore[override]
        return PluginManifest(protocol="dummy", type="string", sensitive=False)

    def load_value(self, protocol_value: str):  # type: ignore[override]
        return f"{self._return_value}:{protocol_value}"


class SensitiveDummyPlugin(ConfigPlugin):
    """Dummy plugin that marks its return value as sensitive."""

    @property
    def manifest(self) -> PluginManifest:  # type: ignore[override]
        return PluginManifest(protocol="sensitive", type="string", sensitive=True)

    def load_value(self, protocol_value: str):  # type: ignore[override]
        return f"secret:{protocol_value}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def dummy_plugin() -> DummyPlugin:
    """Return a non‑sensitive dummy plugin instance."""

    return DummyPlugin()


@pytest.fixture()
def sensitive_plugin() -> SensitiveDummyPlugin:
    return SensitiveDummyPlugin()


@pytest.fixture()
def basic_spec() -> dict:
    """Return a minimal configuration spec used across multiple tests."""

    return {
        "app_name": "myapp",
        # Enable only argument source to keep tests isolated from env/RC
        "sources": {"args": True, "env": False, "rc": False},
        "parameters": [
            {
                "namespace": "db",
                "name": "password",
                "type": "string",
                "required": True,
                "obfuscated": True,
                "protocol": "dummy",
            },
            {
                "namespace": "app",
                "name": "timeout",
                "type": "number",
                "default": 30,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_encryption_manager_roundtrip() -> None:
    """`EncryptionManager.obfuscate()` should round‑trip with `reveal()`."""

    manager = EncryptionManager()
    plaintext = "s3cr3t"
    obfuscated = manager.obfuscate(plaintext)

    # Basic sanity check on the encoded prefix
    assert obfuscated.startswith("obfuscated:")

    revealed = manager.reveal(obfuscated)
    assert revealed == plaintext



def test_plugin_manager_loads_value(dummy_plugin: DummyPlugin) -> None:
    """`PluginManager` should delegate correctly to a registered plugin."""

    cfg = Configuration({"app_name": "plugapp"}, plugins=[dummy_plugin])

    loaded = cfg.plugin_manager.load_protocol_value(
        "dummy://xyz", expected_type="string"
    )

    assert loaded == "resolved_value:xyz"



def test_configuration_processes_protocol_value(
        basic_spec: dict, dummy_plugin: DummyPlugin
) -> None:
    """Configuration should resolve protocol values and obfuscate as requested."""

    cfg = Configuration(basic_spec, plugins=[dummy_plugin])

    # Provide required CLI argument using protocol syntax
    args = ["--db.password", "dummy://my-db-pass"]

    result = cfg.process(args)

    # The stored password must be obfuscated
    stored_password = result.db.password  # type: ignore[attr-defined]
    assert stored_password.startswith("obfuscated:")

    # De‑obfuscate and ensure the plugin logic ran
    assert cfg.reveal(stored_password) == "resolved_value:my-db-pass"

    # The parameter with default should be present and intact
    assert result.app.timeout == 30  # type: ignore[attr-defined]



def test_sensitive_protocol_requires_obfuscation(sensitive_plugin: SensitiveDummyPlugin):
    """A sensitive plugin should force parameters to be marked obfuscated."""

    bad_spec = {
        "app_name": "myapp",
        "parameters": [
            {
                "namespace": "db",
                "name": "password",
                "type": "string",
                "required": True,
                # Deliberately *not* obfuscated
                "obfuscated": False,
                "protocol": "sensitive",
            }
        ],
    }

    with pytest.raises(ValueError, match="must be obfuscated"):
        Configuration(bad_spec, plugins=[sensitive_plugin])
