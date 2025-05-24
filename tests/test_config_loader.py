"""Test suite for the `config_loader` package

Run with:
    pytest -q
"""

from __future__ import annotations

import base64
import secrets
from pathlib import Path
from typing import Any, Dict, List

import config_loader.loaders as loaders
import pytest
from config_loader.encryption import EncryptionManager
from config_loader.main import Configuration
from config_loader.plugin_interface import ConfigPlugin, PluginManifest


def _prepare_config(
    spec: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    args_data: Dict[str, Any] | None = None,
    env_data: Dict[str, Dict[str, Any]] | None = None,
    rc_data: Dict[str, Dict[str, Any]] | None = None,
    argv: List[str] | None = None,
    plugins: List[ConfigPlugin] | None = None,
):
    """Instantiate ``Configuration`` and stub out the three loaders."""

    cfg = Configuration(spec, plugins)

    # Monkey‑patch loader outputs
    if args_data is not None:
        monkeypatch.setattr(cfg.arg_loader, "load", lambda _a=argv or []: args_data)
    if env_data is not None:
        monkeypatch.setattr(cfg.env_loader, "load", lambda: env_data)
    if rc_data is not None:
        monkeypatch.setattr(cfg.rc_loader, "load", lambda: rc_data)

    return cfg


def test_precedence_args_over_rc_over_env(monkeypatch: pytest.MonkeyPatch):
    """`precedence=['args','rc','env']` ⇒ args win → rc → env."""

    spec = {
        "app_name": "c3a3",
        "precedence": ["args", "rc", "env"],
        "parameters": [
            {"namespace": None, "name": "host", "type": "string", "required": True},
        ],
    }

    cfg = _prepare_config(
        spec,
        monkeypatch,
        args_data={"param_default_host": "from‑args"},
        rc_data={"default": {"host": "from‑rc"}},
        env_data={"default": {"host": "from‑env"}},
    )

    result = cfg.process([])  # argv isn’t used – we patched ArgsLoader
    assert result._config["default"]["host"] == "from‑args"


def test_obfuscation_applied_and_reversible(monkeypatch: pytest.MonkeyPatch):
    """If a parameter is ``obfuscated=True`` the stored value is encrypted, but
    ``EncryptionManager.reveal`` must return the original string."""

    plaintext = "s3cr3t‑pizza"

    spec = {
        "app_name": "c3a3",
        "precedence": ["env", "rc", "args"],
        "parameters": [
            {
                "namespace": None,
                "name": "api_key",
                "type": "string",
                "required": True,
                "obfuscated": True,
            },
        ],
    }

    cfg = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"api_key": plaintext}},
    )

    result = cfg.process([])
    stored = result._config["default"]["api_key"]

    # Should not be the raw secret and must be decryptable.
    assert stored != plaintext
    assert cfg.encryption.reveal(stored) == plaintext


def test_validations_required_and_accepts(monkeypatch: pytest.MonkeyPatch):
    """Missing required param or value outside ``accepts`` list raises ``ValueError``."""

    spec = {
        "app_name": "c3a3",
        "parameters": [
            {
                "namespace": None,
                "name": "mode",
                "type": "string",
                "accepts": ["auto", "manual"],
                "required": True,
            },
        ],
    }

    # Case 1 – missing entirely → error
    cfg_missing = _prepare_config(spec, monkeypatch, env_data={})
    with pytest.raises(ValueError):
        cfg_missing.process([])

    # Case 2 – invalid choice → error
    cfg_bad = _prepare_config(
        spec, monkeypatch, env_data={"default": {"mode": "invalid"}}
    )
    with pytest.raises(ValueError):
        cfg_bad.process([])

    # Case 3 – valid value → passes
    cfg_ok = _prepare_config(spec, monkeypatch, env_data={"default": {"mode": "auto"}})
    result = cfg_ok.process([])
    assert result._config["default"]["mode"] == "auto"


class BoundedNumberPlugin(ConfigPlugin):
    """`num://<value>` – accepts numbers 1≤x≤10."""

    @property
    def manifest(self) -> PluginManifest:  # pragma: no cover – simple property
        return PluginManifest(protocol="num", type="number", min_value=1, max_value=10)

    def load_value(self, protocol_value: str):  # noqa: D401 – simple loader
        return float(protocol_value)


def test_plugin_min_max(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "parameters": [
            {
                "namespace": None,
                "name": "threshold",
                "type": "number",
                "required": True,
                "protocol": "num",
            },
        ],
        "handle_protocol": True,
    }

    # Happy path – within bounds
    cfg_ok = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"threshold": "num://5"}},
        plugins=[BoundedNumberPlugin()],
    )
    result = cfg_ok.process([])
    assert result._config["default"]["threshold"] == 5

    # Out of bounds – should raise
    cfg_bad = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"threshold": "num://15"}},
        plugins=[BoundedNumberPlugin()],
    )
    with pytest.raises(ValueError):
        cfg_bad.process([])


def test_edge_case_boolean_and_number_parsing(monkeypatch: pytest.MonkeyPatch):
    """Ensure automatic type coercion handles booleans/numbers and complaints on bad input."""

    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": None, "name": "enabled", "type": "boolean", "required": True},
            {"namespace": None, "name": "retries", "type": "number", "required": True},
        ],
    }

    # Valid coercions
    cfg_ok = _prepare_config(
        spec,
        monkeypatch,
        env_data={
            "default": {
                "enabled": "yes",  # → True
                "retries": "3",  # → 3
            }
        },
    )
    result = cfg_ok.process([])
    assert result._config["default"]["enabled"] is True
    assert result._config["default"]["retries"] == 3

    # Invalid number → ValueError
    cfg_bad = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"enabled": "no", "retries": "three"}},
    )
    with pytest.raises(ValueError):
        cfg_bad.process([])


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


def test_sensitive_protocol_requires_obfuscation(
    sensitive_plugin: SensitiveDummyPlugin,
):
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


def test_obfuscate_numeric_and_reveal():
    enc = EncryptionManager()
    token = enc.obfuscate(42)
    assert token.startswith("obfuscated:")
    assert enc.reveal(token) == "42"


def test_reveal_rejects_non_string():
    enc = EncryptionManager()
    with pytest.raises(ValueError, match="must be a string"):
        enc.reveal(123)  # type: ignore[arg-type]


def test_reveal_without_prefix():
    enc = EncryptionManager()
    with pytest.raises(ValueError, match="missing 'obfuscated:'"):
        enc.reveal("plain-text")


def test_reveal_invalid_base64():
    enc = EncryptionManager()
    bad = "obfuscated:not-base64-***"
    with pytest.raises(ValueError, match="Invalid base64"):
        enc.reveal(bad)


def test_reveal_too_short_encrypted_data():
    enc = EncryptionManager()
    short = "obfuscated:" + base64.b64encode(secrets.token_bytes(10)).decode()
    with pytest.raises(ValueError, match="too short"):
        enc.reveal(short)


def test_reveal_decryption_failure():
    enc = EncryptionManager()
    bogus = secrets.token_bytes(16 + 32)  # 16‑byte IV + random ciphertext
    token = "obfuscated:" + base64.b64encode(bogus).decode()
    with pytest.raises(ValueError, match="Failed to decrypt"):
        enc.reveal(token)


def test_obfuscation_applied_from_each_source(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "precedence": ["env", "rc", "args"],
        "parameters": [
            {
                "namespace": None,
                "name": "token",
                "type": "string",
                "required": True,
                "obfuscated": True,
            },
        ],
    }

    cfg = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"token": "plain"}},
    )
    result = cfg.process([])
    stored = result._config["default"]["token"]
    assert stored != "plain"
    assert cfg.encryption.reveal(stored) == "plain"


def test_value_precedence_all_sources(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "precedence": ["rc", "env", "args"],
        "parameters": [
            {"namespace": None, "name": "host", "type": "string", "required": True},
        ],
    }

    cfg = _prepare_config(
        spec,
        monkeypatch,
        args_data={"param_default_host": "from-args"},
        rc_data={"default": {"host": "from-rc"}},
        env_data={"default": {"host": "from-env"}},
    )
    res = cfg.process([])
    assert res._config["default"]["host"] == "from-rc"  # rc wins


def test_configuration_processes_protocol_value_basic(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "myapp",
        "handle_protocol": True,
        "parameters": [
            {
                "name": "password",
                "namespace": "db",
                "obfuscated": True,
                "protocol": "dummy",
                "type": "string",
                "required": True,
            },
            {"namespace": "app", "name": "timeout", "type": "number", "default": 30},
        ],
    }

    args = ["--db.password", "dummy://my-db-pass"]

    cfg = _prepare_config(
        spec,
        monkeypatch,
        argv=args,
        args_data={"param_db_password": "dummy://my-db-pass"},
        plugins=[DummyPlugin()],
    )
    result = cfg.process(args)

    stored = result.db.password  # type: ignore[attr-defined]
    assert stored.startswith("obfuscated:")
    assert cfg.reveal(stored) == "resolved_value:my-db-pass"


def test_mixed_required_and_optional_positional(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "arguments": [
            {"name": "src", "type": "string", "required": True},
            {"name": "dst", "type": "string", "required": False},
        ],
    }

    # Provide both positional args
    cfg = _prepare_config(
        spec,
        monkeypatch,
        args_data={"src": "input.txt", "dst": "out.txt"},
    )
    res = cfg.process([])
    assert res._config["arguments"]["src"] == "input.txt"
    assert res._config["arguments"]["dst"] == "out.txt"

    # Provide only required positional
    cfg2 = _prepare_config(
        spec,
        monkeypatch,
        args_data={"src": "only.txt"},
    )
    res2 = cfg2.process([])
    assert res2._config["arguments"]["src"] == "only.txt"
    assert res2._config["arguments"].get("dst") is None  # optional arg left unset

    # Omit required → should raise
    with pytest.raises(ValueError):
        cfg3 = _prepare_config(spec, monkeypatch, args_data={})
        cfg3.process([])


def test_missing_plugin(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "handle_protocol": True,
        "parameters": [
            {
                "namespace": None,
                "name": "value",
                "type": "string",
                "required": True,
                "protocol": "dummy",
            },
        ],
    }

    with pytest.raises(ValueError, match="Required protocol 'dummy' is not registered"):
        Configuration(spec)  # Validator triggers during init


def test_wrong_protocol_used(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "handle_protocol": True,
        "parameters": [
            {
                "namespace": None,
                "name": "value",
                "type": "string",
                "required": True,
                "protocol": "dummy",
            },
        ],
    }

    cfg = _prepare_config(
        spec,
        monkeypatch,
        env_data={"default": {"value": "other://hello"}},
        plugins=[DummyPlugin()],
    )
    with pytest.raises(ValueError, match="requires protocol"):
        cfg.process([])


def test_error_when_tomllib_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(loaders, "tomllib", None, raising=False)

    spec = {
        "app_name": "c3a3",
        "precedence": ["rc"],
        "parameters": [
            {"namespace": None, "name": "username", "type": "string", "required": True},
        ],
    }

    rc_path = tmp_path / ".c3a3rc"
    rc_path.write_text('[default]\nusername="bob"\n')
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    cfg = _prepare_config(spec, monkeypatch, rc_data={})
    with pytest.raises(ValueError):
        cfg.process([])


def test_type_checking_true(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(loaders, "TYPE_CHECKING", True, raising=False)

    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": None, "name": "flag", "type": "boolean", "required": True},
        ],
    }

    cfg = _prepare_config(spec, monkeypatch, env_data={"default": {"flag": "yes"}})
    res = cfg.process([])
    assert res._config["default"]["flag"] is True


def test_env_loader_with_namespace(monkeypatch: pytest.MonkeyPatch):
    """Environment variable name format should be <APP>_<NAMESPACE>_<NAME>."""
    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": "db", "name": "user", "type": "string", "required": True},
        ],
    }
    monkeypatch.setenv("C3A3_DB_USER", "admin")
    cfg = Configuration(spec)
    env_values = cfg.env_loader.load()
    assert env_values == {"db": {"user": "admin"}}


def test_rc_loader_reads_toml(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """RCLoader should parse a TOML rc file in the user's home directory."""
    rc_content = """[default]
api_key = 'abc123'
"""
    rc_file = tmp_path / ".c3a3rc"
    rc_file.write_text(rc_content)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    spec = {
        "app_name": "c3a3",
        "precedence": ["rc"],
        "parameters": [
            {"namespace": None, "name": "api_key", "type": "string", "required": True},
        ],
    }
    cfg = Configuration(spec)
    rc_loaded = cfg.rc_loader.load()
    assert rc_loaded == {"default": {"api_key": "abc123"}}


def test_plugin_manager_duplicate_registration():
    """Registering a plugin twice for the same protocol should raise."""

    class P(ConfigPlugin):
        @property
        def manifest(self):
            return PluginManifest(protocol="dup", type="string")

        def load_value(self, protocol_value: str):
            return protocol_value

    pm = Configuration({"app_name": "dupapp"}).plugin_manager
    pm.register_plugin(P())
    with pytest.raises(ValueError, match="already registered"):
        pm.register_plugin(P())  # duplicate


def test_plugin_value_out_of_range():
    """Numeric value outside plugin range should fail validation."""

    class NumPlugin(ConfigPlugin):
        @property
        def manifest(self):
            return PluginManifest(
                protocol="num", type="number", min_value=10, max_value=20
            )

        def load_value(self, protocol_value: str):
            return int(protocol_value)

    cfg = Configuration({"app_name": "rangeapp"}, plugins=[NumPlugin()])
    pm = cfg.plugin_manager
    # Below range
    with pytest.raises(ValueError, match="less than minimum"):
        pm.load_protocol_value("num://5", expected_type="number")
    # Above range
    with pytest.raises(ValueError, match="exceeds maximum"):
        pm.load_protocol_value("num://25", expected_type="number")


def test_configuration_result_export_and_debug(capsys):
    """export_json returns valid JSON and debug prints expected lines."""
    from config_loader.result import ConfigurationResult

    data = {"default": {"x": 1}, "app": {"flag": True}}
    debug_info = {"default.x": "env", "app.flag": "args"}
    res = ConfigurationResult(data, debug_info)

    json_str = res.export_json()
    assert '"x": 1' in json_str
    assert '"flag": true' in json_str.lower()

    res.debug()
    captured = capsys.readouterr().out
    assert "default.x: 1 (from env)" in captured
    assert "app.flag: True (from args)" in captured


def test_rc_loader_returns_empty_when_file_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """RCLoader.load should return {{}} if rc file does not exist."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    spec = {
        "app_name": "c3a3",
        "precedence": ["rc"],
        "parameters": [
            {"namespace": None, "name": "x", "type": "string"},
        ],
    }
    cfg = Configuration(spec)
    assert cfg.rc_loader.load() == {}


class _BadLenPlugin(ConfigPlugin):
    @property
    def manifest(self):
        # Invalid: number type with length constraints
        return PluginManifest(protocol="badlen", type="number", min_length=1)

    def load_value(self, protocol_value: str):
        return int(protocol_value)


def test_plugin_manifest_invalid_constraints():
    cfg = Configuration({"app_name": "badlenapp"})
    with pytest.raises(
        ValueError, match="Length constraints only valid for string type"
    ):
        cfg.plugin_manager.register_plugin(_BadLenPlugin())


class _StringLenPlugin(ConfigPlugin):
    @property
    def manifest(self):
        return PluginManifest(protocol="strlen", type="string", min_length=5)

    def load_value(self, protocol_value: str):
        return protocol_value


def test_plugin_validate_constraints_string_length():
    p = _StringLenPlugin()
    # Value too short triggers manifest.validate_constraints via plugin method
    with pytest.raises(ValueError, match="less than minimum"):
        p.validate_constraints("abc")


def test_plugin_manager_parse_protocol_value():
    cfg = Configuration({"app_name": "protoapp"})
    pm = cfg.plugin_manager
    assert pm.parse_protocol_value("proto://val") == ("proto", "val")
    with pytest.raises(ValueError):
        pm.parse_protocol_value("not-a-protocol")


def test_parse_value_boolean_and_number():
    cfg = Configuration({"app_name": "parseapp"})
    assert cfg._parse_value("True", "boolean") is True  # noqa: SLF001
    assert cfg._parse_value("3.14", "number") == 3.14  # noqa: SLF001
    with pytest.raises(ValueError):
        cfg._parse_value("abc", "number")  # noqa: SLF001


def test_validator_duplicate_and_invalid_boolean_accepts():
    # Duplicate param names and boolean with accepts
    spec = {
        "app_name": "dupapp",
        "parameters": [
            {"namespace": None, "name": "dup", "type": "string"},
            {"namespace": None, "name": "dup", "type": "string"},  # duplicate
            {
                "namespace": None,
                "name": "flag",
                "type": "boolean",
                "accepts": [True, False],
            },
        ],
    }
    with pytest.raises(ValueError, match="Configuration specification errors"):
        Configuration(spec)


def test_validator_required_arg_after_optional():
    spec = {
        "app_name": "argorder",
        "arguments": [
            {"name": "opt", "type": "string", "required": False},
            {"name": "req", "type": "string", "required": True},  # illegal ordering
        ],
    }
    with pytest.raises(ValueError, match="cannot follow optional arguments"):
        Configuration(spec)


def test_result_export_json_and_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """ConfigurationResult.export_json() and debug() should include resolved values."""

    spec = {
        "app_name": "c3a3",
        "parameters": [
            {
                "namespace": None,
                "name": "path",
                "type": "string",
                "default": "/tmp/data",
            },
            {"namespace": None, "name": "flag", "type": "boolean", "default": False},
        ],
    }

    cfg = _prepare_config(spec, monkeypatch)
    result = cfg.process([])

    exported = result.export_json()  # type: ignore[attr-defined]
    assert '"path": "/tmp/data"' in exported
    assert '"flag": false' in exported

    # debug() prints to stdout; capture it
    result.debug()  # type: ignore[attr-defined]
    captured = capsys.readouterr().out
    assert "Configuration Debug Information" in captured
    assert "path: /tmp/data" in captured


def test_arg_loader_parses_dash_names(monkeypatch: pytest.MonkeyPatch):
    """ArgLoader should convert ``--namespace.name`` CLI options correctly."""
    argv = [
        "prog",
        "--server.host",
        "localhost",
        "--db.password",
        "secret",
    ]
    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": "server", "name": "host", "type": "string", "required": True},
            {"namespace": "db", "name": "password", "type": "string", "required": True},
        ],
    }
    cfg = Configuration(spec)
    args_map = cfg.arg_loader.load(argv)  # type: ignore[arg-type]
    assert args_map["param_server_host"] == "localhost"
    assert args_map["param_db_password"] == "secret"
    # debug flag may be auto‑added by parser defaults
    assert args_map.get("debug") in (True, False)


def test_validator_invalid_type_and_accepts_length():
    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": None, "name": "foo", "type": "unsupported"},
            {
                "namespace": None,
                "name": "color",
                "type": "string",
                "accepts": ["red"],
            },  # too short
        ],
    }
    with pytest.raises(ValueError, match="Configuration specification errors"):
        Configuration(spec)


def test_env_loader_ignores_unmatched_env_vars(monkeypatch: pytest.MonkeyPatch):
    spec = {
        "app_name": "c3a3",
        "parameters": [
            {"namespace": None, "name": "foo", "type": "string", "required": False},
        ],
    }
    # Set a variable that looks similar but doesn't match the expected prefix
    monkeypatch.setenv("C3A3X_FOO", "BAR")
    cfg = Configuration(spec)
    env_map = cfg.env_loader.load()
    # Should be empty because prefix mismatched
    assert env_map == {}


def test_rc_loader_when_file_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    spec = {"app_name": "c3a3"}
    cfg = Configuration(spec)
    assert cfg.rc_loader.load() == {}


class BadLenPlugin(ConfigPlugin):
    @property
    def manifest(self) -> PluginManifest:  # type: ignore[override]
        # min_length greater than max_length should be rejected by validation
        return PluginManifest(protocol="len", type="string", min_length=5, max_length=3)

    def load_value(self, protocol_value: str):
        return protocol_value


def test_plugin_manifest_invalid_length():
    pm = Configuration({"app_name": "len"}).plugin_manager
    with pytest.raises(ValueError, match="min_length.*greater than max_length"):
        pm.register_plugin(BadLenPlugin())


def test_validator_duplicate_and_bad_precedence():
    spec = {
        "app_name": "c3a3",
        "precedence": ["args", "file"],  # invalid source 'file'
        "parameters": [
            {"namespace": None, "name": "dup", "type": "string"},
            {"namespace": None, "name": "dup", "type": "string"},  # duplicate
        ],
    }
    with pytest.raises(
        ValueError, match="Invalid precedence values|Duplicate parameter"
    ):
        Configuration(spec)
