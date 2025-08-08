import json
from pathlib import Path

import pytest

from config_loader.main import load_config_auto, Configuration


MINIMAL_CONFIG = {
    "schema_version": "1.0",
    "app_name": "myapp",
    "parameters": [],
}


def _setup_script(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, script_name: str = "myscript") -> None:
    # make CWD the temp dir and set argv[0] so loader looks for myscript.* in CWD
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PWD", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOMEPATH", str(tmp_path))
    monkeypatch.setenv("HOMEDRIVE", str(tmp_path.drive) if hasattr(tmp_path, "drive") else "")
    monkeypatch.setenv("CI", "true")
    # Set argv to a plausible value
    monkeypatch.setattr("sys.argv", [str(tmp_path / f"{script_name}.py")])


def test_load_config_auto_json_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_script(monkeypatch, tmp_path, script_name="myscript")

    cfg_path = tmp_path / "myscript.json"
    cfg_path.write_text(json.dumps(MINIMAL_CONFIG), encoding="utf-8")

    cfg = load_config_auto()
    assert isinstance(cfg, Configuration)
    assert cfg.app_name == "myapp"


def test_load_config_auto_yaml_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    yaml = pytest.importorskip("yaml")
    _setup_script(monkeypatch, tmp_path, script_name="myscript")

    cfg_path = tmp_path / "myscript.yaml"
    cfg_path.write_text(yaml.safe_dump(MINIMAL_CONFIG), encoding="utf-8")

    cfg = load_config_auto()
    assert isinstance(cfg, Configuration)
    assert cfg.app_name == "myapp"


def test_load_config_auto_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_script(monkeypatch, tmp_path, script_name="myscript")

    with pytest.raises(FileNotFoundError):
        load_config_auto()


def test_load_config_auto_duplicate_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    yaml = pytest.importorskip("yaml")
    _setup_script(monkeypatch, tmp_path, script_name="myscript")

    # Create both JSON and YAML for the same script name
    (tmp_path / "myscript.json").write_text(json.dumps(MINIMAL_CONFIG), encoding="utf-8")
    (tmp_path / "myscript.yaml").write_text(yaml.safe_dump(MINIMAL_CONFIG), encoding="utf-8")

    with pytest.raises(ValueError):
        load_config_auto()
