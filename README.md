# c3a3‑config‑loader

[![Coverage](https://img.shields.io/badge/coverage-80%25-brightgreen.svg)](./tests)
[![Python](https://img.shields.io/pypi/pyversions/c3a3-config-loader.svg)](https://pypi.org/project/c3a3-config-loader/)

> **Seamless, pluggable configuration for modern Python apps — merge CLI/ENV/RC, validate & decrypt secrets in one line.**

---

## Why?

Reading configuration shouldn’t require boilerplate. **`c3a3‑config‑loader`** lets you declare a tiny TOML‑like spec and automatically:

* Parse **command‑line** arguments (`--db.password`) with positional support.
* Pull values from **environment variables** (`C3A3_DB_PASSWORD`).
* Fall back to a per‑user **rc‑file** (`~/.c3a3rc`) in TOML or INI.
* Respect a deterministic **precedence** order you choose.
* **Validate** types, required flags, allowed values & numeric ranges.
* **Obfuscate** or **reveal** sensitive values using AES‑256.
* **Extend** via **plugins** (e.g. `vault://secret`) with size/charset constraints.

All in a 100% type‑annotated, 80%+ test‑covered library.

---

## Installation

```bash
pip install c3a3-config-loader
```

> Requires **Python≥3.9**.  Binary wheels ship with \[cryptography] so no external libs.

---

## Quick start

### Automatic Configuration Loading (New!)

The easiest way to get started is with automatic configuration loading:

```python
from config_loader.main import load_config_auto

# Automatically loads script_name.json or script_name.yaml
cfg = load_config_auto()
result = cfg.process()  # auto‑reads sys.argv, os.environ, ~/.c3a3rc

print(result.db.password)               # ➔ "obfuscated:..."
print(cfg.reveal(result.db.password))   # ➔ "my‑secret"
print(result.mode)                      # ➔ "prod"
```

Create a configuration file named after your script (e.g., `myapp.json` for `myapp.py`):

```json
{
    "schema_version": "1.0",
    "app_name": "myapp",
    "precedence": ["args", "env", "rc"],
    "parameters": [
        {"namespace": "db", "name": "password", "type": "string", "required": true, "obfuscated": true},
        {"namespace": null, "name": "mode", "type": "string", "default": "prod", "accepts": ["dev", "prod"]},
        {"namespace": "app", "name": "timeout", "type": "number", "min": 1, "max": 60, "default": 30}
    ]
}
```

### Manual Configuration (Traditional)

```python
from config_loader.main import Configuration

spec = {
    "app_name": "c3a3",               # affects env‑var prefix & rc file name
    "precedence": ["args", "env", "rc"],  # CLI wins, env next, then rc
    "parameters": [
        {"namespace": "db", "name": "password", "type": "string", "required": True, "obfuscated": True},
        {"namespace": None, "name": "mode", "type": "string", "default": "prod", "accepts": ["dev", "prod"]},
        {"namespace": "app", "name": "timeout", "type": "number", "min": 1, "max": 60, "default": 30},
    ],
}

cfg = Configuration(spec)
result = cfg.process()  # auto‑reads sys.argv, os.environ, ~/.c3a3rc

print(result.db.password)               # ➔ "obfuscated:..."
print(cfg.reveal(result.db.password))   # ➔ "my‑secret"
print(result.mode)                      # ➔ "prod"
```

### Command‑line invocation

```bash
python app.py --db.password my‑secret --mode dev
```

### Environment variables

```bash
export C3A3_DB_PASSWORD=my‑secret
```

### RC file (`~/.c3a3rc`)

```toml
[default]
mode = "dev"
```

---

## New Features

### YAML Support

Configuration files can now be written in YAML format alongside JSON:

```yaml
schema_version: "1.0"
app_name: myapp
precedence:
  - args
  - env
  - rc
parameters:
  - namespace: db
    name: password
    type: string
    required: true
    obfuscated: true
  - namespace: null
    name: mode
    type: string
    default: prod
    accepts:
      - dev
      - prod
```

The system automatically detects and loads `.json`, `.yaml`, or `.yml` files.

### Schema Validation

All configuration files must now include a `schema_version` field and conform to the defined JSON schema. This ensures:

* **Structure validation**: Required fields, correct data types, valid enum values
* **Version compatibility**: Forward/backward compatibility handling
* **Error reporting**: Clear validation error messages

Supported schema versions: `1.0`, `1.0.0`

---

## Plugins

Implement `ConfigPlugin` to fetch protocol values from anywhere:

```python
from config_loader.plugin_interface import ConfigPlugin, PluginManifest

class VaultPlugin(ConfigPlugin):
    @property
    def manifest(self):
        return PluginManifest(protocol="vault", type="string")

    def load_value(self, protocol_value: str):
        # e.g. call HashiCorp Vault
        return vault_client.read(protocol_value)
```

Register at `Configuration(..., plugins=[VaultPlugin()])` and list `protocol:"vault"` in a parameter.

---

## Coverage & quality

* **Tests:** 40+pytest cases, **80%** overall coverage
* **Type‑checking:** `mypy --strict -p config_loader`
* **Lint:** `ruff check --fix`

---

## Development

```bash
git clone https://github.com/your‑org/c3a3‑config_loader.git
cd c3a3‑config_loader
python -m pip install -e .[dev]
pytest -q  # run test suite
```

Pull requests welcome — please include tests and pass CI.

---

## License

SPDX-License-Identifier: Prosperity-3.0.0
© 2025 ã — see LICENSE.md for terms.
