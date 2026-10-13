# Vendored Tomli 2.2.1

Pure-Python TOML 1.0 parser, MIT licensed, Python >=3.8 (including Python 3.9).
Only the four parser Python files and LICENSE are retained, byte-identical to
the published pure-Python wheel. No setup/build hook, installer, or compiled
extension was executed. No global dependency installation is required.

- Project: https://pypi.org/project/tomli/2.2.1/
- Published metadata: https://pypi.org/pypi/tomli/2.2.1/json
- Source wheel: https://files.pythonhosted.org/packages/6e/c2/61d3e0f47e2b74ef40a68b9e6ad5984f6241a942f7cd3bbfbdbd03861ea9/tomli-2.2.1-py3-none-any.whl
- Wheel size: 14257 bytes
- Published and downloaded SHA-256: `cb55c73c5f4408779d0cf3eef9f762b9c9f147a77de7b258bef0a5628adc85cc`
- Metadata license: MIT; full upstream license is retained in LICENSE.

The runtime policy imports this namespaced copy explicitly (`vendor.tomli`),
never an ambient package. It uses only `loads`, never `load`; TOML bytes remain
private in memory and are never normalized or written by the classifier.
