# pyspw_rmap

`pyspw_rmap` provides Python bindings and CLI tooling for the `spw_rmap` SpaceWire/RMAP helper library. It exposes the same TCP client that the C++ API uses, so you can connect to a SpaceWire-over-TCP bridge, describe a target node, and issue synchronous `read`/`write` transactions from pure Python.

## Installation

The package is published as a `scikit-build-core` wheel, so CMake, Ninja (or another generator), and a C/C++ compiler must be available. Once the build prerequisites are satisfied, install it like any other PyPI package:

```bash
python -m pip install pyspw_rmap
```

Command-line helpers are included automatically and become available as `spwrmap` and `spwrmap_speedtest`.

## Quick start

```python
from pyspw_rmap import TargetNode, SpwRmapTCPNode

target = TargetNode(
    logical_address=0x32,
    target_spacewire_address=[0x06, 0x02],
    reply_address=[0x01, 0x03],
)

with SpwRmapTCPNode(ip_address="192.168.1.100", port="10030") as node:
    node.connect()
    node.write(target, 0x44A200D4, [0, 0, 0, 1])
    data = node.read(target, 0x44A200D0, 4)
    print(list(data))
```

- `TargetNode` represents the destination node (logical address, hop list, and return path).
- `SpwRmapTCPNode` owns the SpaceWire-over-TCP connection and performs the request/reply handshake.
- Calls are synchronous: they block until a reply frame is parsed or the default 100 ms timeout elapses. Pass `timeout=` to `read` or `write` to override it. Catch the raised exception to handle transport or timeout errors explicitly.
- Blocking calls release the Python GIL, so other Python threads can run while a request is in flight. The binding does not provide an `asyncio` wrapper.

Call `disconnect()` to close the TCP connection explicitly, or use the context manager as shown above. Destruction also closes the connection.

## Building from source

If you prefer installing from a checkout, clone the main repository and let `pip` build the wheel locally:

```bash
python -m pip install .
```

The build steps mirror the ones documented in the root `README.md`. The `pyspw_rmap` wheel bundles the Python module, the C++ extension, and the CLI entry points, so no extra copy steps are required after `pip` finishes.

## Testing a source build

After installing the checkout, run the binding smoke tests with:

```bash
python -m unittest tests/test_python_bindings.py
```

These tests cover module import, target-node field conversion, client construction and context management, and the debug-control functions. They do not require a SpaceWire-over-TCP server.
