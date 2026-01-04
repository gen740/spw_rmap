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

node = SpwRmapTCPNode(ip_address="192.168.1.100", port="10030")

node.write(target, 0x44A200D4, [0, 0, 0, 1])
data = node.read(target, 0x44A200D0, 4)
print(list(data))
```

- `TargetNode` represents the destination node (logical address, hop list, and return path).
- `SpwRmapTCPNode` owns the SpaceWire-over-TCP connection and performs the request/reply handshake.
- Calls are synchronous: they block until a reply frame is parsed or the default timeout elapses. Catch the raised exception to handle transport or timeout errors explicitly.

Destroy the node (or let it go out of scope) to close the TCP connection. You can also call `node.shutdown()` manually when deterministic teardown is required.

## Building from source

If you prefer installing from a checkout, clone the main repository and let `pip` build the wheel locally:

```bash
python -m pip install .
```

The build steps mirror the ones documented in the root `README.md`. The `pyspw_rmap` wheel bundles the Python module, the C++ extension, and the CLI entry points, so no extra copy steps are required after `pip` finishes.
