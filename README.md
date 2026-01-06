# spw_rmap

`spw_rmap` is a SpaceWire/RMAP helper library that provides packet builders/parsers, a TCP transport, CLI utilities, and Python bindings.

## Building

```bash
cmake -S . -B build
cmake --build build
```

Key CMake options:

- `SPWRMAP_BUILD_APPS` (default `ON`): build the `spwrmap` and `spwrmap_speedtest` CLI tools.
- `SPWRMAP_BUILD_EXAMPLES` (default `OFF`): enable examples under `examples/`.
- `SPWRMAP_BUILD_TESTS` (default `ON`): add the `tests` subdirectory and register the GTest suite.
- `SPWRMAP_BUILD_PYTHON_BINDINGS` (default `OFF`): build the pybind11 module (also enabled when using `pyproject.toml` / `scikit-build-core`).

## Testing

```bash
cmake --build build --target spwrmap_tests
cd build
ctest --output-on-failure
```

Some TCP tests require the ability to bind a local port; they will be skipped automatically when the environment forbids that operation (e.g., in sandboxed CI).

## Python bindings

To build the wheel:

```bash
python -m pip install .  # uses pyproject + scikit-build-core
```

The resulting package exposes `_core.SpwRmapTCPNode` mirroring the C++ API.

## Key Concepts

- `target_node`: abstraction describing a SpaceWire node address (logical address, SpaceWire hop list, reply path). Implemented by `spw_rmap::TargetNode`, which stores up to 12 hops for both the outbound and reply paths.
- `tcp_node`: the SpaceWire-over-TCP bridge (`SpwRmapTCPClient`/`SpwRmapTCPServer`) that owns the sockets, buffers, and RMAP transaction management.
- `Write` / `Read`: synchronous helpers that perform the transaction, block until a reply arrives (or timeout happens), and return `std::expected` success/error codes.
- `WriteAsync` / `ReadAsync`: asynchronous variants that immediately return the reserved transaction ID (inside `std::expected`) and invoke a user-supplied callback once the reply or error is available, enabling low-latency event handling without blocking the caller.

See `examples/spwrmap_example_sync.cc`, `examples/spwrmap_example_async.cc` (C++), and `examples/spwrmap_example.py` (Python) for minimal workflows demonstrating how to connect, construct a target node, and issue read/write RMAP commands.

# Quick Start Guide

## C++

### Initialize spw

```cpp
#include <chrono>
#include <expected>
#include <memory>
#include <thread>
#include <vector>

#include <spw_rmap/spw_rmap_tcp_node.hh>
#include <spw_rmap/target_node.hh>

int main() {
  using namespace std::chrono_literals;

  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = "127.0.0.1", .port = "10030"});

  client.SetInitiatorLogicalAddress(0xFE);
  client.Connect(500ms).value();  // abort on failure

  std::thread loop([&client] {
    auto res = client.RunLoop();
    if (!res) {
      throw std::system_error(res.error());
    }
  });

  // ...

  auto shutdown_res = client.Shutdown();
  if (!shutdown_res.has_value()) {
    throw std::system_error(shutdown_res.error());
  }
  if (loop.joinable()) {
    loop.join();
  }
}
```

You can also call `Poll()` manually from your own loop instead of spawning a thread.

### Creating target node

```cpp
spw_rmap::TargetNode target(0x34);
target.SetTargetAddress(3, 5, 7);              // SpaceWire hops
target.SetReplyAddress(9, 11, 13, 0x00);       // Reply path (zero-padded)
```

### Read and write

```cpp
std::array<uint8_t, 4> write_payload{0x12, 0x34, 0x56, 0x78};
client.Write(target, /*address=*/0x20000000, write_payload).value();

std::array<uint8_t, 4> read_buffer{};
client.Read(target, 0x20000000, std::span(read_buffer)).value();

auto read_transaction =
    client
        .ReadAsync(
            target, 0x20000000, /*length=*/4,
            [](std::expected<spw_rmap::Packet, std::error_code> packet) {
              if (!packet) {
                std::cerr << "Async read failed: " << packet.error().message()
                          << '\n';
                return;
              }
              std::cout << "Async read returned "
                        << packet->data.size() << " bytes\n";
            })
        .value();

auto write_transaction =
    client
        .WriteAsync(
            target, 0x20000000, std::span(write_payload),
            [](std::expected<spw_rmap::Packet, std::error_code> packet) {
              if (!packet) {
                std::cerr << "Async write failed: " << packet.error().message()
                          << '\n';
                return;
              }
              std::cout << "Async write acknowledged (TID "
                        << packet->transaction_id << ")\n";
            })
        .value();

std::cout << "Read TID: " << read_transaction
          << ", Write TID: " << write_transaction << '\n';
```

`Write`/`Read` are *synchronous*: they transmit the command, block until a reply is parsed (or the timeout fires), and return `std::expected`.  
`WriteAsync`/`ReadAsync` are *asynchronous*: they enqueue the transaction, immediately return the reserved transaction ID (inside `std::expected<uint16_t, std::error_code>`), and invoke the supplied callback as soon as the reply arrives—allowing low-latency event handling without blocking.

## Python

### Initialize spw

```python
from pyspw_rmap import _core as spw

node = spw.SpwRmapTCPNode("127.0.0.1", "10030")
node.connect()  # opens the TCP connection; no worker thread is spawned
```

The bindings now run in an auto-polling mode, so there is no `start()`/`stop()` pair or internal polling thread. Once connected, synchronous `read`/`write` calls send a command and block until the reply is parsed (or a timeout/error occurs).

### Creating target node

```python
target = spw.TargetNode()
target.logical_address = 0x34
target.target_spacewire_address = [3, 5, 7]
target.reply_address = [9, 11, 13, 0]
```

### Read and write

```python
# blocking write/read; no async API is exposed in Python
node.write(target, 0x20000000, [0x12, 0x34, 0x56, 0x78])
data = node.read(target, 0x20000000, 4)
print("sync read:", list(data))
```

Destroy the `SpwRmapTCPNode` instance (or let it go out of scope) when you are done—the underlying socket is closed automatically.
If you prefer explicit lifecycle management, follow `examples/spwrmap_example.py`, which wraps the connection in a context manager to pair `connect()`/cleanup deterministically.

## Timeouts and Error Handling

- `Write` / `Read` accept a `timeout` (default 100 ms). When the timeout expires the pending transaction is cancelled internally, its transaction ID is released, and the call returns `std::errc::timed_out`. This prevents deadlocks when a remote node never replies.

- Asynchronous callbacks run inside the polling loop. If a function you pass to `WriteAsync` / `ReadAsync` throws, the library catches and logs the exception so the loop stays alive—wrap your callback body in your own error handling if you need to mark the operation successful despite local issues.

Python bindings currently offer only synchronous `read`/`write` methods. To parallelize operations you must call them from your own threads or processes; there is no built-in async wrapper.

The [examples](examples) directory contains CLI programs that parse command-line arguments, manage the lifecycle for you, and show additional patterns (speed tests, multi-target setups, etc.).
