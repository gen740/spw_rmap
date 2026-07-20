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
- `SPWRMAP_BUILD_TESTS` (default `OFF`): add the `tests` subdirectory and register the GTest suite.
- `SPWRMAP_BUILD_PYTHON_BINDINGS` (default `OFF`): build the pybind11 module (also enabled when using `pyproject.toml` / `scikit-build-core`).

## Testing

```bash
cmake -S . -B build -DSPWRMAP_BUILD_TESTS=ON
cmake --build build --target spwrmap_tests
ctest --test-dir build --output-on-failure
```

The C++ suite covers packet round trips and malformed input, CRC failures, builder bounds, synchronous and asynchronous node behavior, transaction-ID lifecycle and concurrency, TCP reconnects, and timeout behavior. Some TCP tests require the ability to bind a local port; they are skipped automatically when the environment forbids that operation.

To run the same undefined-behavior checks used by CI:

```bash
cmake -S . -B build-ubsan -G Ninja \
  -DSPWRMAP_BUILD_TESTS=ON \
  -DSPWRMAP_BUILD_APPS=OFF \
  -DCMAKE_CXX_FLAGS=-fsanitize=undefined \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined
cmake --build build-ubsan
ctest --test-dir build-ubsan --output-on-failure
```

GitHub Actions runs the regular C++ suite, the UBSan suite, and Python binding smoke tests for every push and pull request.

## Python bindings

To build the wheel:

```bash
python -m pip install .  # uses pyproject + scikit-build-core
```

The resulting package exposes a synchronous subset of the C++ API through `_core.SpwRmapTCPNode`.

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

## Threading and connection behavior

- `TCPClient` serializes connect, disconnect, send, receive, timeout configuration, and shutdown operations around its socket descriptor. A receive timeout returns `std::errc::timed_out` without discarding an otherwise healthy TCP connection; peer closure and hard socket errors still disconnect it.
- Auto-polling mode serializes synchronous `Read` and `Write` calls. It intentionally rejects `ReadAsync` and `WriteAsync` with `std::errc::operation_not_permitted`.
- Outside auto-polling mode, asynchronous operations require the application to run `Poll()` or `RunLoop()` to dispatch replies. Do not run multiple polling loops for the same node.
- `Shutdown()` ends the current client lifecycle. Calls such as `EnsureTcpConnection()` after the backend has been released return `std::errc::not_connected`.

## Protocol limits

- `TargetNode` supports at most 12 target-path bytes and 12 reply-path bytes.
- RMAP command data lengths are encoded in 24 bits. Builders reject values larger than `0xFFFFFF`.
- Builder functions return `std::errc::no_buffer_space` when the caller-provided output span is too small.

## Timeouts and Error Handling

- `Write` / `Read` accept a `timeout` (default 100 ms). When the timeout expires the pending transaction is cancelled internally, its transaction ID is released, and the call returns `std::errc::timed_out`. This prevents deadlocks when a remote node never replies.

- Asynchronous callbacks run inside the polling loop. If a function you pass to `WriteAsync` / `ReadAsync` throws, the library catches and logs the exception so the loop stays alive—wrap your callback body in your own error handling if you need to mark the operation successful despite local issues.

Python bindings currently offer only synchronous `read`/`write` methods, do not release the GIL around blocking I/O, and provide no built-in async wrapper.

## Known limitations

- Python read/write timeouts are currently fixed at 100 ms, and the binding does not expose an explicit `shutdown()` method or context-manager protocol. Destruction closes the socket.
- Synchronous C++ `Read`/`Write` validate reply type, transaction ID, and length, but currently do not convert a non-zero RMAP reply status into an error. Async users can inspect `Packet::status` directly.
- `Packet` payload and address fields are non-owning spans into parser or receive buffers. Callbacks must copy data they need to retain after the callback returns.
- Auto-resizing receive buffers trust the frame length advertised by the TCP peer; deployments that accept untrusted peers should use a fixed buffer policy until a configurable maximum frame size is added.
- Span and initializer-list address setters on `TargetNode` require the caller to respect the 12-byte limit; this is enforced by an assertion in debug builds.
- CI uses loopback TCP peers and synthetic RMAP frames. Hardware-in-the-loop coverage, parser fuzzing, and ThreadSanitizer coverage are not yet included.

The [examples](examples) directory contains CLI programs that parse command-line arguments, manage the lifecycle for you, and show additional patterns (speed tests, multi-target setups, etc.).
