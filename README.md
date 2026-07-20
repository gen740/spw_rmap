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
- `SPWRMAP_BUILD_FUZZERS` (default `OFF`): build Clang/libFuzzer targets with AddressSanitizer and UBSan instrumentation.
- `SPWRMAP_ENABLE_TSAN` (default `OFF`): instrument the library and tests with ThreadSanitizer using Clang or GCC.
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

To check the supported concurrent paths for data races:

```bash
cmake -S . -B build-tsan -G Ninja \
  -DSPWRMAP_BUILD_TESTS=ON \
  -DSPWRMAP_BUILD_APPS=OFF \
  -DSPWRMAP_ENABLE_TSAN=ON
cmake --build build-tsan
TSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-tsan --output-on-failure
```

ThreadSanitizer runtime support depends on the compiler and operating system; CI runs this configuration with Clang on Linux.

To build and run the RMAP packet-parser fuzzer:

```bash
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DSPWRMAP_BUILD_APPS=OFF \
  -DSPWRMAP_BUILD_FUZZERS=ON
cmake --build build-fuzz --target parse_rmap_packet_fuzz
build-fuzz/fuzz/parse_rmap_packet_fuzz \
  -max_total_time=30 -timeout=2 -max_len=65536 \
  -dict=fuzz/rmap.dict fuzz/corpus
```

GitHub Actions runs the regular C++ suite, UBSan, TSan, the parser fuzzer, and Python binding smoke tests for every push and pull request.

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
#include <system_error>

#include <spw_rmap/spw_rmap_tcp_node.hh>
#include <spw_rmap/target_node.hh>

int main() {
  using namespace std::chrono_literals;

  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = "127.0.0.1", .port = "10030"});

  client.SetInitiatorLogicalAddress(0xFE);
  client.SetAutoPollingMode(true);
  client.Connect(500ms).value();  // abort on failure

  // Issue synchronous Read/Write calls on this thread.

  auto shutdown_res = client.Shutdown();
  if (!shutdown_res.has_value()) {
    throw std::system_error(shutdown_res.error());
  }
}
```

For asynchronous operation, submit `ReadAsync`/`WriteAsync` calls and use exactly one polling loop to dispatch their replies. Follow the concurrency contract below.

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

The library is not unconditionally thread-safe. The supported combinations are:

| Operations on one node | Concurrent use | Conditions |
|---|---|---|
| `Read` / `Write` in auto-polling mode | Supported | Calls are serialized internally. Do not call `Poll`, `RunLoop`, `ReadAsync`, or `WriteAsync` in this mode. |
| `ReadAsync` / `WriteAsync` / `EmitTimeCode` | Supported | Auto-polling must be off, the connection and configuration must remain unchanged, and caller-owned input objects must remain valid for each call. Transaction allocation and outgoing frame construction are serialized internally. |
| One `Poll` or `RunLoop` plus asynchronous requests or non-auto-polling `Read` / `Write` | Limited support | Use exactly one receive loop. The current `TCPClient` socket lock can delay a send while a blocking receive owns the descriptor lock, so this is not a general full-duplex thread-safety guarantee. |
| Two or more `Poll` / `RunLoop` calls | Not supported | They share one receive buffer and one TCP byte stream. |
| `RegisterOnRead`, `RegisterOnWrite`, or `RegisterOnTimeCode` while polling | Not supported | Register callbacks before starting the receive loop. |
| `Connect`, `Shutdown`, `SetSendTimeout`, `SetTransactionTimeout`, `SetAutoPollingMode`, logical-address/verify-mode setters, or endpoint setters while requests or polling are active | Not supported | Treat these as lifecycle/configuration operations and serialize them at application level. |
| Concurrent access to the same caller-owned `TargetNode`, input span, or output span | Not supported | Use immutable inputs or separate external synchronization. |
| Any concurrent `TCPServer` socket operations | Not supported | Serialize accept, send, receive, configuration, and shutdown at application level. |

Internally, `TCPClient` protects its descriptor lifetime, `TransactionDatabase` protects transaction allocation/completion, and the node protects outgoing frame construction. Those mutexes provide the specific guarantees above; they do not make the whole object safe for arbitrary concurrent calls. A receive timeout returns `std::errc::timed_out` without discarding an otherwise healthy TCP connection; peer closure and hard socket errors still disconnect it.

`Shutdown()` ends the current client lifecycle. After shutdown, calls such as `EnsureTcpConnection()` return `std::errc::not_connected`; do not race shutdown against another node operation.

## Protocol limits

- `TargetNode` supports at most 12 target-path bytes and 12 reply-path bytes.
- RMAP command data lengths are encoded in 24 bits. Builders reject values larger than `0xFFFFFF`.
- Auto-resizing receive buffers reject accumulated frame payload larger than `SpwRmapTCPNodeConfig::max_receive_frame_size` (16 MiB plus 256 bytes by default). Lower this limit when peers are untrusted or application packets are known to be smaller.
- Builder functions return `std::errc::no_buffer_space` when the caller-provided output span is too small.

## Timeouts and Error Handling

- `Write` / `Read` accept a `timeout` (default 100 ms). When the timeout expires the pending transaction is cancelled internally, its transaction ID is released, and the call returns `std::errc::timed_out`. This prevents deadlocks when a remote node never replies.

- Asynchronous callbacks run inside the polling loop. If a function you pass to `WriteAsync` / `ReadAsync` throws, the library catches and logs the exception so the loop stays alive—wrap your callback body in your own error handling if you need to mark the operation successful despite local issues.

Python bindings currently offer only synchronous `read`/`write` methods, do not release the GIL around blocking I/O, and provide no built-in async wrapper.

## Known limitations

- Python read/write timeouts are currently fixed at 100 ms, and the binding does not expose an explicit `shutdown()` method or context-manager protocol. Destruction closes the socket.
- Synchronous C++ `Read`/`Write` validate reply type, transaction ID, and length, but currently do not convert a non-zero RMAP reply status into an error. Async users can inspect `Packet::status` directly.
- `Packet` payload and address fields are non-owning spans into parser or receive buffers. Callbacks must copy data they need to retain after the callback returns.
- The internal `TCPServer` backend requires its owner to serialize accept, send, receive, and shutdown calls. Unlike `TCPClient`, it does not yet protect socket lifecycle operations with a mutex.
- Span and initializer-list address setters on `TargetNode` require the caller to respect the 12-byte limit; this is enforced by an assertion in debug builds.
- CI uses loopback TCP peers and synthetic RMAP frames. Hardware-in-the-loop coverage is not yet included.

The [examples](examples) directory contains CLI programs that parse command-line arguments, manage the lifecycle for you, and show additional patterns (speed tests, multi-target setups, etc.).
