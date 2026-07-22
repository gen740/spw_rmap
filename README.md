# spw_rmap

`spw_rmap` is a SpaceWire/RMAP helper library that provides packet builders/parsers, a TCP transport, CLI utilities, and Python bindings.

## Quick start

The library requires a C++23 compiler and CMake 3.20 or newer.  Build the
default library and command-line tools with:

```bash
cmake -S . -B build
cmake --build build
```

This project also provides a Nix development shell with the supported build,
test, Python, and formatting tools:

```bash
nix develop
```

For a ready-made Debug build with the test suite, examples, applications, and
Python bindings enabled, run:

```bash
nix run .#build
```

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

To install the C++ library and CMake package configuration to a prefix:

```bash
cmake -S . -B build -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build
cmake --install build
```

Downstream CMake projects can then use the exported target:

```cmake
find_package(spw_rmap CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE spw_rmap::spw_rmap)
```

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

ThreadSanitizer runtime support depends on the compiler and operating system; CI exercises this configuration on Linux.

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

## C++ request and receive model

There are two separate decisions:

1. `Write` / `Read` versus `WriteAsync` / `ReadAsync` determines whether the requesting thread waits for the reply.
2. `SetAutoPollingMode` determines who receives replies for synchronous requests. It does not start a polling thread.

The supported combinations are:

| Auto-polling | Receive driver | Available request APIs | Request completion |
|---|---|---|---|
| On | The calling `Write` / `Read` call | `Write`, `Read` | The call sends, receives one matching reply, and returns synchronously. Calls on the node are serialized. |
| Off (default) | Exactly one background `RunLoop` or polling thread | `Write`, `Read` | The call sends through the async transaction machinery, then waits for its internal callback. The receive loop invokes that callback and wakes the caller. |
| Off (default) | Exactly one `RunLoop` or repeated `Poll` calls | `WriteAsync`, `ReadAsync` | The call builds and sends the packet before returning its transaction ID. The receive loop later invokes the supplied callback. |

With auto-polling off, synchronous and asynchronous requests may share the same receive loop and may be interleaved. A synchronous `Write` / `Read` is implemented as an async transaction plus an internal condition-variable wait; it does not receive from the socket itself. Therefore, start `RunLoop` (or another thread calling `Poll`) before issuing such a synchronous request.

Synchronous `Write` / `Read` require the matching reply type and `PacketStatusCode::kCommandExecutedSuccessfully`. A non-zero RMAP status is returned as a `std::error_code` in the `RMAPReplyStatus` category, preserving statuses such as `kInvalidKey`. The asynchronous APIs continue to deliver the parsed `Packet` to the callback so the callback can inspect `Packet::status` directly.

`WriteAsync` / `ReadAsync` are asynchronous only with respect to waiting for the reply. Packet construction and TCP transmission happen in the calling thread and are complete before a successful return. The callback only handles the matching reply or transaction error. Because `RunLoop` may receive a very fast reply concurrently, the callback can run before the async function returns.

When auto-polling is on, do not call `Poll` or `RunLoop`; `WriteAsync` and `ReadAsync` return `std::errc::operation_not_permitted`.

### Target node

```cpp
spw_rmap::TargetNode target(0x34);              // target logical address
target.SetTargetAddress(3, 5, 7);               // outbound SpaceWire path
target.SetReplyAddress(9, 11, 13, 0x00);        // reply path
```

Both paths have a maximum length of 12 bytes.

### Synchronous client without a receive thread

Use this mode for command-line tools and simple request/response applications. No worker thread or explicit polling is required.

```cpp
#include <array>
#include <chrono>
#include <span>

#include <spw_rmap/spw_rmap_tcp_node.hh>
#include <spw_rmap/target_node.hh>

using namespace std::chrono_literals;

spw_rmap::SpwRmapTCPClient client(
    {.ip_address = "127.0.0.1", .port = "10030"});
client.SetInitiatorLogicalAddress(0xFE);
client.SetAutoPollingMode(true);
client.Connect(500ms).value();

spw_rmap::TargetNode target(0x34);
target.SetTargetAddress(3, 5, 7).SetReplyAddress(9, 11, 13, 0);

std::array<uint8_t, 4> payload{0x12, 0x34, 0x56, 0x78};
client.Write(target, 0x20000000, payload, 100ms).value();

std::array<uint8_t, 4> data{};
client.Read(target, 0x20000000, std::span(data), 100ms).value();

client.Shutdown().value();
```

Auto-polling serializes synchronous calls on the node. This form is suitable when only one request needs to be in flight at a time.

### Shared background `RunLoop`

Leave auto-polling off to let one background `RunLoop` receive all replies. The same loop supports both blocking `Write` / `Read` callers and callback-based `WriteAsync` / `ReadAsync` callers.

```cpp
#include <array>
#include <future>
#include <thread>

spw_rmap::SpwRmapTCPClient client(
    {.ip_address = "127.0.0.1", .port = "10030"});
client.SetInitiatorLogicalAddress(0xFE);
client.Connect(500ms).value();  // auto-polling remains off

spw_rmap::TargetNode target(0x34);
target.SetTargetAddress(3, 5, 7).SetReplyAddress(9, 11, 13, 0);

std::error_code loop_error;
std::thread loop([&] {
  if (auto result = client.RunLoop(); !result) {
    loop_error = result.error();
  }
});

std::array<uint8_t, 4> payload{0x12, 0x34, 0x56, 0x78};

// Synchronous API: sends now, then waits until RunLoop dispatches the reply to
// the internal callback.
client.Write(target, 0x20000000, payload, 100ms).value();

std::array<uint8_t, 4> data{};
client.Read(target, 0x20000000, std::span(data), 100ms).value();

// Asynchronous API: sends now and returns the transaction ID without waiting.
std::promise<bool> completed;
auto completion = completed.get_future();

auto transaction = client.WriteAsync(
    target, 0x20000000, payload,
    [&completed](std::expected<spw_rmap::Packet, std::error_code> reply) {
      const bool success =
          reply && reply->type == spw_rmap::PacketType::kWriteReply &&
          reply->status ==
              spw_rmap::PacketStatusCode::kCommandExecutedSuccessfully;
      completed.set_value(success);
    });
transaction.value();  // transmission succeeded; value is the transaction ID

const bool request_succeeded = completion.get();

client.Stop().value();  // interrupts the blocking receive
loop.join();
client.Shutdown().value();
```

For a single-threaded event loop, submit asynchronous requests and call `Poll()` repeatedly instead of starting `RunLoop()`. Each successful `Poll()` receives one complete frame and dispatches the matching transaction callback. A synchronous `Write` / `Read` cannot drive `Poll()` on the same thread while it is blocked; use auto-polling or a separate receive thread for synchronous calls.

### Callback and lifetime rules

- Use exactly one `Poll` or `RunLoop` per node.
- Reply callbacks and the internal callbacks used by non-auto-polling `Write` / `Read` execute on the polling thread. A transaction callback expired by `SetTransactionTimeout` is invoked lazily by a later request allocation, on that allocating thread instead.
- A user callback may run before the corresponding async call returns. Keep callbacks short and non-blocking; blocking the callback also blocks reply dispatch for every transaction on that receive loop.
- `Packet` address and payload fields are non-owning spans into the receive buffer. Copy anything that must survive after the callback returns.
- Inspect `Packet::type`, `Packet::status`, and read-data length in the callback. Async APIs intentionally return the parsed reply rather than converting RMAP status values into `std::error_code`.
- `Stop` does not complete outstanding callbacks. Wait for them or call `CancelTransaction` before stopping the loop. Then join the loop thread before `Shutdown`.
- Outgoing packet construction and transmission are serialized, so concurrent async submissions cannot interleave bytes on the TCP stream. Receiving remains independent and can block in `RunLoop` while another thread submits a request.

See `examples/spwrmap_example_sync.cc`, `examples/spwrmap_example_async.cc`, and `examples/spwrmap_example.py` for complete programs.

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
| `Read` / `Write` in auto-polling mode | Supported | Calls are serialized internally and receive their own replies. Do not call `Poll`, `RunLoop`, `ReadAsync`, or `WriteAsync` in this mode. |
| `ReadAsync` / `WriteAsync` / `EmitTimeCode` | Supported | Auto-polling must be off, the connection and configuration must remain unchanged, and caller-owned input objects must remain valid for each call. Transaction allocation and outgoing frame construction are serialized internally. |
| One `Poll` or `RunLoop` plus async requests and/or non-auto-polling `Read` / `Write` | Supported | Sync and async requests may share the loop. Outgoing frames are serialized independently from the blocking receive direction. |
| Two or more `Poll` / `RunLoop` calls | Not supported | They share one receive buffer and one TCP byte stream. |
| `RegisterOnRead`, `RegisterOnWrite`, or `RegisterOnTimeCode` while polling | Not supported | Register callbacks before starting the receive loop. |
| `Connect`, `Shutdown`, `SetSendTimeout`, `SetTransactionTimeout`, `SetAutoPollingMode`, logical-address/verify-mode setters, or endpoint setters while requests or polling are active | Not supported | Treat these as lifecycle/configuration operations and serialize them at application level. `Stop` is the exception: it is designed to interrupt the one blocking receive loop. |
| Concurrent access to the same caller-owned `TargetNode`, input span, or output span | Not supported | Use immutable inputs or separate external synchronization. |
| Any concurrent `TCPServer` socket operations | Not supported | Serialize accept, send, receive, configuration, and shutdown at application level. |

Internally, `TCPClient` uses independent send, receive, and lifecycle locks, `TransactionDatabase` protects transaction allocation/completion, and the node protects outgoing frame construction. Those mutexes provide the specific guarantees above; they do not make the whole object safe for arbitrary concurrent calls. A receive timeout returns `std::errc::timed_out` without discarding an otherwise healthy TCP connection; peer closure and hard socket errors still disconnect it.

To stop a background `RunLoop()`, call `Stop()`, join the loop thread, and then call `Shutdown()`. `Stop()` sets the loop stop flag and interrupts its blocking receive without destroying the backend. `Shutdown()` ends the current client lifecycle; do not race it against another node operation.

## Protocol limits

- `TargetNode` supports at most 12 target-path bytes and 12 reply-path bytes.
- RMAP command data lengths are encoded in 24 bits. Builders reject values larger than `0xFFFFFF`.
- Auto-resizing receive buffers reject accumulated frame payload larger than `SpwRmapTCPNodeConfig::max_receive_frame_size` (16 MiB plus 256 bytes by default). Lower this limit when peers are untrusted or application packets are known to be smaller.
- Builder functions return `std::errc::no_buffer_space` when the caller-provided output span is too small.

## Timeouts and Error Handling

- `Write` / `Read` accept a `timeout` (default 100 ms). In auto-polling mode it is applied to the socket receive. With auto-polling off it bounds the internal condition-variable wait. In either path, a timeout releases the transaction ID and returns `std::errc::timed_out`.

- `WriteAsync` / `ReadAsync` have no per-call deadline or timer thread. `SetTransactionTimeout` controls when an old transaction ID becomes eligible for reuse. Expiration is noticed during a later transaction allocation; only then is the old callback invoked with `std::errc::timed_out`. Applications needing prompt async deadlines should enforce their own timer and call `CancelTransaction`.

- Asynchronous callbacks run inside the polling loop. If a function you pass to `WriteAsync` / `ReadAsync` throws, the library catches and logs the exception so the loop stays alive—wrap your callback body in your own error handling if you need to mark the operation successful despite local issues.

Python bindings offer synchronous `read`/`write` methods that release the GIL during blocking I/O, allowing other Python threads to execute concurrently. Timeouts can be configured per call (default 100 ms). No built-in `asyncio` wrapper is provided yet.

## Known limitations

- During automatic client reconnection, a request submitted concurrently with descriptor replacement is not yet protected by the normal send/receive locks. (Pending transactions from the old connection are correctly aborted with a network error).
- `Packet` payload and address fields are non-owning spans into parser or receive buffers. Callbacks must copy data they need to retain after the callback returns.
- The internal `TCPServer` backend requires its owner to serialize accept, send, receive, and shutdown calls. In addition, generated replies do not yet preserve all command header fields: logical-address fields are swapped, instruction mode/address-length bits are not copied, and an all-zero padded reply address is decoded as an empty path rather than the required single zero byte.
- Span and initializer-list address setters on `TargetNode` require the caller to respect the 12-byte limit; this is enforced by an assertion in debug builds.

The [examples](examples) directory contains CLI programs that parse command-line arguments, manage the lifecycle for you, and show additional patterns (speed tests, multi-target setups, etc.).
