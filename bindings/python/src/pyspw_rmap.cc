#include <pybind11/chrono.h>
#include <pybind11/stl.h>

#include <atomic>
#include <span>
#include <spw_rmap/internal/debug.hh>
#include <spw_rmap/spw_rmap_node_base.hh>
#include <spw_rmap/spw_rmap_tcp_node.hh>
#include <spw_rmap/target_node.hh>

#include "span_caster.hh"

namespace py = pybind11;

using namespace std::chrono_literals;

struct PyTargetNode {
  uint32_t logical_address{0};
  std::vector<uint8_t> target_spacewire_address{};
  std::vector<uint8_t> reply_address{};
};

class PySpwRmapTCPNode {
 public:
  PySpwRmapTCPNode(const PySpwRmapTCPNode&) = delete;
  PySpwRmapTCPNode(PySpwRmapTCPNode&&) = delete;
  auto operator=(const PySpwRmapTCPNode&) -> PySpwRmapTCPNode& = delete;
  auto operator=(PySpwRmapTCPNode&&) -> PySpwRmapTCPNode& = delete;

  PySpwRmapTCPNode(std::string ip_address, std::string port)
      : node_({.ip_address = ip_address,
               .port = port,
               .send_buffer_size = 4096,
               .recv_buffer_size = 4096,
               .buffer_policy = spw_rmap::BufferPolicy::kAutoResize}) {
    node_.SetAutoPollingMode(true);
  }

  ~PySpwRmapTCPNode() = default;

  auto Connect(std::chrono::milliseconds timeout = 500ms) -> void {
    auto res = node_.Connect(timeout);
    if (!res.has_value()) [[unlikely]] {
      throw std::system_error(res.error());
    }
    connected_.store(true, std::memory_order_release);
  }

  auto Disconnect() -> void {
    if (!connected_.exchange(false, std::memory_order_acq_rel)) {
      return;
    }
    auto res = node_.Shutdown();
    if (!res && res.error() != std::errc::bad_file_descriptor) [[unlikely]] {
      throw std::system_error(res.error());
    }
  }

  auto Read(PyTargetNode target_node, uint32_t memory_adderss,
            uint32_t data_length, std::chrono::milliseconds timeout = 100ms)
      -> std::vector<uint8_t> {
    std::vector<uint8_t> data(data_length);
    if (target_node.reply_address.size() > spw_rmap::TargetNode::kMaxAddressLen)
        [[unlikely]] {
      throw std::out_of_range("Reply address length exceeds maximum allowed.");
    }
    if (target_node.target_spacewire_address.size() >
        spw_rmap::TargetNode::kMaxAddressLen) [[unlikely]] {
      throw std::out_of_range("Target address length exceeds maximum allowed.");
    }

    auto spw_target_node =
        spw_rmap::TargetNode(target_node.logical_address)
            .SetTargetAddress(std::move(target_node.target_spacewire_address))
            .SetReplyAddress(std::move(target_node.reply_address));
    std::expected<void, std::error_code> res_read;
    {
      py::gil_scoped_release release;
      res_read = node_.Read(spw_target_node, memory_adderss, data, timeout);
    }
    if (!res_read) [[unlikely]] {
      throw std::system_error(res_read.error());
    }
    return data;
  }

  void Write(PyTargetNode target_node, uint32_t memory_adderss,
             const std::vector<uint8_t>& data,
             std::chrono::milliseconds timeout = 100ms) {
    if (target_node.target_spacewire_address.size() >
        spw_rmap::TargetNode::kMaxAddressLen) [[unlikely]] {
      throw std::out_of_range("Target address length exceeds maximum allowed.");
    }
    if (target_node.reply_address.size() > spw_rmap::TargetNode::kMaxAddressLen)
        [[unlikely]] {
      throw std::out_of_range("Reply address length exceeds maximum allowed.");
    }

    auto spw_target_node =
        spw_rmap::TargetNode(target_node.logical_address)
            .SetTargetAddress(std::move(target_node.target_spacewire_address))
            .SetReplyAddress(std::move(target_node.reply_address));
    std::expected<void, std::error_code> res_write;
    {
      py::gil_scoped_release release;
      res_write = node_.Write(spw_target_node, memory_adderss, data, timeout);
    }
    if (!res_write) [[unlikely]] {
      throw std::system_error(res_write.error());
    }
  }

 private:
  spw_rmap::SpwRmapTCPClient node_;
  std::atomic<bool> connected_{false};
};

PYBIND11_MODULE(_core, m) {
  py::class_<PyTargetNode>(m, "TargetNode")
      .def(py::init<>())
      .def(py::init<uint32_t, std::vector<uint8_t>, std::vector<uint8_t>>(),
           py::arg("logical_address"), py::arg("target_spacewire_address"),
           py::arg("reply_address"))
      .def_readwrite("logical_address", &PyTargetNode::logical_address)
      .def_readwrite("target_spacewire_address",
                     &PyTargetNode::target_spacewire_address)
      .def_readwrite("reply_address", &PyTargetNode::reply_address);

  py::class_<PySpwRmapTCPNode>(m, "SpwRmapTCPNode")
      .def(py::init<std::string, std::string>(), py::arg("ip_address"),
           py::arg("port"))
      .def("connect", &::PySpwRmapTCPNode::Connect, py::arg("timeout") = 500ms)
      .def("disconnect", &::PySpwRmapTCPNode::Disconnect)
      .def(
          "__enter__",
          [](PySpwRmapTCPNode& self) -> PySpwRmapTCPNode& { return self; },
          py::return_value_policy::reference_internal)
      .def("__exit__", [](PySpwRmapTCPNode& self, py::object, py::object,
                          py::object) { self.Disconnect(); })
      .def("read", &PySpwRmapTCPNode::Read, py::arg("target_node"),
           py::arg("memory_address"), py::arg("data_length"),
           py::arg("timeout") = 100ms)
      .def("write", &PySpwRmapTCPNode::Write, py::arg("target_node"),
           py::arg("memory_address"), py::arg("data"),
           py::arg("timeout") = 100ms);

  m.def(
      "set_debug_enabled",
      [](bool enabled) -> void { spw_rmap::debug::SetRuntimeEnabled(enabled); },
      py::arg("enabled"), "Enable or disable runtime debug logging");
  m.def(
      "enable_debug", []() -> void { spw_rmap::debug::Enable(); },
      "Enable runtime debug logging");
  m.def(
      "disable_debug", []() -> void { spw_rmap::debug::Disable(); },
      "Disable runtime debug logging");
  m.def(
      "is_debug_enabled",
      []() -> bool { return spw_rmap::debug::IsRuntimeEnabled(); },
      "Check if runtime debug logging is enabled");
}
