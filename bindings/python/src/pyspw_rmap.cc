#include <pybind11/chrono.h>
#include <pybind11/stl.h>

#include <atomic>
#include <exception>
#include <mutex>
#include <span>
#include <spw_rmap/internal/debug.hh>
#include <spw_rmap/spw_rmap_node_base.hh>
#include <spw_rmap/spw_rmap_tcp_node.hh>
#include <spw_rmap/target_node.hh>
#include <thread>

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
               .buffer_policy = spw_rmap::BufferPolicy::AutoResize}) {
    node_.setAutoPollingMode(true);
  }

  ~PySpwRmapTCPNode() = default;

  auto connect(std::chrono::milliseconds timeout = 500ms) -> void {
    auto res = node_.connect(timeout);
    if (!res.has_value()) {
      throw std::system_error(res.error());
    }
  }

  auto read(PyTargetNode target_node, uint32_t memory_adderss,
            uint32_t data_length) -> std::vector<uint8_t> {
    std::vector<uint8_t> data(data_length);
    auto spw_target_node = spw_rmap::TargetNode(target_node.logical_address);
    auto res = spw_target_node.setTargetAddress(
        std::move(target_node.target_spacewire_address));
    if (!res) {
      throw std::system_error(res.error());
    }
    res = spw_target_node.setReplyAddress(std::move(target_node.reply_address));
    if (!res) {
      throw std::system_error(res.error());
    }
    auto res_read = node_.read(spw_target_node, memory_adderss, data, 100ms);
    if (!res_read) {
      throw std::system_error(res.error());
    }
    return data;
  }

  void write(PyTargetNode target_node, uint32_t memory_adderss,
             const std::vector<uint8_t>& data) {
    auto spw_target_node = spw_rmap::TargetNode(target_node.logical_address);
    auto res = spw_target_node.setTargetAddress(
        std::move(target_node.target_spacewire_address));
    if (!res) {
      throw std::system_error(res.error());
    }
    res = spw_target_node.setReplyAddress(std::move(target_node.reply_address));
    if (!res) {
      throw std::system_error(res.error());
    }
    auto res_write = node_.write(spw_target_node, memory_adderss, data, 100ms);
    if (!res_write) {
      throw std::system_error(res.error());
    }
  }

 private:
  spw_rmap::SpwRmapTCPClient node_;
  std::thread thread_;
  std::mutex thread_error_mtx_;
  std::exception_ptr thread_error_ = nullptr;
  std::atomic<bool> running_{false};
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
      .def("connect", &PySpwRmapTCPNode::connect, py::arg("timeout") = 500ms)
      .def("read", &PySpwRmapTCPNode::read, py::arg("target_node"),
           py::arg("memory_address"), py::arg("data_length"))
      .def("write", &PySpwRmapTCPNode::write, py::arg("target_node"),
           py::arg("memory_address"), py::arg("data"));

  m.def(
      "set_debug_enabled",
      [](bool enabled) -> void {
        spw_rmap::debug::set_runtime_enabled(enabled);
      },
      py::arg("enabled"), "Enable or disable runtime debug logging");
  m.def(
      "enable_debug", []() -> void { spw_rmap::debug::enable(); },
      "Enable runtime debug logging");
  m.def(
      "disable_debug", []() -> void { spw_rmap::debug::disable(); },
      "Disable runtime debug logging");
  m.def(
      "is_debug_enabled",
      []() -> bool { return spw_rmap::debug::is_runtime_enabled(); },
      "Check if runtime debug logging is enabled");
}
