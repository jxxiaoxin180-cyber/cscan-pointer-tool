#pragma once
#include <sys/types.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "ahwbp/paradise.h"
#include "json.hpp"
namespace cs {
using J = nlohmann::json;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
constexpr const char* version = "1.2.2";
std::string hex(uint64_t n);
uint64_t number(const std::string& s, bool address = false);
std::vector<uint64_t> addresses(const std::string& s, int bits);
uint64_t add(uint64_t a, int64_t b, int bits = 64);
uint64_t mask_pointer(uint64_t p, const std::string& mask);
std::string text(const fs::path& p, size_t limit = 1024 * 1024);
std::string unique_id();
struct Cancelled : std::runtime_error {
  Cancelled() : runtime_error("任务已取消") {}
};
struct Budget : std::runtime_error {
  using runtime_error::runtime_error;
};
struct Context {
  std::atomic_bool cancel{false};
  Clock::time_point started = Clock::now();
  std::function<void(J)> event = [](J) {};
  uint64_t visited = 0, max_nodes = 5000000;
  int timeout = 120;
  void check();
  void progress(const std::string& phase, const std::string& message, J fields = J::object());
};
struct Region {
  uint64_t start = 0, end = 0, file_offset = 0;
  std::string perms, path, name, kind, id;
  int index = 0;
  bool root = false;
};
struct Target {
  int pid = 0, uid = -1, bits = 0;
  std::string name, identity;
  std::vector<Region> regions;
};
Target target(int pid);
J processes();
J process_probe(int pid, const fs::path& proc_root = "/proc");
J process_catalog(const fs::path& proc_root = "/proc");
J runtime_info(const fs::path& proc_root = "/proc");
J modules(const Target& t);
void check_identity(const Target& t);
class Reader {
  int pid_, fd_ = -1;
  std::string backend_;
  std::mutex mutex_;
  ahwb_paradise paradise_{-1, AHWBP_PARADISE_TRANSPORT_NONE, 0, {0, 0, 0, 0}};
  uint64_t read_calls_ = 0, ioctl_calls_ = 0, bytes_read_ = 0, syscall_reads_ = 0, pread_reads_ = 0;
  int last_error_ = 0;

 public:
  explicit Reader(int pid, const std::string& backend, int inherited_fd = -1);
  ~Reader();
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  ssize_t read(uint64_t addr, void* buf, size_t length);
  ssize_t read_exact(uint64_t addr, void* buf, size_t length);
  J diagnostics() const;
};
struct Pointer {
  uint64_t address, value;
};
struct Config {
  int pid = 0, bits = 64, depth = 6, step = 8, timeout = 120, driver_fd = -1, threads = 0;
  uint64_t graph_memory_mb = 128;
  uint64_t offset = 2000, limit = 100000, memory_mb = 128, max_nodes = 5000000, source = 0;
  bool negative = false, nonread = false, relation = false;
  std::string reader = "syscall", mask = "none";
  std::vector<uint64_t> targets;
  std::vector<std::string> roots, kinds = {"A", "Ca", "Ch", "Cb", "Cd"};
  std::vector<std::pair<uint64_t, uint64_t>> spans;
  std::vector<uint64_t> layer_offsets;
  static Config parse(const J& j);
};
struct Index {
  std::vector<Pointer> pointers;
  J stats = J::object();
  bool complete = true;
  std::string reason;
};
Index collect(const Target& t, Reader& r, const Config& c, Context& ctx);
struct Chain {
  bool absolute = false;
  int bits = 64, index = 1;
  std::string module, region, mask = "none";
  std::vector<int64_t> offsets;
  bool operator<(const Chain& o) const;
  bool operator==(const Chain& o) const;
  std::string line() const;
  J json() const;
  static Chain parse(const std::string& s, int bits = 64, const std::string& mask = "none");
};
using Emit = std::function<void(const Chain&)>;
uint64_t search(Index& index, const Target& t, const Config& c, Context& ctx, Emit emit);
J resolve(const Chain& c, const Target& t, Reader& r, uint64_t source = 0);
class ChainGraph;
struct StoreWriterImpl;
class StoreWriter {
  std::unique_ptr<StoreWriterImpl> impl_;

 public:
  explicit StoreWriter(fs::path output);
  ~StoreWriter();
  void push(const Chain& c);
  J finish(J metadata);
  uint64_t count() const;
};
struct StoreReaderImpl;
class StoreReader {
  std::unique_ptr<StoreReaderImpl> impl_;

 public:
  J metadata;
  explicit StoreReader(const fs::path& p, size_t graph_memory_bytes = 128ULL * 1024 * 1024);
  ~StoreReader();
  bool next(Chain& c);
  void skip(uint64_t count);
  bool is_graph() const;
  std::shared_ptr<ChainGraph> graph();
};
J save_graph(const fs::path& path, const ChainGraph& graph, J metadata);
struct TextReaderImpl;
class TextReader {
  std::unique_ptr<TextReaderImpl> impl_;

 public:
  J metadata;
  explicit TextReader(const fs::path& p, int bits = 64, std::string mask = "none");
  ~TextReader();
  bool next(Chain& c);
};
class ChainInput {
  std::unique_ptr<StoreReader> binary_;
  std::unique_ptr<TextReader> text_;

 public:
  explicit ChainInput(const fs::path& p, int bits = 64, std::string mask = "none",
                      size_t graph_memory_bytes = 128ULL * 1024 * 1024);
  bool next(Chain& c);
  void skip(uint64_t count);
  J metadata() const;
  bool is_graph() const;
  std::shared_ptr<ChainGraph> graph();
};
J format_text(const fs::path& input, const fs::path& output, const J& options, Context& ctx,
              J provenance = J::object());
J list_results(const fs::path& dir);
J preview(const fs::path& p, size_t page, size_t page_size = 50,
          size_t graph_memory_bytes = 128ULL * 1024 * 1024);
fs::path safe_file(const fs::path& dir, const std::string& name);
J run(const J& request, const fs::path& dir, Context& ctx, const fs::path& external_text = {});
class Fixture {
  int fd_ = -1;
  void* root_ = nullptr;
  void* heap_ = nullptr;
  size_t page_ = 0;
  fs::path path_;

 public:
  explicit Fixture(const fs::path& dir);
  ~Fixture();
  J info() const;
};
int serve(const fs::path& dir, int port);
int menu(const fs::path& dir);
}  // namespace cs
