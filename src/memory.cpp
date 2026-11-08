#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "core.hpp"
namespace cs {
std::string hex(uint64_t n) {
  std::ostringstream s;
  s << "0x" << std::uppercase << std::hex << n;
  return s.str();
}
uint64_t number(const std::string& s, bool addr) {
  if (s.empty() || s[0] == '-' || s[0] == '+' || s.find_first_of(" \n\t\r") != std::string::npos)
    throw std::runtime_error("无效数字：" + s);
  size_t pos = 0;
  uint64_t n = 0;
  try {
    n = std::stoull(s, &pos, (addr || s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) ? 16 : 10);
  } catch (...) {
    throw std::runtime_error("数字无效或溢出：" + s);
  }
  if (pos != s.size())
    throw std::runtime_error("数字包含非法字符：" + s);
  return n;
}
std::vector<uint64_t> addresses(const std::string& s, int bits) {
  std::string norm = s;
  for (auto pair : std::vector<std::pair<std::string, std::string>>{{"，", " "}, {"；", " "}}) {
    size_t p;
    while ((p = norm.find(pair.first)) != std::string::npos)
      norm.replace(p, pair.first.size(), pair.second);
  }
  for (char& c : norm)
    if (c == ',' || c == ';')
      c = ' ';
  std::istringstream in(norm);
  std::string word;
  std::vector<uint64_t> out;
  while (in >> word) {
    auto n = number(word, true);
    if (!n || (bits == 32 && n > UINT32_MAX))
      throw std::runtime_error("目标地址为零或超出目标位数：" + word);
    if (std::find(out.begin(), out.end(), n) == out.end())
      out.push_back(n);
    if (out.size() > 1000)
      throw std::runtime_error("最多输入 1000 个目标地址");
  }
  return out;
}
uint64_t add(uint64_t a, int64_t b, int bits) {
  uint64_t max = bits == 32 ? UINT32_MAX : UINT64_MAX;
  if (a > max)
    throw std::runtime_error("地址超出目标位数");
  if (b >= 0) {
    if (uint64_t(b) > max - a)
      throw std::runtime_error("地址加法溢出");
    return a + uint64_t(b);
  }
  uint64_t d = uint64_t(-(b + 1)) + 1;
  if (d > a)
    throw std::runtime_error("地址减法溢出");
  return a - d;
}
uint64_t mask_pointer(uint64_t p, const std::string& m) {
  return m == "topbyte" ? p & 0x00ffffffffffffffULL : m == "low48" ? p & 0x0000ffffffffffffULL : p;
}
std::string text(const fs::path& p, size_t lim) {
  std::ifstream f(p, std::ios::binary);
  if (!f)
    throw std::runtime_error("无法读取：" + p.string());
  std::string s;
  char b[4096];
  while (f) {
    f.read(b, std::min(sizeof(b), lim + 1 - s.size()));
    s.append(b, f.gcount());
    if (s.size() > lim)
      throw std::runtime_error("文件超出读取上限：" + p.string());
  }
  return s;
}
std::string unique_id() {
  unsigned char b[12];
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    throw std::runtime_error("无法生成任务标识");
  ssize_t n = ::read(fd, b, sizeof b);
  close(fd);
  if (n != sizeof b)
    throw std::runtime_error("随机数读取失败");
  const char* h = "0123456789abcdef";
  std::string s;
  for (auto v : b) {
    s += h[v >> 4];
    s += h[v & 15];
  }
  return s;
}
void Context::check() {
  if (cancel)
    throw Cancelled();
  if (timeout &&
      std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - started).count() >= timeout)
    throw Budget("time_limit");
  if (max_nodes && visited >= max_nodes)
    throw Budget("work_limit");
}
void Context::progress(const std::string& p, const std::string& m, J fields) {
  fields["phase"] = p;
  fields["message"] = m;
  fields["visited"] = visited;
  fields["elapsed_ms"] =
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
  event(std::move(fields));
}
J modules(const Target& t) {
  J a = J::array();
  for (auto& r : t.regions)
    if (r.root)
      a.push_back({{"id", r.id},
                   {"name", r.name},
                   {"region", r.kind},
                   {"index", r.index},
                   {"start", hex(r.start)},
                   {"end", hex(r.end)},
                   {"size", r.end - r.start},
                   {"path", r.path},
                   {"perms", r.perms}});
  return a;
}
Config Config::parse(const J& j) {
  Config c;
  auto num = [&](const char* k, uint64_t def, bool addr = false) {
    if (!j.contains(k))
      return def;
    return number(j[k].is_string() ? j[k].get<std::string>() : j[k].dump(), addr);
  };
  auto bounded = [&](const char* k, uint64_t d, uint64_t lo, uint64_t hi) {
    auto n = num(k, d);
    if (n < lo || n > hi)
      throw std::runtime_error(std::string(k) + " 超出允许范围 " + std::to_string(lo) + "–" +
                               std::to_string(hi));
    return n;
  };
  c.pid = bounded("pid", 0, 1, INT32_MAX);
  c.bits = bounded("bits", 64, 32, 64);
  if (c.bits != 32 && c.bits != 64)
    throw std::runtime_error("目标位数只能为 32 或 64");
  c.depth = bounded("depth", 6, 0, 256);
  c.threads = bounded("threads", 0, 0, 32);
  c.graph_memory_mb = bounded("graph_memory_mb", 128, 8, 4096);
  c.step = bounded("step", c.bits / 8, 4, 8);
  if (c.step != 4 && c.step != 8)
    throw std::runtime_error("采集步进只能为 4 或 8");
  if (c.bits == 32 && c.step != 4)
    throw std::runtime_error("32 位目标使用 4 字节步进");
  c.offset = bounded("offset", 2000, 0, INT32_MAX);
  c.limit = bounded("limit", 100000, 0, 1000000000);
  c.memory_mb = bounded("memory_mb", 128, 8, 4096);
  c.timeout = bounded("timeout", 120, 1, 3600);
  c.max_nodes = bounded("max_nodes", 5000000, 1, 1000000000);
  c.reader = j.value("reader", "syscall");
  c.mask = j.value("mask", "none");
  if (c.mask != "none" && c.mask != "low48" && c.mask != "topbyte")
    throw std::runtime_error("无效的指针标签策略");
  c.negative = j.value("negative", false);
  c.nonread = j.value("nonread", false);
  c.relation = j.value("kind", "") == "relation";
  c.targets = addresses(j.value("addresses", ""), c.bits);
  c.roots = j.value("modules", std::vector<std::string>{});
  c.kinds = j.value("ranges", c.kinds);
  if (j.contains("source") && !j["source"].get<std::string>().empty())
    c.source = number(j["source"].get<std::string>(), true);
  if (j.contains("driver_fd"))
    c.driver_fd = j["driver_fd"].get<int>();
  c.layer_offsets.assign(c.depth + 1, c.offset);
  std::string layers = j.value("layer_offsets", "");
  for (char& ch : layers)
    if (ch == ',')
      ch = ' ';
  std::istringstream lin(layers);
  std::string item;
  std::vector<int> seen;
  while (lin >> item) {
    auto colon = item.find(':');
    if (colon == std::string::npos)
      throw std::runtime_error("逐层偏移格式为 1:0x40,2:0x100");
    auto level = number(item.substr(0, colon)), off = number(item.substr(colon + 1));
    if (!level || level > uint64_t(c.depth) || off > INT32_MAX ||
        std::find(seen.begin(), seen.end(), level) != seen.end())
      throw std::runtime_error("逐层偏移含重复层号或越界值");
    seen.push_back(level);
    c.layer_offsets[level] = off;
  }
  if (j.contains("spans")) {
    if (!j["spans"].is_array() || j["spans"].size() > 1000)
      throw std::runtime_error("无效地址区间");
    for (auto& s : j["spans"]) {
      uint64_t a = number(s.at(0).get<std::string>(), true),
               b = number(s.at(1).get<std::string>(), true);
      if (b <= a)
        throw std::runtime_error("区间终点必须大于起点");
      c.spans.emplace_back(a, b);
    }
    std::sort(c.spans.begin(), c.spans.end());
    for (size_t i = 1; i < c.spans.size(); ++i)
      if (c.spans[i].first < c.spans[i - 1].second)
        throw std::runtime_error("采集区间不能重叠");
  }
  if (c.relation) {
    if (!c.source || !c.depth || !c.offset)
      throw std::runtime_error("关系扫描需要有效起点、至少 1 层和非零范围");
    add(c.source, c.offset, c.bits);
    if (c.negative || !layers.empty())
      throw std::runtime_error("关系扫描使用独立的正偏移范围");
  }
  return c;
}
Fixture::Fixture(const fs::path& dir) {
  page_ = sysconf(_SC_PAGESIZE);
  fd_ = syscall(SYS_memfd_create, "libcscan_fixture.so", 1);
  if (fd_ < 0) {
    path_ = dir / ("libcscan_fixture_" + unique_id() + ".so");
    fd_ = open(path_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  }
  if (fd_ < 0 || ftruncate(fd_, page_) < 0)
    throw std::runtime_error("无法创建自测内存");
  root_ = mmap(nullptr, page_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
  heap_ = mmap(nullptr, page_ * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (root_ == MAP_FAILED || heap_ == MAP_FAILED)
    throw std::runtime_error("自测内存映射失败");
  auto put = [](void* p, size_t off, uint64_t v) {
    std::memcpy(static_cast<char*>(p) + off, &v, 8);
  };
  put(root_, 0x40, reinterpret_cast<uint64_t>(heap_));
  put(root_, 0x50, reinterpret_cast<uint64_t>(heap_));
  put(heap_, 0x20, reinterpret_cast<uint64_t>(heap_) + page_);
  put(heap_, page_ + 0x30, 424242);
}
Fixture::~Fixture() {
  if (root_ && root_ != MAP_FAILED)
    munmap(root_, page_);
  if (heap_ && heap_ != MAP_FAILED)
    munmap(heap_, page_ * 2);
  if (fd_ >= 0)
    close(fd_);
  std::error_code ec;
  fs::remove(path_, ec);
}
J Fixture::info() const {
  auto t = target(getpid());
  std::string rootid;
  for (auto& r : t.regions)
    if (r.start == reinterpret_cast<uint64_t>(root_))
      rootid = r.id;
  return {{"pid", getpid()},
          {"name", "内置可控样本"},
          {"bits", 64},
          {"addresses", hex(reinterpret_cast<uint64_t>(heap_) + page_ + 0x30)},
          {"source", hex(reinterpret_cast<uint64_t>(root_))},
          {"modules", J::array({rootid})},
          {"spans", J::array({J::array({hex(reinterpret_cast<uint64_t>(root_)),
                                        hex(reinterpret_cast<uint64_t>(root_) + page_)}),
                              J::array({hex(reinterpret_cast<uint64_t>(heap_)),
                                        hex(reinterpret_cast<uint64_t>(heap_) + page_ * 2)})})},
          {"expected", 2},
          {"depth", 2},
          {"offset", 128},
          {"value", 424242}};
}
}  // namespace cs
