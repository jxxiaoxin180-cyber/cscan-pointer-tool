#include <fcntl.h>
#include <unistd.h>

#include <charconv>
#include <cstring>
#include <regex>
#include <sstream>

#include "core.hpp"
#include "graph.hpp"
#include "zstd.h"
namespace cs {
namespace {
void put(std::string& b, uint64_t n, int bytes) {
  for (int i = 0; i < bytes; ++i) b.push_back(char((n >> (i * 8)) & 255));
}
uint64_t get(const std::string& b, size_t& pos, int bytes) {
  if (pos + bytes > b.size())
    throw std::runtime_error("结果文件记录不完整");
  uint64_t n = 0;
  for (int i = 0; i < bytes; ++i) n |= uint64_t(uint8_t(b[pos++])) << (8 * i);
  return n;
}
uint32_t crc(const std::string& s) {
  uint32_t c = 0xffffffff;
  for (unsigned char ch : s) {
    c ^= ch;
    for (int k = 0; k < 8; ++k) c = (c >> 1) ^ ((c & 1) ? 0xedb88320 : 0);
  }
  return ~c;
}
void u32(std::ostream& s, uint32_t n) {
  std::string b;
  put(b, n, 4);
  s.write(b.data(), 4);
}
uint32_t read32(std::istream& s) {
  char b[4];
  if (!s.read(b, 4))
    throw std::runtime_error("结果文件截断");
  size_t p = 0;
  return get(std::string(b, 4), p, 4);
}
void validate(const Chain& c) {
  if (c.bits != 32 && c.bits != 64)
    throw std::runtime_error("文件含无效指针位数");
  if (c.mask != "none" && c.mask != "topbyte" && c.mask != "low48")
    throw std::runtime_error("文件含无效指针掩码");
  if (c.offsets.empty() || c.offsets.size() > 257)
    throw std::runtime_error("文件含无效链深度");
  if (c.offsets[0] < 0)
    throw std::runtime_error("根偏移不能为负数");
  if (!c.absolute &&
      (c.module.empty() || c.module.size() > 4096 || c.index <= 0 || c.region.empty() ||
       c.region.size() > 16 || c.module.find_first_of("\r\n\0", 0, 3) != std::string::npos))
    throw std::runtime_error("文件含无效模块身份");
}
[[maybe_unused]] std::string encode(const Chain& c) {
  validate(c);
  std::string b;
  put(b, c.absolute, 1);
  put(b, c.bits, 1);
  put(b, c.mask == "none" ? 0 : c.mask == "topbyte" ? 1 : 2, 1);
  put(b, 0, 1);
  put(b, c.index, 4);
  put(b, c.module.size(), 2);
  b += c.module;
  put(b, c.region.size(), 1);
  b += c.region;
  put(b, c.offsets.size(), 2);
  for (auto off : c.offsets) put(b, uint64_t(off), 8);
  return b;
}
Chain decode(const std::string& b) {
  Chain c;
  size_t p = 0;
  auto a = get(b, p, 1);
  if (a > 1)
    throw std::runtime_error("无效根类型");
  c.absolute = a;
  c.bits = get(b, p, 1);
  auto mask = get(b, p, 1);
  if (mask > 2 || get(b, p, 1) != 0)
    throw std::runtime_error("无效结果字段");
  c.mask = mask == 0 ? "none" : mask == 1 ? "topbyte" : "low48";
  auto ix = get(b, p, 4);
  if (ix > INT32_MAX)
    throw std::runtime_error("无效模块索引");
  c.index = ix;
  auto len = get(b, p, 2);
  if (p + len > b.size())
    throw std::runtime_error("无效模块长度");
  c.module = b.substr(p, len);
  p += len;
  len = get(b, p, 1);
  if (p + len > b.size())
    throw std::runtime_error("无效区域长度");
  c.region = b.substr(p, len);
  p += len;
  len = get(b, p, 2);
  if (!len || len > 257)
    throw std::runtime_error("无效偏移数量");
  for (size_t i = 0; i < len; ++i) {
    auto raw = get(b, p, 8);
    int64_t val;
    std::memcpy(&val, &raw, 8);
    c.offsets.push_back(val);
  }
  if (p != b.size())
    throw std::runtime_error("结果记录含多余字段");
  validate(c);
  return c;
}
}  // namespace
std::string Chain::line() const {
  std::string s = absolute ? "@start" : module + "[" + std::to_string(index) + "][" + region + "]";
  for (size_t i = 0; i < offsets.size(); ++i) {
    if (i)
      s += " ->";
    int64_t n = offsets[i];
    s += n < 0 ? " - " : " + ";
    s += hex(n < 0 ? uint64_t(-(n + 1)) + 1 : uint64_t(n));
  }
  return s;
}
J Chain::json() const {
  J offs = J::array();
  for (auto n : offsets) offs.push_back(std::to_string(n));
  return {{"text", line()},   {"bits", bits},
          {"mask", mask},     {"root", absolute ? "start" : "module"},
          {"module", module}, {"region", region},
          {"index", index},   {"depth", offsets.size() - 1},
          {"offsets", offs}};
}
Chain Chain::parse(const std::string& line, int bits, const std::string& mask) {
  if (line.size() > 16384)
    throw std::runtime_error("单条链过长");
  Chain c;
  c.bits = bits;
  c.mask = mask;
  std::smatch match;
  static const std::regex re(R"(^\s*(.*?)\[(\d+)\]\[([A-Za-z]+)\]\s*(.*)$)");
  std::string rest;
  if (std::regex_match(line, match, re)) {
    c.module = match[1];
    auto n = number(match[2]);
    if (n > INT32_MAX)
      throw std::runtime_error("模块编号溢出");
    c.index = n;
    c.region = match[3];
    rest = match[4];
  } else {
    auto pos = line.find_first_not_of(" \t");
    if (pos == std::string::npos || line.substr(pos, 6) != "@start")
      throw std::runtime_error("链应以 模块[编号][区域] 或 @start 开头");
    c.absolute = true;
    rest = line.substr(pos + 6);
  }
  std::istringstream s(rest);
  std::string sign, word, arrow;
  while (s >> sign) {
    if (sign != "+" && sign != "-")
      throw std::runtime_error("偏移前需要 + 或 -");
    if (!(s >> word))
      throw std::runtime_error("缺少偏移值");
    uint64_t n = number(word, true);
    if (n > uint64_t(INT64_MAX))
      throw std::runtime_error("偏移溢出");
    c.offsets.push_back(sign == "-" ? -int64_t(n) : int64_t(n));
    if (!(s >> arrow))
      break;
    if (arrow != "->")
      throw std::runtime_error("偏移之间需要 ->");
    s >> std::ws;
    if (s.peek() == std::char_traits<char>::eof())
      throw std::runtime_error("链末尾不能是箭头");
  }
  validate(c);
  return c;
}
// CSCAN/2: bounded independent Zstandard frames and compact variable-width records.
namespace {
constexpr size_t block_size = 1024 * 1024;
uint32_t header_crc(const std::string& bytes) {
  static const auto table = []() {
    std::array<uint32_t, 256> a{};
    for (uint32_t i = 0; i < 256; ++i) {
      auto c = i;
      for (int k = 0; k < 8; ++k) c = (c >> 1) ^ ((c & 1) ? 0xedb88320 : 0);
      a[i] = c;
    }
    return a;
  }();
  uint32_t c = 0xffffffff;
  for (unsigned char ch : bytes) c = table[(c ^ ch) & 255] ^ (c >> 8);
  return ~c;
}
class BlockWriter {
  std::ostream& out_;
  std::string raw_;
  ZSTD_CCtx* ctx_ = nullptr;
  bool ended_ = false;

 public:
  explicit BlockWriter(std::ostream& out) : out_(out) {
    ctx_ = ZSTD_createCCtx();
    if (!ctx_)
      throw std::bad_alloc();
    raw_.reserve(block_size);
    ZSTD_CCtx_setParameter(ctx_, ZSTD_c_compressionLevel, 3);
    ZSTD_CCtx_setParameter(ctx_, ZSTD_c_checksumFlag, 1);
  }
  ~BlockWriter() {
    ZSTD_freeCCtx(ctx_);
  }
  void flush() {
    if (raw_.empty())
      return;
    std::string packed(ZSTD_compressBound(raw_.size()), '\0');
    size_t n = ZSTD_compress2(ctx_, packed.data(), packed.size(), raw_.data(), raw_.size());
    if (ZSTD_isError(n))
      throw std::runtime_error(ZSTD_getErrorName(n));
    u32(out_, raw_.size());
    u32(out_, n);
    out_.write(packed.data(), n);
    if (!out_)
      throw std::runtime_error("压缩块写入失败");
    raw_.clear();
  }
  void byte(uint8_t b) {
    if (ended_)
      throw std::runtime_error("输出已结束");
    raw_.push_back(char(b));
    if (raw_.size() == block_size)
      flush();
  }
  void uint(uint64_t n) {
    while (n >= 128) {
      byte(uint8_t(n) | 128);
      n >>= 7;
    }
    byte(n);
  }
  void sint(int64_t n) {
    uint(n < 0 ? (uint64_t(-(n + 1)) * 2 + 1) : uint64_t(n) * 2);
  }
  void string(const std::string& s) {
    uint(s.size());
    for (unsigned char ch : s) byte(ch);
  }
  void finish() {
    if (ended_)
      return;
    flush();
    u32(out_, 0);
    u32(out_, 0);
    ended_ = true;
  }
};
class BlockReader {
  std::istream& in_;
  std::string raw_;
  size_t position_ = 0;
  bool ended_ = false;

 public:
  explicit BlockReader(std::istream& in) : in_(in) {}
  bool more() {
    if (position_ < raw_.size())
      return true;
    if (ended_)
      return false;
    uint32_t raw = read32(in_), packed = read32(in_);
    if (!raw && !packed) {
      ended_ = true;
      if (in_.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("压缩文件尾部包含多余数据");
      return false;
    }
    if (!raw || raw > block_size || !packed || packed > ZSTD_compressBound(block_size))
      throw std::runtime_error("压缩块长度不合法");
    std::string bytes(packed, '\0');
    if (!in_.read(bytes.data(), packed))
      throw std::runtime_error("压缩块截断");
    if (ZSTD_getFrameContentSize(bytes.data(), bytes.size()) != raw)
      throw std::runtime_error("压缩帧声明长度不匹配");
    raw_.resize(raw);
    auto n = ZSTD_decompress(raw_.data(), raw_.size(), bytes.data(), bytes.size());
    if (ZSTD_isError(n) || n != raw)
      throw std::runtime_error("压缩块校验或解压失败");
    position_ = 0;
    return true;
  }
  uint8_t byte() {
    if (!more())
      throw std::runtime_error("压缩记录截断");
    return uint8_t(raw_[position_++]);
  }
  uint64_t uint() {
    uint64_t n = 0;
    for (unsigned i = 0; i < 10; ++i) {
      auto b = byte();
      if (i == 9 && b > 1)
        throw std::runtime_error("变长整数溢出");
      n |= uint64_t(b & 127) << (i * 7);
      if (!(b & 128)) {
        if (i && b == 0)
          throw std::runtime_error("非规范变长整数");
        return n;
      }
    }
    throw std::runtime_error("变长整数过长");
  }
  int64_t sint() {
    auto n = uint();
    return n & 1 ? -int64_t(n >> 1) - 1 : int64_t(n >> 1);
  }
  std::string string(size_t max) {
    auto n = uint();
    if (n > max)
      throw std::runtime_error("字符串长度超限");
    std::string s;
    s.reserve(n);
    for (uint64_t i = 0; i < n; ++i) s.push_back(char(byte()));
    return s;
  }
  void finish() {
    if (more())
      throw std::runtime_error("压缩数据含未声明的记录");
  }
};
void root_write(BlockWriter& out, const RootKey& root) {
  Chain check = root.chain();
  check.offsets = {0};
  validate(check);
  out.byte(root.absolute);
  out.byte(root.bits);
  out.byte(root.mask == "none" ? 0 : root.mask == "topbyte" ? 1 : 2);
  out.uint(root.index);
  out.string(root.module);
  out.string(root.region);
}
RootKey root_read(BlockReader& in) {
  RootKey root;
  auto kind = in.byte();
  if (kind > 1)
    throw std::runtime_error("根类型非法");
  root.absolute = kind;
  root.bits = in.byte();
  auto mask = in.byte();
  if (mask > 2)
    throw std::runtime_error("标签策略非法");
  root.mask = mask == 0 ? "none" : mask == 1 ? "topbyte" : "low48";
  auto index = in.uint();
  if (index > INT32_MAX)
    throw std::runtime_error("模块编号溢出");
  root.index = index;
  root.module = in.string(4096);
  root.region = in.string(16);
  Chain check = root.chain();
  check.offsets = {0};
  validate(check);
  return root;
}
J publish_container(const fs::path& output, const fs::path& body, J meta) {
  meta["format"] = "CSCAN/2";
  meta["codec"] = "zstd";
  meta["block_bytes"] = block_size;
  meta["version"] = version;
  meta["file"] = output.filename().string();
  if (!meta.contains("count_text"))
    meta["count_text"] = std::to_string(meta.at("count").get<uint64_t>());
  if (!meta.contains("complete"))
    meta["complete"] = true;
  auto path = output.parent_path() / ("." + unique_id() + ".publish.part");
  try {
    std::ofstream out(path, std::ios::binary);
    auto head = meta.dump();
    if (head.size() > 4 * 1024 * 1024)
      throw std::runtime_error("元数据过大");
    out.write("CSCAN02\n", 8);
    u32(out, head.size());
    out.write(head.data(), head.size());
    u32(out, header_crc(head));
    std::ifstream input(body, std::ios::binary);
    if (!input)
      throw std::runtime_error("无法读取临时结果");
    char buffer[65536];
    while (input) {
      input.read(buffer, sizeof buffer);
      out.write(buffer, input.gcount());
    }
    if (input.bad())
      throw std::runtime_error("临时结果读取失败");
    out.flush();
    if (!out)
      throw std::runtime_error("结果文件写入失败");
    out.close();
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("输出文件不可读");
    int status = fsync(fd);
    close(fd);
    if (status)
      throw std::runtime_error("结果落盘失败");
    int reserved = open(output.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (reserved < 0)
      throw std::runtime_error("输出路径已存在或不可写");
    close(reserved);
    try {
      fs::rename(path, output);
    } catch (...) {
      std::error_code ec;
      fs::remove(output, ec);
      throw;
    }
    return meta;
  } catch (...) {
    std::error_code ec;
    fs::remove(path, ec);
    throw;
  }
}
}  // namespace
struct StoreWriterImpl {
  fs::path output, body;
  std::ofstream stream;
  std::unique_ptr<BlockWriter> blocks;
  uint64_t count = 0;
  std::optional<RootKey> previous;
  bool finished = false;
  explicit StoreWriterImpl(fs::path path) : output(std::move(path)) {
    if (fs::exists(output))
      throw std::runtime_error("输出文件已经存在，不能覆盖：" + output.filename().string());
    fs::create_directories(output.parent_path());
    body = output.parent_path() / ("." + unique_id() + ".body.part");
    stream.open(body, std::ios::binary);
    if (!stream)
      throw std::runtime_error("无法创建临时结果");
    blocks = std::make_unique<BlockWriter>(stream);
  }
  ~StoreWriterImpl() {
    stream.close();
    std::error_code ec;
    fs::remove(body, ec);
  }
  J finish(J meta) {
    if (finished)
      throw std::runtime_error("结果已保存");
    blocks->finish();
    stream.flush();
    if (!stream)
      throw std::runtime_error("临时结果写入失败");
    stream.close();
    meta["count"] = count;
    if (!meta.contains("representation"))
      meta["representation"] = "chains";
    auto result = publish_container(output, body, std::move(meta));
    finished = true;
    return result;
  }
};
StoreWriter::StoreWriter(fs::path output)
    : impl_(std::make_unique<StoreWriterImpl>(std::move(output))) {}
StoreWriter::~StoreWriter() = default;
uint64_t StoreWriter::count() const {
  return impl_->count;
}
void StoreWriter::push(const Chain& chain) {
  validate(chain);
  if (impl_->count == UINT64_MAX)
    throw std::runtime_error("链数量溢出");
  RootKey key(chain);
  bool changed = !impl_->previous || !(key == *impl_->previous);
  impl_->blocks->byte(changed ? 1 : 0);
  if (changed) {
    root_write(*impl_->blocks, key);
    impl_->previous = key;
  }
  impl_->blocks->uint(chain.offsets.size());
  for (auto value : chain.offsets) impl_->blocks->sint(value);
  ++impl_->count;
}
J StoreWriter::finish(J metadata) {
  return impl_->finish(std::move(metadata));
}
J save_graph(const fs::path& path, const ChainGraph& graph, J metadata) {
  graph.finalize();
  StoreWriterImpl writer(path);
  bool overflow = false;
  writer.count = graph.count(&overflow);
  if (overflow)
    throw std::runtime_error("链数量溢出，无法发布完整结果");
  auto& out = *writer.blocks;
  std::vector<uint8_t> reachable(graph.nodes.size(), 0);
  std::vector<NodeId> stack;
  reachable[0] = reachable[1] = 1;
  for (auto& [key, node] : graph.roots) stack.push_back(node);
  while (!stack.empty()) {
    auto id = stack.back();
    stack.pop_back();
    if (reachable[id])
      continue;
    reachable[id] = 1;
    for (auto& e : graph.nodes[id].edges) stack.push_back(e.child);
  }
  std::vector<NodeId> mapped(graph.nodes.size());
  uint64_t count = 0, edges = 0;
  for (NodeId i = 0; i < graph.nodes.size(); ++i)
    if (reachable[i]) {
      mapped[i] = count++;
      edges += graph.nodes[i].edges.size();
    }
  out.uint(count);
  for (NodeId i = 0; i < graph.nodes.size(); ++i)
    if (reachable[i]) {
      auto& node = graph.nodes[i];
      out.byte(node.terminal);
      out.uint(node.edges.size());
      for (auto& e : node.edges) {
        out.sint(e.offset);
        out.uint(mapped[e.child]);
      }
    }
  out.uint(graph.roots.size());
  for (auto& [key, node] : graph.roots) {
    root_write(out, key);
    out.uint(mapped[node]);
  }
  metadata["representation"] = "graph";
  metadata["graph_nodes"] = count;
  metadata["graph_edges"] = edges;
  return writer.finish(std::move(metadata));
}
struct StoreReaderImpl {
  std::ifstream stream;
  std::unique_ptr<BlockReader> blocks;
  std::shared_ptr<ChainGraph> graph;
  std::unique_ptr<GraphCursor> cursor;
  std::optional<RootKey> previous;
  uint64_t seen = 0, expected = 0;
  bool legacy = false, graph_type = false, ended = false;
  size_t graph_budget;
  explicit StoreReaderImpl(const fs::path& path, size_t budget) : graph_budget(budget) {
    stream.open(path, std::ios::binary);
    if (!stream)
      throw std::runtime_error("无法打开结果文件：" + path.filename().string());
  }
};
StoreReader::StoreReader(const fs::path& path, size_t budget)
    : impl_(std::make_unique<StoreReaderImpl>(path, budget)) {
  char magic[8];
  auto& s = impl_->stream;
  if (!s.read(magic, 8))
    throw std::runtime_error("结果文件过短");
  auto sign = std::string(magic, 8);
  impl_->legacy = sign == "CSCAN01\n";
  if (!impl_->legacy && sign != "CSCAN02\n")
    throw std::runtime_error("不是 CSCAN 结果文件，FastScan OUT/NORM 不能直接读取");
  auto size = read32(s);
  if (size > 4 * 1024 * 1024)
    throw std::runtime_error("结果文件头过大");
  std::string head(size, '\0');
  if (!s.read(head.data(), size))
    throw std::runtime_error("结果文件头截断");
  if (!impl_->legacy && read32(s) != header_crc(head))
    throw std::runtime_error("结果文件头校验失败");
  metadata = J::parse(head);
  if (metadata.value("format", "") != (impl_->legacy ? "CSCAN/1" : "CSCAN/2") ||
      !metadata.contains("count") || !metadata["count"].is_number_unsigned() ||
      !metadata.contains("complete") || !metadata["complete"].is_boolean())
    throw std::runtime_error("结果元数据非法");
  impl_->expected = metadata["count"].get<uint64_t>();
  metadata["count_text"] = std::to_string(impl_->expected);
  if (!impl_->legacy) {
    if (metadata.value("codec", "") != "zstd")
      throw std::runtime_error("不支持的压缩算法");
    auto type = metadata.value("representation", "");
    if (type != "chains" && type != "graph")
      throw std::runtime_error("不支持的结果表示");
    impl_->graph_type = type == "graph";
    impl_->blocks = std::make_unique<BlockReader>(s);
  }
}
StoreReader::~StoreReader() = default;
bool StoreReader::is_graph() const {
  return impl_->graph_type;
}
std::shared_ptr<ChainGraph> StoreReader::graph() {
  if (!is_graph())
    return {};
  if (impl_->graph)
    return impl_->graph;
  auto g = std::make_shared<ChainGraph>(impl_->graph_budget);
  auto& input = *impl_->blocks;
  auto count = input.uint();
  if (count < 2 || count > UINT32_MAX || count > impl_->graph_budget / 96)
    throw std::runtime_error("链图节点数量或内存预算不合法");
  for (NodeId i = 0; i < count; ++i) {
    auto terminal = input.byte();
    if (terminal > 1)
      throw std::runtime_error("链图终点标记非法");
    auto size = input.uint();
    if (size > impl_->graph_budget / sizeof(GraphEdge))
      throw Budget("graph_memory_limit");
    std::vector<GraphEdge> edges;
    edges.reserve(size);
    for (uint64_t j = 0; j < size; ++j) {
      auto offset = input.sint();
      auto child = input.uint();
      if (child >= i || (j && offset <= edges.back().offset))
        throw std::runtime_error("链图含循环、错误索引或未排序的边");
      edges.push_back({offset, NodeId(child)});
    }
    if (g->intern(terminal, std::move(edges)) != i)
      throw std::runtime_error("链图节点不是规范表示");
  }
  auto roots = input.uint();
  if (roots > count + 1000000 || roots > impl_->graph_budget / 64)
    throw std::runtime_error("根数量不合法");
  for (uint64_t i = 0; i < roots; ++i) {
    auto key = root_read(input);
    auto node = input.uint();
    if (node >= count || g->has_root(key) || g->nodes[node].terminal)
      throw std::runtime_error("根节点不合法");
    for (auto& e : g->nodes[node].edges)
      if (e.offset < 0)
        throw std::runtime_error("根偏移不能为负");
    g->root(key, node);
  }
  input.finish();
  bool overflow = false;
  if (g->count(&overflow) != impl_->expected || overflow)
    throw std::runtime_error("链图路径数量与文件头不匹配");
  impl_->graph = g;
  impl_->cursor = std::make_unique<GraphCursor>(*g);
  return g;
}
bool StoreReader::next(Chain& chain) {
  if (impl_->ended)
    return false;
  if (is_graph()) {
    graph();
    if (impl_->cursor->next(chain)) {
      ++impl_->seen;
      return true;
    }
    impl_->ended = true;
    if (impl_->seen != impl_->expected)
      throw std::runtime_error("链图展开数量不匹配");
    return false;
  }
  if (impl_->legacy) {
    auto& s = impl_->stream;
    if (s.peek() == std::char_traits<char>::eof()) {
      impl_->ended = true;
      if (impl_->seen != impl_->expected)
        throw std::runtime_error("旧结果截断或数量不匹配");
      return false;
    }
    if (impl_->seen >= impl_->expected)
      throw std::runtime_error("旧结果含多余记录");
    auto size = read32(s);
    if (size > 16384 || size < 13)
      throw std::runtime_error("旧记录长度非法");
    std::string bytes(size, '\0');
    if (!s.read(bytes.data(), size))
      throw std::runtime_error("旧记录截断");
    if (read32(s) != crc(bytes))
      throw std::runtime_error("旧记录校验失败");
    chain = decode(bytes);
    ++impl_->seen;
    return true;
  }
  auto& in = *impl_->blocks;
  if (impl_->seen == impl_->expected) {
    in.finish();
    impl_->ended = true;
    return false;
  }
  auto tag = in.byte();
  if (tag > 1 || (!tag && !impl_->previous))
    throw std::runtime_error("缺少模块上下文");
  if (tag)
    impl_->previous = root_read(in);
  chain = impl_->previous->chain();
  auto count = in.uint();
  if (!count || count > 257)
    throw std::runtime_error("偏移数量非法");
  chain.offsets.reserve(count);
  for (uint64_t i = 0; i < count; ++i) chain.offsets.push_back(in.sint());
  validate(chain);
  ++impl_->seen;
  return true;
}
void StoreReader::skip(uint64_t n) {
  n = std::min(n, impl_->expected - impl_->seen);
  if (is_graph()) {
    graph();
    impl_->cursor->skip(n);
    impl_->seen += n;
  } else {
    Chain chain;
    while (n-- && next(chain)) {
    };
  }
}
fs::path safe_file(const fs::path& dir, const std::string& name) {
  if (name.empty() || name.size() > 160 || name[0] == '.' || name.find('/') != std::string::npos ||
      name.find('\\') != std::string::npos ||
      name.find_first_of("\r\n\t\"\0", 0, 5) != std::string::npos ||
      fs::path(name).filename() != name)
    throw std::runtime_error("无效的结果文件名");
  auto p = dir / name;
  if (fs::is_symlink(p))
    throw std::runtime_error("结果目录不接受符号链接");
  return p;
}
J list_results(const fs::path& dir) {
  J out = J::array();
  for (auto& e : fs::directory_iterator(dir)) {
    if (e.is_symlink() || !e.is_regular_file() ||
        (e.path().extension() != ".cptr" && e.path().extension() != ".txt"))
      continue;
    try {
      J row;
      if (e.path().extension() == ".txt") {
        TextReader r(e.path());
        Chain first;
        r.next(first);  // Read the bounded header/first record, never the full chain list.
        row = r.metadata;
        row["output_format"] = "text";
      } else {
        StoreReader r(e.path());
        row = r.metadata;
      }
      row["file"] = e.path().filename().string();
      row["bytes"] = e.file_size();
      out.push_back(row);
    } catch (const std::exception& e2) {
      out.push_back({{"file", e.path().filename().string()},
                     {"error", e2.what()},
                     {"count", 0},
                     {"complete", false}});
    }
  }
  std::sort(out.begin(), out.end(), [](auto& a, auto& b) {
    return a["file"].template get<std::string>() > b["file"].template get<std::string>();
  });
  return out;
}
J preview(const fs::path& p, size_t page, size_t size, size_t budget) {
  if (!size || size > 100 || page > UINT64_MAX / size)
    throw std::runtime_error("分页超出范围");
  ChainInput r(p, 64, "none", budget);
  Chain c;
  r.skip(uint64_t(page) * size);
  J rows = J::array();
  while (r.next(c)) {
    rows.push_back(c.json());
    if (rows.size() == size)
      break;
  }
  return {{"metadata", r.metadata()}, {"page", page}, {"rows", rows}};
}
}  // namespace cs
