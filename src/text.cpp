#include <fcntl.h>
#include <unistd.h>

#include "core.hpp"
#include "graph.hpp"
namespace cs {
namespace {
// The buffer is fixed-size; a corrupt multi-GB single line never causes unbounded allocation.
bool line_read(std::istream& stream, std::string& line) {
  line.clear();
  char c;
  while (stream.get(c)) {
    if (c == '\n')
      return true;
    if (line.size() >= 16384)
      throw std::runtime_error("文本单行超过 16 KiB");
    line.push_back(c);
  }
  if (stream.bad())
    throw std::runtime_error("文本文件读取失败");
  return !line.empty();
}
bool is_binary(const fs::path& path) {
  std::ifstream f(path, std::ios::binary);
  char sign[8]{};
  f.read(sign, 8);
  return std::string(sign, 8) == "CSCAN01\n" || std::string(sign, 8) == "CSCAN02\n";
}
}  // namespace
struct TextReaderImpl {
  std::ifstream stream;
  int bits;
  std::string mask;
  size_t line = 0;
  uint64_t seen = 0;
  std::optional<uint64_t> expected;
  bool ended = false;
  explicit TextReaderImpl(const fs::path& p, int b, std::string m)
      : stream(p), bits(b), mask(std::move(m)) {
    if (!stream)
      throw std::runtime_error("无法读取文本文件");
  }
};
TextReader::TextReader(const fs::path& p, int bits, std::string mask)
    : impl_(std::make_unique<TextReaderImpl>(p, bits, std::move(mask))) {
  metadata = {
      {"format", "text"}, {"complete", true}, {"count_known", false}, {"count", uint64_t(0)}};
}
TextReader::~TextReader() = default;
bool TextReader::next(Chain& chain) {
  if (impl_->ended)
    return false;
  std::string line;
  while (line_read(impl_->stream, line)) {
    ++impl_->line;
    if (line.empty() || line.find_first_not_of(" \t\r") == std::string::npos)
      continue;
    if (line.rfind("# CSCAN-TXT 1 ", 0) == 0) {
      auto header = J::parse(line.substr(14));
      for (const auto* key : {"kind", "created_at", "source", "version", "output_format"})
        if (header.contains(key))
          metadata[key] = header[key];
      impl_->bits = header.value("bits", impl_->bits);
      impl_->mask = header.value("mask", impl_->mask);
      if (!header.value("complete", true)) {
        metadata["complete"] = false;
        metadata["reason"] = header.value("reason", "incomplete_input");
      }
      if (header.contains("count") && !impl_->expected) {
        if (!header["count"].is_number_unsigned())
          throw std::runtime_error("文本计数非法");
        impl_->expected = header["count"];
        metadata["count"] = *impl_->expected;
        metadata["count_known"] = true;
      }
      continue;
    }
    if (line[0] == '#')
      continue;
    try {
      chain = Chain::parse(line, impl_->bits, impl_->mask);
    } catch (const std::exception& e) {
      throw std::runtime_error("第 " + std::to_string(impl_->line) + " 行：" + e.what());
    }
    if (impl_->expected && impl_->seen >= *impl_->expected)
      throw std::runtime_error("文本含超出声明数量的链");
    ++impl_->seen;
    return true;
  }
  impl_->ended = true;
  if (impl_->expected && impl_->seen != *impl_->expected)
    throw std::runtime_error("文本链数量不匹配或文件截断");
  metadata["count"] = impl_->seen;
  metadata["count_text"] = std::to_string(impl_->seen);
  metadata["count_known"] = true;
  return false;
}
ChainInput::ChainInput(const fs::path& p, int bits, std::string mask, size_t memory) {
  if (is_binary(p))
    binary_ = std::make_unique<StoreReader>(p, memory);
  else
    text_ = std::make_unique<TextReader>(p, bits, std::move(mask));
}
bool ChainInput::next(Chain& c) {
  return binary_ ? binary_->next(c) : text_->next(c);
}
void ChainInput::skip(uint64_t count) {
  if (binary_)
    binary_->skip(count);
  else {
    Chain chain;
    while (count-- && text_->next(chain)) {
    }
  }
}
J ChainInput::metadata() const {
  return binary_ ? binary_->metadata : text_->metadata;
}
bool ChainInput::is_graph() const {
  return binary_ && binary_->is_graph();
}
std::shared_ptr<ChainGraph> ChainInput::graph() {
  return binary_ ? binary_->graph() : nullptr;
}
J format_text(const fs::path& input, const fs::path& output, const J& options, Context& ctx,
              J provenance) {
  if (fs::exists(output))
    throw std::runtime_error("文本输出文件已存在");
  int min = options.value("min_depth", 0), max = options.value("max_depth", 256);
  if (min < 0 || max > 256 || min > max)
    throw std::runtime_error("格式化层级范围不合法");
  uint64_t limit = 0;
  if (options.contains("limit"))
    limit = number(options["limit"].is_string() ? options["limit"].get<std::string>()
                                                : options["limit"].dump());
  auto temporary = output.parent_path() / ("." + unique_id() + ".text.part"),
       publish = output.parent_path() / ("." + unique_id() + ".text-publish.part");
  J metadata = {{"kind", "format"},
                {"version", version},
                {"complete", true},
                {"count", uint64_t(0)},
                {"reason", ""},
                {"file", output.filename().string()},
                {"source", input.filename().string()},
                {"min_depth", min},
                {"max_depth", max}};
  metadata.update(provenance);
  metadata["file"] = output.filename().string();
  metadata["format"] = "CSCAN-TXT/1";
  metadata["output_format"] = "text";
  metadata["representation"] = "text";
  uint64_t count = 0;
  try {
    ChainInput reader(input, options.value("bits", 64), options.value("mask", "none"),
                      options.value("graph_memory_mb", uint64_t(128)) * 1024 * 1024);
    std::ofstream body(temporary);
    if (!body)
      throw std::runtime_error("文本输出目录不可写");
    std::optional<RootKey> previous;
    Chain chain;
    try {
      while (reader.next(chain)) {
        ctx.check();
        ++ctx.visited;
        auto depth = int(chain.offsets.size()) - 1;
        if (depth < min || depth > max)
          continue;
        if (limit && count >= limit) {
          metadata["complete"] = false;
          metadata["reason"] = "result_limit";
          break;
        }
        RootKey key(chain);
        if (!previous || previous->bits != key.bits || previous->mask != key.mask) {
          body << "# CSCAN-TXT 1 " << J({{"bits", key.bits}, {"mask", key.mask}}).dump() << "\n";
          previous = key;
        }
        body << chain.line() << "\n";
        if (!body)
          throw std::runtime_error("文本写入失败");
        ++count;
        if (count % 10000 == 0)
          ctx.progress("format", "流式展开文本", {{"result_count", count}});
      }
    } catch (const Cancelled&) {
      metadata["complete"] = false;
      metadata["reason"] = "cancelled";
    } catch (const Budget& e) {
      metadata["complete"] = false;
      metadata["reason"] = e.what();
    }
    auto source = reader.metadata();
    if (!source.value("complete", true)) {
      metadata["complete"] = false;
      if (metadata["reason"] == "")
        metadata["reason"] = "incomplete_input";
    }
    metadata["count"] = count;
    metadata["count_text"] = std::to_string(count);
    body.flush();
    if (!body)
      throw std::runtime_error("文本刷新失败");
    body.close();
    std::ofstream out(publish);
    out << "# CSCAN-TXT 1 " << metadata.dump() << "\n";
    std::ifstream from(temporary, std::ios::binary);
    char buffer[65536];
    while (from) {
      from.read(buffer, sizeof buffer);
      out.write(buffer, from.gcount());
    }
    if (from.bad())
      throw std::runtime_error("文本临时文件读取失败");
    out.flush();
    if (!out)
      throw std::runtime_error("文本文件写入失败");
    out.close();
    int fd = open(publish.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("无法落盘文本文件");
    int synced = fsync(fd);
    close(fd);
    if (synced)
      throw std::runtime_error("文本落盘失败");
    int reservation = open(output.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (reservation < 0)
      throw std::runtime_error("文本输出已存在或不可写");
    close(reservation);
    try {
      fs::rename(publish, output);
    } catch (...) {
      std::error_code ec;
      fs::remove(output, ec);
      throw;
    }
    std::error_code ec;
    fs::remove(temporary, ec);
    metadata["elapsed_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started).count();
    return metadata;
  } catch (...) {
    std::error_code ec;
    fs::remove(temporary, ec);
    fs::remove(publish, ec);
    throw;
  }
}
}  // namespace cs
