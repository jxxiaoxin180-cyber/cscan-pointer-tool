#include <unistd.h>

#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <queue>
#include <set>
#include <sstream>

#include "core.hpp"
#include "graph.hpp"
namespace cs {
namespace {
struct Temps {
  std::vector<fs::path> files;
  ~Temps() {
    std::error_code ec;
    for (auto& p : files) fs::remove(p, ec);
  }
  fs::path next(const fs::path& dir) {
    auto p = dir / ("." + unique_id() + ".sort.part");
    files.push_back(p);
    return p;
  }
};
fs::path sorted(const fs::path& input, const fs::path& dir, Temps& temps, Context& ctx,
                const J& req, J& metadata, size_t budget) {
  ChainInput reader(input, req.value("bits", 64), req.value("mask", "none"), budget);
  if (reader.is_graph())
    return input;  // Graph traversal is already sorted and unique.
  std::vector<fs::path> runs;
  std::vector<Chain> chunk;
  Chain c;
  uint64_t done = 0;
  size_t bytes = 0;
  auto flush = [&] {
    if (chunk.empty())
      return;
    std::sort(chunk.begin(), chunk.end());
    chunk.erase(std::unique(chunk.begin(), chunk.end()), chunk.end());
    auto path = temps.next(dir);
    StoreWriter w(path);
    for (auto& x : chunk) w.push(x);
    w.finish({{"complete", true}, {"internal", true}});
    runs.push_back(path);
    chunk.clear();
    bytes = 0;
  };
  while (reader.next(c)) {
    ctx.check();
    ++ctx.visited;
    ++done;
    bytes += c.module.size() + c.region.size() + c.offsets.size() * 8 + 128;
    chunk.push_back(c);
    if (bytes >= 8 * 1024 * 1024) {
      flush();
      ctx.progress("sort", "排序并去重输入结果", {{"records", done}});
    }
  }
  auto source = reader.metadata();
  if (!source.value("complete", true)) {
    metadata["complete"] = false;
    metadata["reason"] = "incomplete_input";
  }
  flush();
  if (runs.empty()) {
    auto path = temps.next(dir);
    StoreWriter w(path);
    w.finish({{"complete", true}});
    return path;
  }
  // Pairwise merge keeps descriptor use and RAM independent of the number of runs.
  while (runs.size() > 1) {
    std::vector<fs::path> next;
    for (size_t i = 0; i < runs.size(); i += 2) {
      if (i + 1 == runs.size()) {
        next.push_back(runs[i]);
        continue;
      }
      StoreReader a(runs[i]), b(runs[i + 1]);
      Chain x, y;
      bool hasx = a.next(x), hasy = b.next(y);
      auto path = temps.next(dir);
      StoreWriter w(path);
      while (hasx || hasy) {
        ctx.check();
        ++ctx.visited;
        if (!hasy || (hasx && x < y)) {
          w.push(x);
          hasx = a.next(x);
        } else if (!hasx || y < x) {
          w.push(y);
          hasy = b.next(y);
        } else {
          w.push(x);
          hasx = a.next(x);
          hasy = b.next(y);
        }
      }
      w.finish({{"complete", true}});
      next.push_back(path);
      std::error_code ec;
      fs::remove(runs[i], ec);
      fs::remove(runs[i + 1], ec);
    }
    runs = std::move(next);
  }
  return runs[0];
}
std::string output_name(const std::string& kind, const std::string& extension = ".cptr") {
  auto now = std::time(nullptr);
  tm t{};
  localtime_r(&now, &t);
  char b[32];
  std::strftime(b, sizeof b, "%Y%m%d-%H%M%S", &t);
  return std::string(b) + "-" + kind + "-" + unique_id().substr(0, 6) + extension;
}
size_t graph_budget_bytes(const J& req) {
  uint64_t mb = 128;
  if (req.contains("graph_memory_mb"))
    mb = number(req["graph_memory_mb"].is_string() ? req["graph_memory_mb"].get<std::string>()
                                                   : req["graph_memory_mb"].dump());
  if (mb < 8 || mb > 4096)
    throw std::runtime_error("graph_memory_mb 超出允许范围 8–4096");
  if (mb > SIZE_MAX / (1024ULL * 1024ULL))
    throw std::runtime_error("图内存预算溢出");
  return size_t(mb * 1024ULL * 1024ULL);
}
J base_meta(const J& req) {
  J config = req;
  config.erase("text");
  config.erase("chains");
  return {{"kind", req.value("kind", "scan")},
          {"created_at", std::time(nullptr)},
          {"complete", true},
          {"reason", ""},
          {"config", config}};
}
void validate_identity(const J& req, const Target& t) {
  if (req.contains("identity") && req["identity"].get<std::string>() != t.identity)
    throw std::runtime_error("所选 PID 已被其他进程复用，请重新连接目标");
  if (req.contains("uid") && req["uid"].get<int>() != t.uid)
    throw std::runtime_error("目标 UID 已改变，请重新选择进程");
}
void validate_bits(const Target& t, int bits) {
  if (t.bits && t.bits != bits)
    throw std::runtime_error("所选位数与目标 ELF 不一致：目标为 " + std::to_string(t.bits) + " 位");
}
}  // namespace
J run(const J& req, const fs::path& dir, Context& ctx, const fs::path& external_text) {
  fs::create_directories(dir);
  auto kind = req.value("kind", "scan");
  const auto output_format = req.value("output_format", "binary");
  if (kind == "filter" && output_format != "binary" && output_format != "text")
    throw std::runtime_error("过滤输出格式只能选择 binary 或 text");
  const bool text_output = kind == "format" || (kind == "filter" && output_format == "text");
  std::string filename = req.value("output", output_name(kind, text_output ? ".txt" : ".cptr"));
  if (text_output) {
    if (fs::path(filename).extension() != ".txt")
      throw std::runtime_error("格式化文本输出使用 .txt 后缀");
  } else if (fs::path(filename).extension() != ".cptr") {
    throw std::runtime_error("结果文件使用 .cptr 后缀");
  }
  auto output = safe_file(dir, filename);
  J meta = base_meta(req);
  ctx.timeout = req.value("timeout", 120);
  if (ctx.timeout < 1 || ctx.timeout > 3600)
    throw std::runtime_error("任务超时范围为 1–3600 秒");
  ctx.max_nodes = req.value("max_nodes", uint64_t(5000000));
  if (!ctx.max_nodes || ctx.max_nodes > 1000000000)
    throw std::runtime_error("工作量上限超出范围");
  if (kind == "backend-status") {
    auto selected = req.value("reader", "paradise");
    try {
      Reader reader(getpid(), selected, req.value("driver_fd", -1));
      return {{"kind", kind},
              {"complete", true},
              {"count", 0},
              {"available", true},
              {"reader_info", reader.diagnostics()},
              {"runtime", runtime_info()}};
    } catch (const std::exception& e) {
      return {{"kind", kind},
              {"complete", false},
              {"count", 0},
              {"available", false},
              {"reason", "backend_unavailable"},
              {"error", e.what()},
              {"runtime", runtime_info()}};
    }
  }
  if (kind == "scan" || kind == "relation") {
    Config c = Config::parse(req);
    if (c.targets.empty())
      throw std::runtime_error("请输入至少一个目标地址");
    Target t = target(c.pid);
    validate_identity(req, t);
    validate_bits(t, c.bits);
    Reader reader(t.pid, c.reader, c.driver_fd);
    ctx.progress("prepare", "目标与读取器准备完成", {{"pid", t.pid}});
    GraphBuild built;
    built.graph = std::make_shared<ChainGraph>(c.graph_memory_mb * 1024ULL * 1024ULL);
    Index index;
    try {
      index = collect(t, reader, c, ctx);
      meta["complete"] = index.complete;
      meta["reason"] = index.reason;
      built = search_graph(index, t, c, ctx);
      if (!built.complete) {
        meta["complete"] = false;
        if (meta["reason"].get<std::string>().empty())
          meta["reason"] = built.reason;
      }
      check_identity(t);
    } catch (const Cancelled&) {
      meta["complete"] = false;
      meta["reason"] = "cancelled";
    } catch (const Budget& e) {
      meta["complete"] = false;
      meta["reason"] = e.what();
    }
    if (!built.graph)
      built.graph = std::make_shared<ChainGraph>(c.graph_memory_mb * 1024ULL * 1024ULL);
    meta["stats"] = index.stats;
    for (auto& [key, value] : built.stats.items()) meta["stats"][key] = value;
    meta["reader_info"] = index.stats.value("reader_info", reader.diagnostics());
    meta["visited"] = ctx.visited;
    meta["target"] = {{"pid", t.pid}, {"uid", t.uid}, {"name", t.name}, {"identity", t.identity}};
    meta["elapsed_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started).count();
    bool overflow = false;
    auto result_count = built.graph->count(&overflow);
    if (overflow)
      meta["count_text"] = ">18446744073709551615";
    ctx.progress("save", "正在保存压缩图结果",
                 {{"result_count", result_count}, {"graph_nodes", built.graph->nodes.size()}});
    return save_graph(output, *built.graph, meta);
  }
  if (kind == "compare" || kind == "count") {
    auto files = req.at("files").get<std::vector<std::string>>();
    if (files.size() < 2 || files.size() > 8)
      throw std::runtime_error("比较需要选择 2–8 份结果");
    std::set<std::string> unique(files.begin(), files.end());
    if (unique.size() != files.size())
      throw std::runtime_error("不能重复选择同一份结果");
    uint64_t limit = 0;
    if (req.contains("limit"))
      limit =
          number(req["limit"].is_string() ? req["limit"].get<std::string>() : req["limit"].dump());
    if (limit > 1000000000)
      throw std::runtime_error("结果上限过大");

    // CSCAN/2 graph results can be intersected by node identity and shared suffixes.
    // Keep the external-sort path below for legacy/chain files and mixed inputs.
    const auto graph_budget = graph_budget_bytes(req);
    std::vector<std::unique_ptr<ChainInput>> graph_inputs;
    graph_inputs.reserve(files.size());
    bool all_graph = true;
    for (const auto& name : files) {
      auto path = safe_file(dir, name);
      graph_inputs.push_back(std::make_unique<ChainInput>(path, req.value("bits", 64),
                                                          req.value("mask", "none"), graph_budget));
      if (!graph_inputs.back()->is_graph())
        all_graph = false;
      if (!graph_inputs.back()->metadata().value("complete", false)) {
        meta["complete"] = false;
        meta["reason"] = "incomplete_input";
      }
    }
    if (all_graph) {
      std::shared_ptr<ChainGraph> common;
      uint64_t count = 0;
      bool overflow = false;
      try {
        common = graph_inputs.front()->graph();
        graph_inputs.front().reset();
        for (size_t i = 1; i < graph_inputs.size(); ++i) {
          ctx.check();
          ctx.progress("compare", "按共享图节点求交集",
                       {{"input", i + 1}, {"inputs", files.size()}});
          common = common->intersect(*graph_inputs[i]->graph(), graph_budget, ctx);
          graph_inputs[i].reset();
        }
        count = common->count(&overflow);
        if (overflow && !limit)
          throw std::runtime_error("交集数量超出 64 位计数，请设置结果上限");
        if (limit && (overflow || count > limit)) {
          if (kind == "compare") {
            common = common->select(limit, 0, 256, &ctx);
            count = common->count(&overflow);
          } else {
            count = limit;
          }
          meta["complete"] = false;
          meta["reason"] = "result_limit";
        }
      } catch (const Cancelled&) {
        meta["complete"] = false;
        meta["reason"] = "cancelled";
        common = std::make_shared<ChainGraph>(graph_budget);
        count = 0;
      } catch (const Budget& e) {
        meta["complete"] = false;
        meta["reason"] = e.what();
        common = std::make_shared<ChainGraph>(graph_budget);
        count = 0;
      }
      if (!common)
        common = std::make_shared<ChainGraph>(graph_budget);
      bool final_overflow = false;
      auto final_count = common->count(&final_overflow);
      if (kind == "count") {
        meta["count"] = count;
        meta["count_text"] = std::to_string(count);
        meta["representation"] = "graph";
        meta["graph_nodes"] = common->nodes.size();
        meta["elapsed_ms"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started)
                .count();
        return meta;
      }
      meta["count"] = final_count;
      meta["representation"] = "graph";
      meta["graph_nodes"] = common->nodes.size();
      if (final_overflow)
        meta["count_text"] = ">18446744073709551615";
      meta["elapsed_ms"] =
          std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started).count();
      return save_graph(output, *common, meta);
    }
    graph_inputs.clear();
    Temps temps;
    std::vector<std::unique_ptr<StoreReader>> inputs;
    std::vector<Chain> heads(files.size());
    std::vector<bool> has(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
      auto p = safe_file(dir, files[i]);
      ChainInput check(p, req.value("bits", 64), req.value("mask", "none"), graph_budget);
      if (!check.metadata().value("complete", true)) {
        meta["complete"] = false;
        meta["reason"] = "incomplete_input";
      }
      ctx.progress("sort", "准备比较 " + files[i]);
      auto path = sorted(p, dir, temps, ctx, req, meta, graph_budget);
      inputs.push_back(std::make_unique<StoreReader>(path, graph_budget));
      has[i] = inputs.back()->next(heads[i]);
    }
    std::unique_ptr<StoreWriter> writer;
    if (kind == "compare")
      writer = std::make_unique<StoreWriter>(output);
    uint64_t count = 0;
    try {
      while (std::all_of(has.begin(), has.end(), [](bool v) { return v; })) {
        ctx.check();
        ++ctx.visited;
        Chain max = *std::max_element(heads.begin(), heads.end());
        bool same = true;
        for (size_t i = 0; i < heads.size(); ++i) {
          while (has[i] && heads[i] < max) {
            has[i] = inputs[i]->next(heads[i]);
            ctx.check();
            ++ctx.visited;
          }
          if (!has[i] || !(heads[i] == max))
            same = false;
        }
        if (!same)
          continue;
        if (limit && count >= limit)
          throw Budget("result_limit");
        if (writer)
          writer->push(max);
        ++count;
        for (size_t i = 0; i < heads.size(); ++i) has[i] = inputs[i]->next(heads[i]);
        if (count % 1000 == 0)
          ctx.progress("compare", "比较共同指针链", {{"result_count", count}});
      }
    } catch (const Cancelled&) {
      meta["complete"] = false;
      meta["reason"] = "cancelled";
    } catch (const Budget& e) {
      meta["complete"] = false;
      meta["reason"] = e.what();
    }
    meta["count"] = count;
    meta["elapsed_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started).count();
    if (writer)
      return writer->finish(meta);
    return meta;
  }
  if (kind == "trace" || kind == "filter" || kind == "reader-test" || kind == "read-memory") {
    Config c = Config::parse(req);
    Target t = target(c.pid);
    validate_identity(req, t);
    validate_bits(t, c.bits);
    Reader reader(c.pid, c.reader, c.driver_fd);
    meta["target"] = {{"pid", t.pid}, {"uid", t.uid}, {"identity", t.identity}};
    if (kind == "read-memory") {
      if (c.targets.size() != 1)
        throw std::runtime_error("内存查看需要一个地址");
      size_t size = req.value("size", size_t(64));
      if (!size || size > 4096)
        throw std::runtime_error("查看长度范围为 1–4096 字节");
      std::vector<unsigned char> bytes(size);
      ctx.check();
      auto n = reader.read_exact(c.targets[0], bytes.data(), size);
      check_identity(t);
      if (n <= 0)
        throw std::runtime_error("内存读取失败：" + reader.diagnostics().dump());
      std::ostringstream dump;
      for (ssize_t offset = 0; offset < n; offset += 16) {
        dump << hex(c.targets[0] + offset) << "  ";
        for (ssize_t j = 0; j < 16; ++j) {
          if (offset + j < n)
            dump << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                 << int(bytes[offset + j]) << " ";
          else
            dump << "   ";
        }
        dump << " ";
        for (ssize_t j = 0; j < 16 && offset + j < n; ++j) {
          auto ch = bytes[offset + j];
          dump << (ch >= 32 && ch < 127 ? char(ch) : '.');
        }
        dump << "\n";
      }
      J values = J::object();
      if (n >= 4) {
        int32_t i;
        float f;
        std::memcpy(&i, bytes.data(), 4);
        std::memcpy(&f, bytes.data(), 4);
        values["int32"] = i;
        values["float32"] = std::isfinite(f) ? J(f) : J(nullptr);
      }
      if (n >= 8) {
        int64_t i;
        uint64_t u;
        double d;
        std::memcpy(&i, bytes.data(), 8);
        std::memcpy(&u, bytes.data(), 8);
        std::memcpy(&d, bytes.data(), 8);
        values["int64"] = std::to_string(i);
        values["uint64"] = std::to_string(u);
        values["pointer64"] = hex(u);
        values["float64"] = std::isfinite(d) ? J(d) : J(nullptr);
      }
      return {{"kind", kind},
              {"complete", n == ssize_t(size)},
              {"reason", n == ssize_t(size) ? "" : "short_read"},
              {"count", 0},
              {"address", hex(c.targets[0])},
              {"requested", size},
              {"bytes_read", n},
              {"dump", dump.str()},
              {"values", values},
              {"reader_info", reader.diagnostics()}};
    }
    if (kind == "reader-test") {
      uint64_t addr = !c.targets.empty() ? c.targets[0] : 0;
      if (!addr)
        for (auto& r : t.regions)
          if (r.perms.find('r') != std::string::npos) {
            addr = r.start;
            break;
          }
      unsigned char data[16]{};
      ctx.check();
      auto n = reader.read_exact(addr, data, sizeof(data));
      check_identity(t);
      if (n <= 0)
        throw std::runtime_error("读取测试失败：当前后端无法读取 " + hex(addr));
      std::string bytes;
      const char* h = "0123456789ABCDEF";
      for (int i = 0; i < n; ++i) {
        bytes += h[data[i] >> 4];
        bytes += h[data[i] & 15];
      }
      return {{"kind", kind},
              {"complete", n == 16},
              {"count", 0},
              {"reader", c.reader},
              {"reader_info", reader.diagnostics()},
              {"address", hex(addr)},
              {"requested", 16},
              {"bytes_read", n},
              {"hex", bytes}};
    }
    if (kind == "trace") {
      std::istringstream stream(req.value("chains", ""));
      std::string line;
      J traces = J::array();
      size_t number = 0;
      while (std::getline(stream, line)) {
        if (line.find_first_not_of(" \t\r") == std::string::npos || line[0] == '#')
          continue;
        if (++number > 1000)
          throw std::runtime_error("一次最多调试 1000 条链");
        ctx.check();
        auto chain = Chain::parse(line, c.bits, c.mask);
        auto result = resolve(chain, t, reader, c.source);
        traces.push_back(result);
      }
      if (traces.empty())
        throw std::runtime_error("请输入需要调试的指针链");
      check_identity(t);
      return {{"kind", kind}, {"complete", true}, {"traces", traces}, {"count", traces.size()}};
    }
    if (fs::exists(output))
      throw std::runtime_error("输出文件已存在，不能覆盖");
    Temps staging;
    auto binary_output = text_output ? staging.next(dir) : output;
    meta["output_format"] = output_format;
    auto finish_filtered = [&](J saved) {
      if (!text_output)
        return saved;
      // Keep the shared graph through filtering, then expand only the retained paths.
      J options = req;
      options["graph_memory_mb"] = c.graph_memory_mb;
      options["bits"] = c.bits;
      options["mask"] = c.mask;
      options["limit"] = 0;
      options["min_depth"] = 0;
      options["max_depth"] = 256;
      J provenance = {{"kind", "filter"},
                      {"source", req.at("file")},
                      {"complete", saved.value("complete", true)},
                      {"reason", saved.value("reason", "")},
                      {"created_at", saved.at("created_at")}};
      auto formatted = format_text(binary_output, output, options, ctx, provenance);
      saved.erase("codec");
      saved.erase("block_bytes");
      saved.update(formatted);
      return saved;
    };
    auto input_path = safe_file(dir, req.at("file").get<std::string>());
    ChainInput input(input_path, c.bits, c.mask, c.graph_memory_mb * 1024ULL * 1024ULL);
    if (kind == "filter" && input.is_graph()) {
      auto source = input.graph();
      auto filtered = filter_graph(*source, t, reader, c, ctx);
      if (!input.metadata().value("complete", true)) {
        meta["complete"] = false;
        meta["reason"] = "incomplete_input";
      }
      if (!filtered.complete) {
        meta["complete"] = false;
        if (meta["reason"].get<std::string>().empty())
          meta["reason"] = filtered.reason;
      }
      meta["stats"] = filtered.stats;
      meta["reader_info"] = reader.diagnostics();
      meta["target"] = {{"pid", t.pid}, {"uid", t.uid}, {"name", t.name}, {"identity", t.identity}};
      meta["inspected"] = filtered.stats.value("graph_states", uint64_t(0));
      meta["failed"] = filtered.stats.value("failed", uint64_t(0));
      meta["elapsed_ms"] =
          std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ctx.started).count();
      return finish_filtered(save_graph(binary_output, *filtered.graph, meta));
    }
    StoreWriter writer(binary_output);
    Chain chain;
    uint64_t inspected = 0, failed = 0, matched = 0;
    std::map<uint64_t, uint64_t> candidates;
    uint64_t other = 0;
    if (!input.metadata().value("complete", true)) {
      meta["complete"] = false;
      meta["reason"] = "incomplete_input";
    }
    try {
      while (input.next(chain)) {
        ctx.check();
        ++ctx.visited;
        if (chain.bits != c.bits)
          throw std::runtime_error("文件指针位数与当前目标不一致");
        ++inspected;
        auto result = resolve(chain, t, reader, c.source);
        if (result["ok"] == true) {
          uint64_t addr = number(result["address"].get<std::string>(), true);
          if (candidates.count(addr) || candidates.size() < 256)
            ++candidates[addr];
          else
            ++other;
          if (c.targets.empty() ||
              std::find(c.targets.begin(), c.targets.end(), addr) != c.targets.end()) {
            if (c.limit && writer.count() >= c.limit)
              throw Budget("result_limit");
            writer.push(chain);
            ++matched;
          }
        } else
          ++failed;
        if (inspected % 500 == 0) {
          check_identity(t);
          ctx.progress("filter", "重新解引用验证",
                       {{"processed", inspected}, {"result_count", matched}, {"failed", failed}});
        }
      }
      check_identity(t);
    } catch (const Cancelled&) {
      meta["complete"] = false;
      meta["reason"] = "cancelled";
    } catch (const Budget& e) {
      meta["complete"] = false;
      meta["reason"] = e.what();
    }
    if (!input.metadata().value("complete", true)) {
      meta["complete"] = false;
      if (meta["reason"] == "")
        meta["reason"] = "incomplete_input";
    }
    J summary = J::array();
    for (auto& [addr, count] : candidates)
      summary.push_back({{"address", hex(addr)}, {"count", count}});
    meta["candidates"] = summary;
    meta["unlisted_candidate_chains"] = other;
    meta["failed"] = failed;
    meta["inspected"] = inspected;
    return finish_filtered(writer.finish(meta));
  }
  if (kind == "format") {
    if (!req.contains("file"))
      throw std::runtime_error("格式化文本需要输入文件");
    auto input = safe_file(dir, req.at("file").get<std::string>());
    J options = req;
    options["graph_memory_mb"] = graph_budget_bytes(req) / (1024ULL * 1024ULL);
    auto result = format_text(input, output, options, ctx);
    result["kind"] = "format";
    return result;
  }
  if (kind == "import") {
    int bits = req.value("bits", 64);
    std::string mask = req.value("mask", "none");
    if (req.contains("file") || !external_text.empty()) {
      auto path = external_text.empty() ? safe_file(dir, req.at("file")) : external_text;
      ChainInput input(path, bits, mask, graph_budget_bytes(req));
      if (input.is_graph()) {
        if (!input.metadata().value("complete", true)) {
          meta["complete"] = false;
          meta["reason"] = "incomplete_input";
        }
        return save_graph(output, *input.graph(), meta);
      }
      StoreWriter writer(output);
      Chain chain;
      while (input.next(chain)) {
        ctx.check();
        ++ctx.visited;
        writer.push(chain);
        if (writer.count() % 10000 == 0)
          ctx.progress("import", "流式导入链文件", {{"result_count", writer.count()}});
      }
      if (!input.metadata().value("complete", true)) {
        meta["complete"] = false;
        meta["reason"] = "incomplete_input";
      }
      return writer.finish(meta);
    }
    std::string content = req.value("text", "");
    if (content.size() > 8 * 1024 * 1024)
      throw std::runtime_error("文本导入最大 8 MiB");
    std::istringstream in(content);
    std::string line;
    StoreWriter writer(output);
    size_t no = 0;
    std::optional<uint64_t> expected;
    while (std::getline(in, line)) {
      ctx.check();
      ++no;
      if (line.empty() || line.find_first_not_of(" \t\r") == std::string::npos)
        continue;
      if (line.rfind("# CSCAN-TXT 1 ", 0) == 0) {
        auto m = J::parse(line.substr(14));
        if (m.contains("count") && !expected) {
          if (!m["count"].is_number_unsigned())
            throw std::runtime_error("文本计数非法");
          expected = m["count"].get<uint64_t>();
        }
        bits = m.value("bits", bits);
        mask = m.value("mask", mask);
        if (!m.value("complete", true)) {
          meta["complete"] = false;
          meta["reason"] = "incomplete_input";
        }
        continue;
      }
      if (line[0] == '#')
        continue;
      try {
        writer.push(Chain::parse(line, bits, mask));
      } catch (const std::exception& e) {
        throw std::runtime_error("第 " + std::to_string(no) + " 行：" + e.what());
      }
    }
    if (expected && writer.count() != *expected)
      throw std::runtime_error("文本链数量不匹配或文件截断");
    if (!writer.count() && !expected)
      throw std::runtime_error("没有可导入的指针链");
    return writer.finish(meta);
  }
  throw std::runtime_error("不支持的操作：" + kind);
}
}  // namespace cs
