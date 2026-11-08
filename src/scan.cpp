#include <unistd.h>

#include <cmath>
#include <cstring>
#include <thread>

#include "core.hpp"
namespace cs {
static bool selected(const std::vector<std::string>& a, const std::string& s) {
  return std::find(a.begin(), a.end(), s) != a.end();
}
Index collect(const Target& t, Reader& primary, const Config& c, Context& ctx) {
  Index out;
  const size_t pointer_size = c.bits / 8, chunk_size = 256 * 1024;
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0)
    throw std::runtime_error("无法读取运行时页大小");
  std::vector<std::pair<uint64_t, uint64_t>> spans;
  uint64_t total = 0, task_count = 0;
  for (auto& region : t.regions) {
    if (!c.nonread && region.perms.find('r') == std::string::npos)
      continue;
    if (!selected(c.kinds, region.kind))
      continue;
    if (c.spans.empty())
      spans.emplace_back(region.start, region.end);
    else
      for (auto& slice : c.spans) {
        auto first = std::max(slice.first, region.start), last = std::min(slice.second, region.end);
        if (first < last)
          spans.emplace_back(first, last);
      }
  }
  for (auto& s : spans) {
    total += s.second - s.first;
    task_count += (s.second - s.first + chunk_size - 1) / chunk_size;
  }
  if (!total)
    throw std::runtime_error("所选范围没有可采集内存");
  bool kernel = c.reader == "paradise" || c.reader == "paradise35" || c.reader == "paradise-hook";
  unsigned workers =
      kernel ? 1
             : (c.threads ? unsigned(c.threads)
                          : std::min(4u, std::max(1u, std::thread::hardware_concurrency())));
  workers = std::max(1u, unsigned(std::min<uint64_t>(workers, task_count)));
  size_t cap = c.memory_mb * 1024 * 1024 / sizeof(Pointer);
  out.pointers.reserve(cap);
  std::mutex queue_lock, output_lock, report_lock, error_lock;
  size_t span_index = 0;
  uint64_t next_address = spans.front().first, last_report = 0;
  std::atomic_bool stopped{false};
  std::atomic<uint64_t> done{0}, valid{0}, failed{0}, calls{0};
  std::exception_ptr error;
  std::vector<J> diagnostics(workers);
  auto mapped = [&](uint64_t address) {
    auto it = std::upper_bound(t.regions.begin(), t.regions.end(), address,
                               [](uint64_t a, const Region& r) { return a < r.start; });
    return it != t.regions.begin() && address < std::prev(it)->end;
  };
  struct Task {
    uint64_t start, end, read_end;
  };
  auto take = [&](Task& task) {
    std::lock_guard<std::mutex> guard(queue_lock);
    if (stopped)
      return false;
    while (span_index < spans.size() && next_address >= spans[span_index].second) {
      ++span_index;
      if (span_index < spans.size())
        next_address = spans[span_index].first;
    }
    if (span_index == spans.size())
      return false;
    task.start = next_address;
    task.end =
        next_address + std::min<uint64_t>(chunk_size, spans[span_index].second - next_address);
    task.read_end =
        task.end + std::min<uint64_t>(pointer_size - 1, spans[span_index].second - task.end);
    next_address = task.end;
    return true;
  };
  ctx.progress("collect", "并行采集有效指针",
               {{"total_bytes", total}, {"threads", workers}, {"kernel_serial", kernel}});
  check_identity(t);
  auto worker = [&](unsigned worker_id) {
    std::unique_ptr<Reader> local;
    Reader* reader = &primary;
    try {
      if (workers > 1) {
        local = std::make_unique<Reader>(t.pid, c.reader);
        reader = local.get();
      }
      std::vector<unsigned char> buffer(chunk_size + 16);
      std::vector<Pointer> batch;
      batch.reserve(4096);
      Task task;
      while (take(task)) {
        ctx.check();
        batch.clear();
        uint64_t cursor = task.start;
        size_t tail = 0;
        while (cursor < task.read_end && !stopped) {
          ctx.check();
          auto requested = std::min<uint64_t>(chunk_size, task.read_end - cursor);
          auto n = reader->read(cursor, buffer.data() + tail, requested);
          ++calls;
          if (n > ssize_t(requested))
            throw std::runtime_error("读取器返回长度超过请求");
          if (n <= 0) {
            auto skip = std::min<uint64_t>(page - cursor % page, task.read_end - cursor);
            auto covered = cursor < task.end ? std::min<uint64_t>(skip, task.end - cursor) : 0;
            failed += covered;
            done += covered;
            cursor += skip;
            tail = 0;
          } else {
            auto bytes = tail + size_t(n);
            auto base = cursor - tail;
            auto first = (c.step - base % c.step) % c.step;
            for (size_t off = first; off + pointer_size <= bytes; off += c.step) {
              auto address = base + off;
              if (address < task.start || address >= task.end)
                continue;
              uint64_t value = 0;
              std::memcpy(&value, buffer.data() + off, pointer_size);
              value = mask_pointer(value, c.mask);
              if (value && mapped(value))
                batch.push_back({address, value});
            }
            auto covered = cursor < task.end ? std::min<uint64_t>(n, task.end - cursor) : 0;
            valid += covered;
            done += covered;
            cursor += n;
            tail = std::min(pointer_size - 1, bytes);
            std::memmove(buffer.data(), buffer.data() + bytes - tail, tail);
          }
        }
        {
          std::lock_guard<std::mutex> guard(output_lock);
          size_t available = cap - out.pointers.size();
          size_t accepted = std::min(available, batch.size());
          out.pointers.insert(out.pointers.end(), batch.begin(), batch.begin() + accepted);
          if (accepted < batch.size()) {
            out.complete = false;
            out.reason = "memory_limit";
            stopped = true;
          }
        }
        {
          std::lock_guard<std::mutex> guard(report_lock);
          auto current = done.load();
          if (current - last_report >= 4 * 1024 * 1024 || current == total) {
            last_report = current;
            check_identity(t);
            size_t count;
            {
              std::lock_guard<std::mutex> lock(output_lock);
              count = out.pointers.size();
            }
            ctx.progress("collect", "采集内存",
                         {{"read_bytes", current},
                          {"valid_bytes", valid.load()},
                          {"failed_bytes", failed.load()},
                          {"total_bytes", total},
                          {"pointers", count},
                          {"threads", workers}});
          }
        }
      }
    } catch (...) {
      std::lock_guard<std::mutex> guard(error_lock);
      if (!error)
        error = std::current_exception();
      stopped = true;
    }
    diagnostics[worker_id] = reader->diagnostics();
  };
  if (workers == 1)
    worker(0);
  else {
    std::vector<std::thread> threads;
    try {
      for (unsigned i = 0; i < workers; ++i) threads.emplace_back(worker, i);
    } catch (...) {
      stopped = true;
      for (auto& thread : threads) thread.join();
      throw;
    }
    for (auto& thread : threads) thread.join();
  }
  if (error) {
    try {
      std::rethrow_exception(error);
    } catch (const Budget& e) {
      out.complete = false;
      out.reason = e.what();
    }
  }
  if (failed) {
    out.complete = false;
    if (out.reason.empty())
      out.reason = "read_failures";
  }
  J reader_info = {{"backend", c.reader},
                   {"threads", workers},
                   {"read_verified", valid > 0},
                   {"read_calls", calls.load()},
                   {"workers", diagnostics}};
  out.stats = {{"total_bytes", total},        {"processed_bytes", done.load()},
               {"valid_bytes", valid.load()}, {"failed_bytes", failed.load()},
               {"read_calls", calls.load()},  {"pointer_count", out.pointers.size()},
               {"page_size", page},           {"threads", workers},
               {"reader_info", reader_info}};
  if (!valid)
    throw std::runtime_error("未读取到有效字节；请检查目标、读取器及运行权限");
  check_identity(t);
  return out;
}
bool Chain::operator<(const Chain& o) const {
  return std::tie(absolute, module, index, region, bits, mask, offsets) <
         std::tie(o.absolute, o.module, o.index, o.region, o.bits, o.mask, o.offsets);
}
bool Chain::operator==(const Chain& o) const {
  return !(*this < o) && !(o < *this);
}
uint64_t search(Index& index, const Target& t, const Config& c, Context& ctx, Emit emit) {
  if (c.targets.empty())
    throw std::runtime_error("请输入目标地址");
  std::vector<Region> roots;
  for (auto& r : t.regions)
    if (r.root && (c.roots.empty() || selected(c.roots, r.id)))
      roots.push_back(r);
  for (auto& id : c.roots)
    if (std::none_of(roots.begin(), roots.end(), [&](auto& r) { return r.id == id; }))
      throw std::runtime_error("所选模块已经失效：" + id);
  if (!c.relation && roots.empty())
    throw std::runtime_error("没有可用的根模块");
  auto& p = index.pointers;
  ctx.progress("index", "正在建立指针索引", {{"pointers", p.size()}});
  if (c.relation)
    std::sort(p.begin(), p.end(), [](auto& a, auto& b) {
      return std::tie(a.address, a.value) < std::tie(b.address, b.value);
    });
  else
    std::sort(p.begin(), p.end(), [](auto& a, auto& b) {
      return std::tie(a.value, a.address) < std::tie(b.value, b.address);
    });
  ctx.check();
  ctx.progress("search", c.relation ? "搜索地址之间的路径" : "从目标地址反向寻找模块根");
  uint64_t count = 0;
  std::vector<int64_t> tail;
  auto output = [&](const Chain& chain) {
    if (c.limit && count >= c.limit)
      throw Budget("result_limit");
    emit(chain);
    ++count;
    if (count % 1000 == 0)
      ctx.progress("search", "正在生成指针链", {{"result_count", count}});
  };
  auto tick = [&] {
    ctx.check();
    ++ctx.visited;
    if (ctx.visited % 10000 == 0)
      ctx.progress("search", "搜索指针路径", {{"result_count", count}});
  };
  if (!c.relation) {
    std::function<void(uint64_t, int)> walk = [&](uint64_t a, int level) {
      tick();
      auto root = std::find_if(roots.begin(), roots.end(),
                               [&](auto& r) { return a >= r.start && a < r.end; });
      if (root != roots.end()) {
        if (a - root->start > INT64_MAX)
          throw std::runtime_error("模块根偏移超出支持范围");
        Chain chain;
        chain.module = root->name;
        chain.index = root->index;
        chain.region = root->kind;
        chain.bits = c.bits;
        chain.mask = c.mask;
        chain.offsets.push_back(a - root->start);
        chain.offsets.insert(chain.offsets.end(), tail.rbegin(), tail.rend());
        output(chain);
        return;
      }
      if (level >= c.depth)
        return;
      uint64_t off = c.layer_offsets[level + 1], lo = a >= off ? a - off : 0,
               hi = c.negative ? (a > UINT64_MAX - off ? UINT64_MAX : a + off) : a;
      auto it = std::lower_bound(p.begin(), p.end(), lo,
                                 [](const Pointer& p, uint64_t v) { return p.value < v; });
      for (; it != p.end() && it->value <= hi; ++it) {
        int64_t delta = it->value <= a ? int64_t(a - it->value) : -int64_t(it->value - a);
        tail.push_back(delta);
        walk(it->address, level + 1);
        tail.pop_back();
      }
    };
    for (auto addr : c.targets) walk(addr, 0);
  } else {
    std::function<void(uint64_t, int)> walk = [&](uint64_t base, int level) {
      tick();
      if (level >= c.depth)
        return;
      uint64_t off = c.offset, hi = base > UINT64_MAX - off ? UINT64_MAX : base + off;
      auto it = std::lower_bound(p.begin(), p.end(), base,
                                 [](const Pointer& p, uint64_t a) { return p.address < a; });
      for (; it != p.end() && it->address <= hi; ++it) {
        if (level == 0 && it->address == hi)
          break;
        tail.push_back(it->address - base);
        for (auto dest : c.targets)
          if (dest >= it->value && dest - it->value <= off) {
            Chain chain;
            chain.absolute = true;
            chain.bits = c.bits;
            chain.mask = c.mask;
            chain.offsets = tail;
            chain.offsets.push_back(dest - it->value);
            output(chain);
          }
        if (level + 1 < c.depth)
          walk(it->value, level + 1);
        tail.pop_back();
      }
    };
    walk(c.source, 0);
  }
  return count;
}
J resolve(const Chain& c, const Target& t, Reader& r, uint64_t source) {
  J out = {{"chain", c.line()}, {"ok", false}, {"steps", J::array()}};
  try {
    uint64_t base = source;
    if (c.absolute) {
      if (!source)
        throw std::runtime_error("这条关系链需要填写本次的起始地址");
    } else {
      auto it = std::find_if(t.regions.begin(), t.regions.end(), [&](auto& reg) {
        return reg.root && reg.name == c.module && reg.index == c.index && reg.kind == c.region;
      });
      if (it == t.regions.end())
        throw std::runtime_error("当前进程没有对应模块段");
      base = it->start;
    }
    if (c.offsets.empty())
      throw std::runtime_error("空偏移序列");
    out["base"] = hex(base);
    uint64_t a = add(base, c.offsets[0], c.bits);
    out["root_address"] = hex(a);
    for (size_t i = 1; i < c.offsets.size(); ++i) {
      uint64_t raw = 0;
      J step = {{"level", i}, {"address", hex(a)}, {"offset", std::to_string(c.offsets[i])}};
      auto n = r.read_exact(a, &raw, c.bits / 8);
      if (n != c.bits / 8) {
        step["ok"] = false;
        step["error"] = "指针读取失败或短读";
        out["steps"].push_back(step);
        throw std::runtime_error("第 " + std::to_string(i) + " 层读取失败");
      }
      uint64_t value = mask_pointer(raw, c.mask);
      step["pointer"] = hex(value);
      step["raw"] = hex(raw);
      a = add(value, c.offsets[i], c.bits);
      step["next"] = hex(a);
      step["ok"] = true;
      out["steps"].push_back(step);
    }
    out["ok"] = true;
    out["address"] = hex(a);
    uint64_t raw = 0;
    auto n = r.read_exact(a, &raw, 8);
    out["value_readable"] = n >= 4;
    if (n >= 4) {
      int32_t iv;
      float fv;
      std::memcpy(&iv, &raw, 4);
      std::memcpy(&fv, &raw, 4);
      out["int32"] = iv;
      out["float32"] = std::isfinite(fv) ? J(fv) : J(nullptr);
    }
    if (n == 8)
      out["uint64"] = std::to_string(raw);
  } catch (const std::exception& e) {
    out["error"] = e.what();
  }
  return out;
}
}  // namespace cs
