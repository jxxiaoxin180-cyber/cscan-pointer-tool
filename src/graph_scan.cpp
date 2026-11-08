#include <map>
#include <set>
#include <tuple>
#include <unordered_map>

#include "graph.hpp"
namespace cs {
namespace {
void work(Context& ctx) {
  ctx.check();
  ++ctx.visited;
}
RootKey key_for(const Region& r, const Config& c) {
  RootKey k;
  k.module = r.name;
  k.region = r.kind;
  k.index = r.index;
  k.bits = c.bits;
  k.mask = c.mask;
  return k;
}
std::vector<Region> roots_for(const Target& t, const Config& c) {
  std::vector<Region> roots;
  for (auto& r : t.regions)
    if (r.root &&
        (c.roots.empty() || std::find(c.roots.begin(), c.roots.end(), r.id) != c.roots.end()))
      roots.push_back(r);
  for (auto& id : c.roots)
    if (std::none_of(roots.begin(), roots.end(), [&](auto& r) { return r.id == id; }))
      throw std::runtime_error("所选模块已经失效：" + id);
  return roots;
}
const Region* locate(const std::vector<Region>& roots, uint64_t address) {
  auto it = std::upper_bound(roots.begin(), roots.end(), address,
                             [](uint64_t a, const Region& r) { return a < r.start; });
  if (it == roots.begin())
    return nullptr;
  --it;
  return address < it->end ? &*it : nullptr;
}
}  // namespace
GraphBuild search_graph(Index& index, const Target& t, const Config& c, Context& ctx) {
  GraphBuild result;
  result.graph = std::make_shared<ChainGraph>(c.graph_memory_mb * 1024 * 1024);
  auto& g = *result.graph;
  auto& p = index.pointers;
  auto roots = roots_for(t, c);
  if (c.targets.empty())
    throw std::runtime_error("请输入目标地址");
  if (!c.relation && roots.empty())
    throw std::runtime_error("没有可用的根模块");
  uint64_t edges_examined = 0;
  size_t temporary = 0;
  ctx.progress("index", "建立指针索引，准备共享链图", {{"pointers", p.size()}});
  if (c.relation)
    std::sort(p.begin(), p.end(), [](auto& a, auto& b) {
      return std::tie(a.address, a.value) < std::tie(b.address, b.value);
    });
  else
    std::sort(p.begin(), p.end(), [](auto& a, auto& b) {
      return std::tie(a.value, a.address) < std::tie(b.value, b.address);
    });
  try {
    if (!c.relation) {
      std::map<uint64_t, NodeId> frontier;
      std::set<uint64_t> targets(c.targets.begin(), c.targets.end());
      auto accept = [&](uint64_t address, NodeId node, std::map<uint64_t, NodeId>& next) {
        const auto* root = locate(roots, address);
        if (root) {
          auto offset = address - root->start;
          if (offset > INT64_MAX)
            throw std::runtime_error("模块根偏移溢出");
          auto start = g.intern(false, {{int64_t(offset), node}});
          g.root(key_for(*root, c), start, &ctx);
        } else
          next[address] = node;
      };
      for (auto address : targets) accept(address, 1, frontier);
      for (int level = 1; level <= c.depth && !frontier.empty(); ++level) {
        ctx.check();
        std::unordered_map<uint64_t, std::vector<GraphEdge>> matches;
        temporary = 0;
        uint64_t offset = c.layer_offsets.at(level);
        for (auto& [address, suffix] : frontier) {
          work(ctx);
          uint64_t lo = address >= offset ? address - offset : 0,
                   hi = c.negative ? (address > UINT64_MAX - offset ? UINT64_MAX : address + offset)
                                   : address;
          auto it = std::lower_bound(p.begin(), p.end(), lo,
                                     [](const Pointer& p, uint64_t v) { return p.value < v; });
          for (; it != p.end() && it->value <= hi; ++it) {
            work(ctx);
            ++edges_examined;
            auto found = matches.find(it->address);
            if (found == matches.end()) {
              g.account(144);
              temporary += 144;
              found = matches.emplace(it->address, std::vector<GraphEdge>{}).first;
            }
            g.account(48);
            temporary += 48;
            auto delta =
                it->value <= address ? int64_t(address - it->value) : -int64_t(it->value - address);
            found->second.push_back({delta, suffix});
          }
        }
        std::vector<uint64_t> ordered;
        ordered.reserve(matches.size());
        for (auto& x : matches) ordered.push_back(x.first);
        std::sort(ordered.begin(), ordered.end());
        std::map<uint64_t, NodeId> next;
        for (auto address : ordered) {
          work(ctx);
          auto node = g.intern(false, std::move(matches[address]));
          accept(address, node, next);
        }
        frontier = std::move(next);
        g.unaccount(temporary);
        temporary = 0;
        bool over = false;
        auto count = g.count(&over);
        ctx.progress(
            "search", "完成第 " + std::to_string(level) + " 层共享链图",
            {{"level", level},
             {"frontier", frontier.size()},
             {"graph_nodes", g.nodes.size()},
             {"edges_examined", edges_examined},
             {"result_count_text", over ? ">18446744073709551615" : std::to_string(count)}});
      }
    } else {
      std::map<std::pair<uint64_t, int>, NodeId> memo;
      std::set<uint64_t> targets(c.targets.begin(), c.targets.end());
      std::function<NodeId(uint64_t, int)> walk = [&](uint64_t base, int remain) -> NodeId {
        if (!remain)
          return 0;
        auto key = std::make_pair(base, remain);
        auto hit = memo.find(key);
        if (hit != memo.end())
          return hit->second;
        work(ctx);
        uint64_t hi = base > UINT64_MAX - c.offset ? UINT64_MAX : base + c.offset;
        std::vector<GraphEdge> edges;
        auto it = std::lower_bound(p.begin(), p.end(), base,
                                   [](const Pointer& p, uint64_t a) { return p.address < a; });
        for (; it != p.end() && it->address <= hi; ++it) {
          if (remain == c.depth && it->address == hi)
            break;
          work(ctx);
          ++edges_examined;
          std::vector<GraphEdge> ends;
          for (auto dest : targets)
            if (dest >= it->value && dest - it->value <= c.offset)
              ends.push_back({int64_t(dest - it->value), 1});
          auto suffix = g.intern(false, std::move(ends));
          if (remain > 1)
            suffix = g.unite(suffix, walk(it->value, remain - 1), &ctx);
          if (suffix)
            edges.push_back({int64_t(it->address - base), suffix});
        }
        auto node = g.intern(false, std::move(edges));
        g.account(80);
        memo[key] = node;
        return node;
      };
      RootKey key;
      key.absolute = true;
      key.bits = c.bits;
      key.mask = c.mask;
      g.root(key, walk(c.source, c.depth), &ctx);
    }
  } catch (const Cancelled&) {
    result.complete = false;
    result.reason = "cancelled";
  } catch (const Budget& e) {
    result.complete = false;
    result.reason = e.what();
  }
  if (temporary)
    g.unaccount(temporary);
  bool overflow = false;
  auto count = g.count(&overflow);
  result.stats = {
      {"graph_nodes", g.nodes.size()},
      {"graph_memory_estimate", g.peak()},
      {"edges_examined", edges_examined},
      {"chains_before_limit", overflow ? ">18446744073709551615" : std::to_string(count)}};
  if (c.limit && (overflow || count > c.limit)) {
    result.graph = g.select(c.limit);
    result.complete = false;
    if (result.reason.empty())
      result.reason = "result_limit";
  } else if (overflow)
    throw std::runtime_error("链数量超出 64 位计数，请设置结果上限");
  return result;
}
GraphBuild filter_graph(const ChainGraph& input, const Target& t, Reader& r, const Config& c,
                        Context& ctx) {
  input.finalize();
  GraphBuild result;
  result.graph = std::make_shared<ChainGraph>(c.graph_memory_mb * 1024 * 1024);
  auto& out = *result.graph;
  using Key = std::tuple<NodeId, uint64_t, int, std::string>;
  struct Answer {
    NodeId node;
    uint64_t failed;
  };
  std::map<Key, Answer> memo;
  std::map<std::pair<uint64_t, int>, std::pair<bool, uint64_t>> reads;
  std::set<uint64_t> candidate_addresses;
  std::set<uint64_t> targets(c.targets.begin(), c.targets.end());
  uint64_t failed = 0, processed = 0;
  std::function<Answer(NodeId, uint64_t, const RootKey&)> walk =
      [&](NodeId n, uint64_t address, const RootKey& root) -> Answer {
    Key key{n, address, root.bits, root.mask};
    auto hit = memo.find(key);
    if (hit != memo.end())
      return hit->second;
    work(ctx);
    ++processed;
    auto& node = input.nodes[n];
    bool terminal = node.terminal && (targets.empty() || targets.count(address));
    if (node.terminal && candidate_addresses.size() < 256)
      candidate_addresses.insert(address);
    std::vector<GraphEdge> edges;
    uint64_t errors = 0;
    if (!node.edges.empty()) {
      auto rk = std::make_pair(address, root.bits);
      auto it = reads.find(rk);
      if (it == reads.end()) {
        uint64_t raw = 0;
        bool ok = r.read_exact(address, &raw, root.bits / 8) == root.bits / 8;
        out.account(80);
        it = reads.emplace(rk, std::make_pair(ok, raw)).first;
      }
      if (!it->second.first)
        errors = node.count - (node.terminal ? 1 : 0);
      else {
        auto value = mask_pointer(it->second.second, root.mask);
        for (auto& e : node.edges) {
          Answer child{0, 0};
          try {
            auto next = add(value, e.offset, root.bits);
            child = walk(e.child, next, root);
          } catch (const Cancelled&) {
            throw;
          } catch (const Budget&) {
            throw;
          } catch (const std::runtime_error&) {
            child.failed = input.nodes[e.child].count;
          }
          if (child.node)
            edges.push_back({e.offset, child.node});
          if (UINT64_MAX - errors < child.failed)
            throw std::runtime_error("过滤计数溢出");
          errors += child.failed;
        }
      }
    }
    Answer answer{out.intern(terminal, std::move(edges)), errors};
    out.account(112);
    memo.emplace(key, answer);
    if (processed % 10000 == 0) {
      check_identity(t);
      ctx.progress("filter", "按共享路径验证当前进程",
                   {{"graph_states", processed}, {"pointer_reads", reads.size()}});
    }
    return answer;
  };
  try {
    for (auto& entry : input.roots) {
      const auto& key = entry.first;
      auto n = entry.second;
      ctx.check();
      if (key.bits != c.bits)
        throw std::runtime_error("文件位数与当前目标不一致");
      uint64_t base = c.source;
      if (!key.absolute) {
        const auto module = key.module;
        const auto region = key.region;
        const auto index = key.index;
        auto it = std::find_if(
            t.regions.begin(), t.regions.end(), [&module, &region, index](const auto& x) {
              return x.root && x.name == module && x.index == index && x.kind == region;
            });
        if (it == t.regions.end()) {
          failed += input.nodes[n].count;
          continue;
        }
        base = it->start;
      } else if (!base)
        throw std::runtime_error("关系链过滤需要当前起始地址");
      std::vector<GraphEdge> edges;
      for (auto& e : input.nodes[n].edges) {
        Answer child{0, 0};
        try {
          child = walk(e.child, add(base, e.offset, key.bits), key);
        } catch (const Cancelled&) {
          throw;
        } catch (const Budget&) {
          throw;
        } catch (const std::runtime_error&) {
          child.failed = input.nodes[e.child].count;
        }
        if (child.node)
          edges.push_back({e.offset, child.node});
        failed += child.failed;
      }
      out.root(key, out.intern(false, std::move(edges)), &ctx);
    }
    check_identity(t);
  } catch (const Cancelled&) {
    result.complete = false;
    result.reason = "cancelled";
  } catch (const Budget& e) {
    result.complete = false;
    result.reason = e.what();
  }
  J candidates = J::array();
  for (auto address : candidate_addresses) candidates.push_back(hex(address));
  result.stats = {{"failed", failed},
                  {"graph_states", processed},
                  {"pointer_reads", reads.size()},
                  {"candidate_addresses", candidates},
                  {"candidate_counts_available", false},
                  {"graph_memory_estimate", out.peak()}};
  bool overflow = false;
  auto count = out.count(&overflow);
  if (c.limit && (overflow || count > c.limit)) {
    result.graph = out.select(c.limit);
    result.complete = false;
    if (result.reason.empty())
      result.reason = "result_limit";
  }
  return result;
}
}  // namespace cs
