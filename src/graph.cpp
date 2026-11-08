#include "graph.hpp"

#include <limits>
#include <tuple>
namespace cs {
namespace {
uint64_t sum(uint64_t a, uint64_t b, bool& overflow) {
  if (UINT64_MAX - a < b) {
    overflow = true;
    return UINT64_MAX;
  }
  return a + b;
}
void tick(Context* ctx) {
  if (ctx) {
    ctx->check();
    ++ctx->visited;
  }
}
}  // namespace
Chain RootKey::chain() const {
  Chain c;
  c.absolute = absolute;
  c.bits = bits;
  c.index = index;
  c.module = module;
  c.region = region;
  c.mask = mask;
  return c;
}
bool RootKey::operator<(const RootKey& o) const {
  return std::tie(absolute, module, index, region, bits, mask) <
         std::tie(o.absolute, o.module, o.index, o.region, o.bits, o.mask);
}
bool RootKey::operator==(const RootKey& o) const {
  return !(*this < o) && !(o < *this);
}
ChainGraph::ChainGraph(size_t limit) : limit_(limit) {
  intern(false, {});
  intern(true, {});
}
void ChainGraph::account(size_t bytes) {
  if (bytes > limit_ || bytes_ + aux_ > limit_ - bytes)
    throw Budget("graph_memory_limit");
  aux_ += bytes;
  peak_ = std::max(peak_, bytes_ + aux_);
}
void ChainGraph::unaccount(size_t bytes) {
  aux_ -= std::min(aux_, bytes);
}
void ChainGraph::begin_root_edit() {
  if (roots_dirty_)
    return;
  size_t cost = 0;
  for (const auto& entry : roots) cost += nodes[entry.second].edges.size() * 80;
  account(cost);
  std::map<RootKey, std::map<int64_t, NodeId>> parts;
  try {
    for (const auto& entry : roots)
      for (const auto& edge : nodes[entry.second].edges)
        parts[entry.first].emplace(edge.offset, edge.child);
  } catch (...) {
    unaccount(cost);
    throw;
  }
  root_parts_ = std::move(parts);
  root_aux_ = cost;
  roots.clear();
  roots_dirty_ = true;
}
void ChainGraph::finalize_roots() {
  if (!roots_dirty_)
    return;
  std::map<RootKey, NodeId> completed;
  for (auto& entry : root_parts_) {
    std::vector<GraphEdge> edges;
    edges.reserve(entry.second.size());
    for (auto& edge : entry.second)
      if (edge.second)
        edges.push_back({edge.first, edge.second});
    auto node = intern(false, std::move(edges));
    if (node)
      completed.emplace(entry.first, node);
  }
  roots = std::move(completed);
  root_parts_.clear();
  unaccount(root_aux_);
  root_aux_ = 0;
  roots_dirty_ = false;
}
void ChainGraph::finalize() const {
  const_cast<ChainGraph*>(this)->finalize_roots();
}
NodeId ChainGraph::intern(bool terminal, std::vector<GraphEdge> edges) {
  edges.erase(std::remove_if(edges.begin(), edges.end(), [](auto& e) { return e.child == 0; }),
              edges.end());
  std::sort(edges.begin(), edges.end(), [](auto& a, auto& b) { return a.offset < b.offset; });
  GraphNode node;
  node.terminal = terminal;
  node.count = terminal ? 1 : 0;
  node.min_length = terminal ? 0 : UINT16_MAX;
  uint64_t hash = terminal ? 1469598103934665603ULL : 1099511628211ULL;
  for (size_t i = 0; i < edges.size(); ++i) {
    auto& e = edges[i];
    if (e.child >= nodes.size() || (i && edges[i - 1].offset == e.offset))
      throw std::runtime_error("链图边或排序不合法");
    auto& child = nodes[e.child];
    node.overflow |= child.overflow;
    node.count = sum(node.count, child.count, node.overflow);
    node.min_length = std::min<uint16_t>(node.min_length, child.min_length + 1);
    node.max_length = std::max<uint16_t>(node.max_length, child.max_length + 1);
    hash ^= uint64_t(e.offset);
    hash *= 1099511628211ULL;
    hash ^= e.child;
    hash *= 1099511628211ULL;
  }
  if (node.max_length > 257)
    throw std::runtime_error("链图深度超出 256 层");
  if (!node.count)
    node.min_length = 0;
  auto found = hashes_.find(hash);
  if (found != hashes_.end())
    for (auto id : found->second)
      if (nodes[id].terminal == terminal && nodes[id].edges == edges)
        return id;
  if (nodes.size() >= UINT32_MAX)
    throw Budget("graph_node_limit");
  size_t cost = sizeof(GraphNode) + 128 + edges.capacity() * sizeof(GraphEdge);
  account(cost);
  aux_ -= cost;
  bytes_ += cost;
  node.edges = std::move(edges);
  NodeId id = nodes.size();
  nodes.push_back(std::move(node));
  hashes_[hash].push_back(id);
  return id;
}
NodeId ChainGraph::unite(NodeId a, NodeId b, Context* ctx) {
  if (a == b || !b)
    return a;
  if (!a)
    return b;
  if (a > b)
    std::swap(a, b);
  uint64_t key = (uint64_t(a) << 32) | b;
  auto cached = union_cache_.find(key);
  if (cached != union_cache_.end())
    return cached->second;
  tick(ctx);
  const auto& x = nodes[a];
  const auto& y = nodes[b];
  std::vector<GraphEdge> edges;
  size_t i = 0, j = 0;
  while (i < x.edges.size() || j < y.edges.size()) {
    if (j == y.edges.size() || (i < x.edges.size() && x.edges[i].offset < y.edges[j].offset))
      edges.push_back(x.edges[i++]);
    else if (i == x.edges.size() || y.edges[j].offset < x.edges[i].offset)
      edges.push_back(y.edges[j++]);
    else {
      auto off = x.edges[i].offset;
      auto child = unite(x.edges[i++].child, y.edges[j++].child, ctx);
      edges.push_back({off, child});
    }
  }
  auto result = intern(x.terminal || y.terminal, std::move(edges));
  account(48);
  union_cache_[key] = result;
  return result;
}
void ChainGraph::root(const RootKey& key, NodeId node, Context* ctx) {
  if (!node)
    return;
  if (node >= nodes.size() || nodes[node].terminal)
    throw std::runtime_error("链图根必须包含非空偏移序列");
  begin_root_edit();
  auto found = root_parts_.find(key);
  if (found == root_parts_.end()) {
    size_t cost = 256 + key.module.size() + key.region.size() + key.mask.size();
    account(cost);
    aux_ -= cost;
    bytes_ += cost;
    found = root_parts_.emplace(key, std::map<int64_t, NodeId>{}).first;
  }
  auto& parts = found->second;
  for (auto& e : nodes[node].edges) {
    auto it = parts.find(e.offset);
    if (it == parts.end()) {
      account(80);
      root_aux_ += 80;
      parts.emplace(e.offset, e.child);
    } else
      it->second = unite(it->second, e.child, ctx);
  }
}
bool ChainGraph::has_root(const RootKey& key) const {
  return roots.find(key) != roots.end() || root_parts_.find(key) != root_parts_.end();
}
uint64_t ChainGraph::count(bool* overflow) const {
  bool over = false;
  uint64_t total = 0;
  if (roots_dirty_) {
    for (const auto& entry : root_parts_)
      for (const auto& edge : entry.second) {
        const auto& node = nodes[edge.second];
        over |= node.overflow;
        total = sum(total, node.count, over);
      }
  } else
    for (const auto& entry : roots) {
      const auto& node = nodes[entry.second];
      over |= node.overflow;
      total = sum(total, node.count, over);
    }
  if (overflow)
    *overflow = over;
  return total;
}
std::shared_ptr<ChainGraph> ChainGraph::select(uint64_t limit, int min_depth, int max_depth,
                                               Context* ctx) const {
  finalize();
  auto out = std::make_shared<ChainGraph>(limit_);
  std::unordered_map<uint64_t, NodeId> length_cache;
  std::function<NodeId(NodeId, int)> length_filter = [&](NodeId n, int used) -> NodeId {
    if (!n)
      return 0;
    tick(ctx);
    const auto& node = nodes[n];
    if (used + node.min_length > max_depth + 1 || used + node.max_length < min_depth + 1)
      return 0;
    uint64_t key = (uint64_t(n) << 9) | uint64_t(used);
    auto it = length_cache.find(key);
    if (it != length_cache.end())
      return it->second;
    std::vector<GraphEdge> edges;
    for (auto& e : node.edges) {
      auto child = length_filter(e.child, used + 1);
      if (child)
        edges.push_back({e.offset, child});
    }
    auto id = out->intern(node.terminal && used >= min_depth + 1 && used <= max_depth + 1,
                          std::move(edges));
    out->account(48);
    length_cache[key] = id;
    return id;
  };
  for (auto& [key, n] : roots) {
    auto filtered = length_filter(n, 0);
    if (filtered)
      out->root(key, filtered, ctx);
  }
  if (!limit)
    return out;
  bool overflow = false;
  auto total = out->count(&overflow);
  if (!overflow && total <= limit)
    return out;
  auto limited = std::make_shared<ChainGraph>(limit_);
  std::unordered_map<NodeId, NodeId> copied;
  std::function<NodeId(NodeId, uint64_t)> take = [&](NodeId n, uint64_t k) -> NodeId {
    if (!n || !k)
      return 0;
    tick(ctx);
    const auto& node = out->nodes[n];
    bool full = !node.overflow && k >= node.count;
    if (full) {
      auto it = copied.find(n);
      if (it != copied.end())
        return it->second;
    }
    bool terminal = node.terminal;
    if (terminal)
      --k;
    std::vector<GraphEdge> edges;
    for (auto& e : node.edges) {
      if (!k)
        break;
      auto& child = out->nodes[e.child];
      auto amount = std::min(k, child.count);
      auto dst = take(e.child, amount);
      if (dst)
        edges.push_back({e.offset, dst});
      k -= amount;
    }
    auto id = limited->intern(terminal, std::move(edges));
    if (full) {
      limited->account(40);
      copied[n] = id;
    }
    return id;
  };
  out->finalize();
  uint64_t remain = limit;
  for (auto& [key, n] : out->roots) {
    if (!remain)
      break;
    auto amount = std::min(remain, out->nodes[n].count);
    limited->root(key, take(n, amount), ctx);
    remain -= amount;
  }
  return limited;
}
std::shared_ptr<ChainGraph> ChainGraph::intersect(const ChainGraph& other, size_t budget,
                                                  Context& ctx) const {
  finalize();
  other.finalize();
  auto out = std::make_shared<ChainGraph>(budget);
  std::unordered_map<uint64_t, NodeId> cache;
  std::function<NodeId(NodeId, NodeId)> meet = [&](NodeId a, NodeId b) -> NodeId {
    if (!a || !b)
      return 0;
    uint64_t key = (uint64_t(a) << 32) | b;
    auto it = cache.find(key);
    if (it != cache.end())
      return it->second;
    tick(&ctx);
    auto& x = nodes[a];
    auto& y = other.nodes[b];
    std::vector<GraphEdge> edges;
    size_t i = 0, j = 0;
    while (i < x.edges.size() && j < y.edges.size()) {
      if (x.edges[i].offset < y.edges[j].offset)
        ++i;
      else if (x.edges[i].offset > y.edges[j].offset)
        ++j;
      else {
        auto off = x.edges[i].offset;
        auto child = meet(x.edges[i++].child, y.edges[j++].child);
        if (child)
          edges.push_back({off, child});
      }
    }
    auto id = out->intern(x.terminal && y.terminal, std::move(edges));
    out->account(48);
    cache[key] = id;
    return id;
  };
  for (auto& [key, n] : roots) {
    ctx.check();
    auto it = other.roots.find(key);
    if (it != other.roots.end())
      out->root(key, meet(n, it->second), &ctx);
  }
  return out;
}
GraphCursor::GraphCursor(const ChainGraph& g) : graph_(g) {
  g.finalize();
  root_ = graph_.roots.begin();
}
bool GraphCursor::enter() {
  while (stack_.empty() && root_ != graph_.roots.end()) {
    if (graph_.nodes[root_->second].count) {
      stack_.push_back({root_->second, 0, true});
      return true;
    }
    ++root_;
  }
  return !stack_.empty();
}
bool GraphCursor::next(Chain& c) {
  while (enter()) {
    auto& frame = stack_.back();
    const auto& node = graph_.nodes[frame.node];
    if (frame.terminal_pending) {
      frame.terminal_pending = false;
      if (node.terminal) {
        c = root_->first.chain();
        c.offsets = path_;
        return true;
      }
    }
    if (frame.edge < node.edges.size()) {
      auto edge = node.edges[frame.edge++];
      path_.push_back(edge.offset);
      stack_.push_back({edge.child, 0, true});
    } else {
      stack_.pop_back();
      if (!path_.empty())
        path_.pop_back();
      if (stack_.empty())
        ++root_;
    }
  }
  return false;
}
void GraphCursor::skip(uint64_t n) {
  while (n && enter()) {
    auto& f = stack_.back();
    const auto& node = graph_.nodes[f.node];
    if (f.terminal_pending) {
      f.terminal_pending = false;
      if (node.terminal) {
        --n;
        continue;
      }
    }
    if (f.edge < node.edges.size()) {
      auto e = node.edges[f.edge++];
      auto& child = graph_.nodes[e.child];
      if (!child.overflow && child.count <= n)
        n -= child.count;
      else {
        path_.push_back(e.offset);
        stack_.push_back({e.child, 0, true});
      }
    } else {
      stack_.pop_back();
      if (!path_.empty())
        path_.pop_back();
      if (stack_.empty())
        ++root_;
    }
  }
}
}  // namespace cs
