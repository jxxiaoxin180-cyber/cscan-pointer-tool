#pragma once
#include <deque>
#include <map>
#include <unordered_map>

#include "core.hpp"
namespace cs {
using NodeId = uint32_t;
struct RootKey {
  bool absolute = false;
  int bits = 64, index = 1;
  std::string module, region, mask = "none";
  explicit RootKey(const Chain& c)
      : absolute(c.absolute),
        bits(c.bits),
        index(c.index),
        module(c.module),
        region(c.region),
        mask(c.mask) {}
  RootKey() = default;
  Chain chain() const;
  bool operator<(const RootKey& o) const;
  bool operator==(const RootKey& o) const;
};
struct GraphEdge {
  int64_t offset;
  NodeId child;
  bool operator==(const GraphEdge& o) const {
    return offset == o.offset && child == o.child;
  }
};
struct GraphNode {
  bool terminal = false, overflow = false;
  uint64_t count = 0;
  uint16_t min_length = 0, max_length = 0;
  std::vector<GraphEdge> edges;
};
class ChainGraph {
  std::unordered_map<uint64_t, std::vector<NodeId>> hashes_;
  std::unordered_map<uint64_t, NodeId> union_cache_;
  std::map<RootKey, std::map<int64_t, NodeId>> root_parts_;
  mutable bool roots_dirty_ = false;
  size_t root_aux_ = 0;
  void begin_root_edit();
  void finalize_roots();
  size_t bytes_ = 0, aux_ = 0, peak_ = 0, limit_;

 public:
  std::deque<GraphNode> nodes;
  std::map<RootKey, NodeId> roots;
  explicit ChainGraph(size_t memory_limit = 128ULL * 1024 * 1024);
  void account(size_t bytes);
  void unaccount(size_t bytes);
  size_t bytes() const {
    return bytes_ + aux_;
  }
  size_t peak() const {
    return peak_;
  }
  size_t budget() const {
    return limit_;
  }
  NodeId intern(bool terminal, std::vector<GraphEdge> edges);
  NodeId unite(NodeId a, NodeId b, Context* ctx = nullptr);
  void root(const RootKey& key, NodeId node, Context* ctx = nullptr);
  bool has_root(const RootKey& key) const;
  void finalize() const;
  uint64_t count(bool* overflow = nullptr) const;
  std::shared_ptr<ChainGraph> select(uint64_t limit, int min_depth = 0, int max_depth = 256,
                                     Context* ctx = nullptr) const;
  std::shared_ptr<ChainGraph> intersect(const ChainGraph& other, size_t budget, Context& ctx) const;
};
class GraphCursor {
  const ChainGraph& graph_;
  std::map<RootKey, NodeId>::const_iterator root_;
  struct Frame {
    NodeId node;
    size_t edge = 0;
    bool terminal_pending = true;
  };
  std::vector<Frame> stack_;
  std::vector<int64_t> path_;
  bool enter();

 public:
  explicit GraphCursor(const ChainGraph& g);
  bool next(Chain& c);
  void skip(uint64_t n);
};
struct GraphBuild {
  std::shared_ptr<ChainGraph> graph;
  bool complete = true;
  std::string reason;
  J stats = J::object();
};
GraphBuild search_graph(Index& index, const Target& t, const Config& c, Context& ctx);
GraphBuild filter_graph(const ChainGraph& input, const Target& t, Reader& r, const Config& c,
                        Context& ctx);
}  // namespace cs
