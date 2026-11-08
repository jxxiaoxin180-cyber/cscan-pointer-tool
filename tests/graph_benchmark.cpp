#include <iostream>
#include <set>

#include "core.hpp"
#include "graph.hpp"
using namespace cs;
int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: graph_benchmark OUTPUT_DIR\n";
    return 1;
  }
  try {
    const fs::path dir(argv[1]);
    fs::create_directories(dir);
    J report = {{"scope",
                 "Synthetic pointer-index benchmark; excludes process collection and real applications."},
                {"version", version}};
    Target target;
    Region root;
    root.start = 0x1000;
    root.end = 0x1100;
    root.root = true;
    root.name = "libbench.so";
    root.kind = "Cd";
    root.index = 1;
    root.id = "libbench.so[1][Cd]";
    target.regions = {root};
    for (int depth : {4, 6}) {
      Config c;
      c.depth = depth;
      c.offset = 128;
      c.layer_offsets.assign(depth + 1, 128);
      c.targets = {uint64_t(depth) * 0x10000};
      c.limit = 0;
      Index index;
      for (int layer = 0; layer < depth; ++layer)
        for (int i = 0; i < 16; ++i)
          index.pointers.push_back({(layer ? uint64_t(layer) * 0x10000 : 0x1000) + uint64_t(i) * 8,
                                    uint64_t(layer + 1) * 0x10000});
      Context graph_ctx;
      graph_ctx.max_nodes = 1000000000;
      auto begin = Clock::now();
      auto graph = search_graph(index, target, c, graph_ctx);
      auto graph_us =
          std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - begin).count();
      uint64_t expected = 1ULL << (4 * depth);
      if (!graph.complete || graph.graph->count() != expected)
        throw std::runtime_error("graph count mismatch");
      auto file = dir / ("depth-" + std::to_string(depth) + ".cptr");
      auto metadata = save_graph(file, *graph.graph, {{"complete", true}, {"kind", "benchmark"}});
      StoreReader reader(file);
      auto loaded = reader.graph();
      Context compare_ctx;
      begin = Clock::now();
      auto common = loaded->intersect(*loaded, 128 * 1024 * 1024, compare_ctx);
      auto compare_us =
          std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - begin).count();
      if (common->count() != expected)
        throw std::runtime_error("intersection mismatch");
      reader.skip(expected - 1);
      Chain last;
      if (!reader.next(last) || reader.next(last))
        throw std::runtime_error("last-page mismatch");
      J row = {{"depth", depth},
               {"index_pointers", index.pointers.size()},
               {"chains", expected},
               {"graph_nodes", metadata["graph_nodes"]},
               {"graph_bytes", fs::file_size(file)},
               {"graph_search_us", graph_us},
               {"graph_work", graph_ctx.visited},
               {"graph_compare_us", compare_us},
               {"graph_compare_work", compare_ctx.visited}};
      if (depth == 4) {
        Context exhaustive;
        exhaustive.max_nodes = 1000000000;
        uint64_t count = 0, text_bytes = 0;
        std::set<Chain> chains;
        begin = Clock::now();
        search(index, target, c, exhaustive, [&](const Chain& chain) { ++count; });
        row["exhaustive_search_us"] =
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - begin).count();
        if (count != expected)
          throw std::runtime_error("exhaustive count mismatch");
        Context verify;
        verify.max_nodes = 1000000000;
        search(index, target, c, verify, [&](const Chain& chain) {
          chains.insert(chain);
          text_bytes += chain.line().size() + 1;
        });
        GraphCursor cursor(*graph.graph);
        Chain chain;
        while (cursor.next(chain)) {
          if (chains.erase(chain) != 1)
            throw std::runtime_error("chain mismatch");
        }
        if (!chains.empty())
          throw std::runtime_error("missing chain");
        row["text_chain_bytes"] = text_bytes;
        row["all_chain_contents_match"] = true;
      }
      report["cases"].push_back(row);
    }
    std::cout << report.dump(2) << "\n";
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
