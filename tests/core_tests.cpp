#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <random>
#include <set>

#include "core.hpp"
#include "graph.hpp"
using namespace cs;
static int passed = 0, failed = 0;
void expect(bool value, const char* msg) {
  if (!value)
    throw std::runtime_error(msg);
}
void test(const char* name, std::function<void()> fn) {
  try {
    fn();
    ++passed;
    std::cout << "PASS " << name << "\n";
  } catch (const std::exception& e) {
    ++failed;
    std::cerr << "FAIL " << name << ": " << e.what() << "\n";
  }
}
void rejects(std::function<void()> fn) {
  bool caught = false;
  try {
    fn();
  } catch (const std::exception&) {
    caught = true;
  }
  expect(caught, "expected rejection");
}
Target model() {
  Target t;
  Region r;
  r.start = 0x1000;
  r.end = 0x1100;
  r.name = "libfixture.so";
  r.kind = "Cd";
  r.index = 1;
  r.root = true;
  r.id = "libfixture.so[1][Cd]";
  t.regions.push_back(r);
  return t;
}
Config config() {
  Config c;
  c.targets = {0x5030};
  c.depth = 2;
  c.offset = 0x100;
  c.layer_offsets.assign(3, c.offset);
  c.limit = 100000;
  return c;
}
std::vector<Chain> find(std::vector<Pointer> p, Config c, Target t = model()) {
  Index index;
  index.pointers = p;
  Context ctx;
  std::vector<Chain> out;
  search(index, t, c, ctx, [&](const Chain& ch) { out.push_back(ch); });
  Context graph_ctx;
  auto graph = search_graph(index, t, c, graph_ctx);
  std::set<Chain> actual, expected(out.begin(), out.end());
  GraphCursor cursor(*graph.graph);
  Chain item;
  while (cursor.next(item)) actual.insert(item);
  expect(graph.complete && actual == expected && graph.graph->count() == expected.size(),
         "graph/DFS results differ");
  return out;
}
int main() {
  fs::path dir = fs::temp_directory_path() / ("cscan-tests-" + unique_id());
  fs::create_directories(dir);
  test("hex addresses vs decimal offsets", [] {
    expect(number("1234", true) == 0x1234 && number("1234") == 1234, "parser radix");
    expect(number("0x100") == 256, "0x");
    auto a = addresses("1234,0X1234；5678\n5678", 64);
    expect(a.size() == 2, "deduplicate");
  });
  test("strict number parsing and overflow", [] {
    for (auto s : {"-1", "+1", "12junk", " 42", "0x", "18446744073709551616"})
      rejects([&] { number(s); });
    rejects([] { addresses("100000000", 32); });
    rejects([] { addresses("0", 64); });
  });
  test("signed address arithmetic", [] {
    expect(add(0x1000, -0x20) == 0xfe0, "negative");
    rejects([] { add(0, -1); });
    rejects([] { add(UINT64_MAX, 1); });
    rejects([] { add(UINT32_MAX, 1, 32); });
  });
  test("target masks are explicit", [] {
    expect(mask_pointer(0xab00000000001234ULL, "none") == 0xab00000000001234ULL, "none");
    expect(mask_pointer(0xab00000000001234ULL, "topbyte") == 0x1234, "topbyte");
  });
  test("positive reverse chain", [] {
    auto out = find({{0x1010, 0x3000}, {0x3020, 0x5000}}, config());
    expect(out.size() == 1 && out[0].offsets == std::vector<int64_t>({0x10, 0x20, 0x30}),
           "expected chain");
  });
  test("negative final offset", [] {
    auto c = config();
    c.negative = true;
    auto out = find({{0x1010, 0x3000}, {0x3020, 0x5060}}, c);
    expect(out.size() == 1 && out[0].offsets.back() == -0x30, "negative final");
    c.negative = false;
    expect(find({{0x1010, 0x3000}, {0x3020, 0x5060}}, c).empty(), "negative disabled");
  });
  test("convergent branches retained", [] {
    auto out = find({{0x1010, 0x3000}, {0x1020, 0x3000}, {0x3020, 0x5000}}, config());
    expect(out.size() == 2, "two prefixes");
  });
  test("level zero static target", [] {
    auto c = config();
    c.depth = 0;
    c.targets = {0x1028};
    auto out = find({}, c);
    expect(out.size() == 1 && out[0].offsets == std::vector<int64_t>{0x28}, "zero-depth");
  });
  test("mapping end is exclusive", [] {
    auto c = config();
    c.depth = 0;
    c.targets = {0x1100};
    expect(find({}, c).empty(), "one-past map end");
  });
  test("strict result cap", [] {
    auto c = config();
    c.limit = 1;
    Index ix;
    ix.pointers = {{0x1010, 0x3000}, {0x1020, 0x3000}, {0x3020, 0x5000}};
    Context ctx;
    int emitted = 0;
    rejects([&] { search(ix, model(), c, ctx, [&](const Chain&) { ++emitted; }); });
    expect(emitted == 1, "exactly one");
  });
  test("per-level offset numbering", [] {
    auto c = config();
    c.layer_offsets[1] = 0x2f;
    expect(find({{0x1010, 0x3000}, {0x3020, 0x5000}}, c).empty(), "tail layer");
    c.layer_offsets[1] = 0x30;
    c.layer_offsets[2] = 0x1f;
    expect(find({{0x1010, 0x3000}, {0x3020, 0x5000}}, c).empty(), "rootward layer");
  });
  test("root selection does not restrict intermediate region", [] {
    auto c = config();
    c.roots = {"libfixture.so[1][Cd]"};
    expect(find({{0x1010, 0x3000}, {0x3020, 0x5000}}, c).size() == 1, "cross-region");
    c.roots = {"missing[1][Cd]"};
    rejects([&] { find({}, c); });
  });
  test("relation positive endpoint and multiple paths", [] {
    auto c = config();
    c.relation = true;
    c.source = 0x1000;
    auto out = find({{0x1010, 0x3000}, {0x1020, 0x3000}, {0x3020, 0x5000}}, c);
    expect(out.size() == 2 && out[0].absolute && out[0].offsets.back() == 0x30,
           "relation complete");
  });
  test("relation source half-open boundary", [] {
    auto c = config();
    c.relation = true;
    c.depth = 1;
    c.source = 0x1000;
    c.offset = 0x10;
    c.targets = {0x5000};
    expect(find({{0x1010, 0x5000}}, c).empty(), "exclusive upper");
  });
  test("relation overshoot excluded", [] {
    auto c = config();
    c.relation = true;
    c.source = 0x1000;
    c.depth = 1;
    c.targets = {0x3030};
    expect(find({{0x1010, 0x3060}}, c).empty(), "wrong-direction endpoint");
  });
  test("text roundtrip positive negative and absolute", [] {
    for (auto line : {"libfixture.so[1][Cd] + 0x10 -> + 0x20 -> - 0x30", "@start + 0x10 -> + 0x0",
                      "module with spaces.so[12][Cb] + 0x8"}) {
      auto c = Chain::parse(line);
      expect(Chain::parse(c.line()) == c, "roundtrip");
    }
  });
  test("malformed text rejected", [] {
    for (auto s : {"garbage", "mod.so[0][Cd] + 0x1", "mod.so[1][Cd] - 0x1", "@start + 0x0 ->",
                   "@start + 0x0 ->   ", "@start + 0x1 junk", "@start + 0x8000000000000000"})
      rejects([&] { Chain::parse(s); });
  });
  test("binary store roundtrip", [&] {
    StoreWriter w(dir / "a.cptr");
    auto c = Chain::parse("libfixture.so[1][Cd] + 0x10 -> - 0x30");
    w.push(c);
    w.finish({{"complete", true}});
    StoreReader r(dir / "a.cptr");
    Chain d;
    expect(r.next(d) && c == d && !r.next(d), "binary roundtrip");
  });
  test("graph store roundtrip and compact representation", [&] {
    auto make_graph = [](size_t count) {
      auto g = std::make_shared<ChainGraph>();
      Chain root;
      root.module = "libfixture.so";
      root.region = "Cd";
      root.index = 1;
      root.bits = 64;
      RootKey key(root);
      for (size_t i = 0; i < count; ++i) {
        NodeId node = 1;
        for (auto off : {int64_t(0x60), int64_t(0x50), int64_t(0x40), int64_t(0x30), int64_t(0x20)})
          node = g->intern(false, {{off, node}});
        auto first = g->intern(false, {{int64_t(0x100 + i * 8), node}});
        g->root(key, first);
      }
      return g;
    };
    constexpr size_t chain_count = 5000;
    auto graph = make_graph(chain_count);
    expect(graph->count() == chain_count, "graph count");
    auto graph_meta =
        save_graph(dir / "graph.cptr", *graph, {{"kind", "scan"}, {"complete", true}});
    save_graph(dir / "graph2.cptr", *graph, {{"kind", "scan"}, {"complete", true}});
    StoreReader graph_reader(dir / "graph.cptr");
    expect(graph_reader.is_graph() && graph_meta["representation"] == "graph", "graph metadata");
    std::set<std::string> graph_lines;
    Chain c;
    while (graph_reader.next(c)) graph_lines.insert(c.line());
    expect(graph_lines.size() == chain_count, "graph expansion count");

    StoreWriter chains(dir / "chains.cptr");
    for (size_t i = 0; i < chain_count; ++i) {
      Chain item;
      item.module = "libfixture.so";
      item.region = "Cd";
      item.index = 1;
      item.bits = 64;
      item.offsets = {int64_t(0x100 + i * 8), 0x20, 0x30, 0x40, 0x50, 0x60};
      chains.push(item);
    }
    chains.finish({{"kind", "scan"}, {"complete", true}});
    Context format_ctx;
    format_text(dir / "graph.cptr", dir / "graph.txt", J::object(), format_ctx);
    expect(fs::file_size(dir / "graph.cptr") < fs::file_size(dir / "graph.txt"),
           "compressed graph should be smaller than formatted text");
    Context ctx;
    auto common = run({{"kind", "compare"},
                       {"files", J::array({"graph.cptr", "graph2.cptr"})},
                       {"output", "graph-common.cptr"}},
                      dir, ctx);
    expect(common["representation"] == "graph" && common["count"] == chain_count,
           "graph intersection");
  });
  test("no overwrite", [&] { rejects([&] { StoreWriter w(dir / "a.cptr"); }); });
  test("CRC detects corruption", [&] {
    auto b = text(dir / "a.cptr");
    b[b.size() - 5] ^= 1;
    std::ofstream f(dir / "corrupt.cptr", std::ios::binary);
    f.write(b.data(), b.size());
    f.close();
    rejects([&] {
      StoreReader r(dir / "corrupt.cptr");
      Chain c;
      while (r.next(c)) {
      };
    });
  });
  test("truncation detected", [&] {
    auto b = text(dir / "a.cptr");
    b.resize(b.size() - 5);
    std::ofstream f(dir / "truncated.cptr", std::ios::binary);
    f << b;
    f.close();
    rejects([&] {
      StoreReader r(dir / "truncated.cptr");
      Chain c;
      while (r.next(c)) {
      };
    });
  });
  test("invalid format and traversal rejected", [&] {
    rejects([&] { StoreReader r(dir / "missing.out"); });
    for (auto s : {"../x", "/tmp/x", ".hidden", "a\r\nb.cptr"}) rejects([&] { safe_file(dir, s); });
  });
  test("duplicate normalized intersection and re-use", [&] {
    auto ch = Chain::parse("libfixture.so[1][Cd] + 0x10 -> - 0x30");
    StoreWriter w(dir / "b.cptr");
    w.push(ch);
    w.push(ch);
    w.push(Chain::parse("libfixture.so[1][Cd] + 0x99"));
    w.finish({{"complete", true}});
    Context ctx;
    auto result = run(
        {{"kind", "compare"}, {"files", J::array({"a.cptr", "b.cptr"})}, {"output", "common.cptr"}},
        dir, ctx);
    expect(result["count"] == 1, "intersection");
    Context again;
    auto res = run({{"kind", "count"}, {"files", J::array({"common.cptr", "b.cptr"})}}, dir, again);
    expect(res["count"] == 1 && !res.contains("file"), "reusable binary count");
  });
  test("incomplete provenance propagates", [&] {
    StoreWriter w(dir / "partial.cptr");
    w.push(Chain::parse("libfixture.so[1][Cd] + 0x10 -> - 0x30"));
    w.finish({{"complete", false}, {"reason", "result_limit"}});
    Context ctx;
    auto r = run({{"kind", "compare"}, {"files", J::array({"a.cptr", "partial.cptr"})}}, dir, ctx);
    expect(r["complete"] == false && r["reason"] == "incomplete_input", "input provenance");
  });
  test("import exported text header", [&] {
    Context ctx;
    auto r =
        run({{"kind", "import"},
             {"text",
              "# CSCAN-TXT 1 {\"bits\":32,\"mask\":\"none\",\"complete\":false}\nliba.so[1][Cd] + "
              "0x20 -> + 0x10\n"}},
            dir, ctx);
    StoreReader reader(dir / r["file"].get<std::string>());
    Chain c;
    expect(reader.next(c) && c.bits == 32 && r["complete"] == false, "header preserved");
  });
  test("cancel produces no fake completed task", [] {
    Context ctx;
    ctx.cancel = true;
    rejects([&] { ctx.check(); });
  });
  test("config boundaries reject invalid values", [] {
    J j = {{"pid", getpid()}, {"depth", -1}};
    rejects([&] { Config::parse(j); });
    j["depth"] = 2;
    j["layer_offsets"] = "1:0x40,1:0x20";
    rejects([&] { Config::parse(j); });
    j.erase("layer_offsets");
    j["bits"] = 33;
    rejects([&] { Config::parse(j); });
  });
  test("random graphs match independent exhaustive reference", [] {
    std::mt19937 gen(42);
    for (int iter = 0; iter < 150; ++iter) {
      std::vector<Pointer> p;
      for (int i = 0; i < 10; ++i)
        p.push_back({i < 3 ? uint64_t(0x1000 + i * 8) : uint64_t(0x3000 + (i - 3) * 8),
                     uint64_t(0x3000 + (gen() % 8) * 8)});
      auto c = config();
      c.targets = {0x3038};
      c.depth = 3;
      c.offset = 16;
      c.layer_offsets.assign(4, 16);
      c.negative = iter % 2;
      auto got = find(p, c);
      std::set<std::vector<int64_t>> expected;
      std::vector<int64_t> tail;
      std::function<void(uint64_t, int)> walk = [&](uint64_t a, int level) {
        if (a >= 0x1000 && a < 0x1100) {
          std::vector<int64_t> x{int64_t(a - 0x1000)};
          x.insert(x.end(), tail.rbegin(), tail.rend());
          expected.insert(x);
          return;
        }
        if (level == 3)
          return;
        for (auto& ptr : p) {
          int64_t d = int64_t(a) - int64_t(ptr.value);
          if (d <= 16 && d >= (c.negative ? -16 : 0)) {
            tail.push_back(d);
            walk(ptr.address, level + 1);
            tail.pop_back();
          }
        }
      };
      walk(c.targets[0], 0);
      std::set<std::vector<int64_t>> actual;
      for (auto& ch : got) actual.insert(ch.offsets);
      expect(actual == expected && actual.size() == got.size(), "random oracle mismatch");
    }
  });
  test("live self process scan filter trace both standard readers", [&] {
    Fixture fixture(dir);
    auto info = fixture.info();
    for (auto backend : {"syscall", "pread"}) {
      J req = info;
      req["kind"] = "scan";
      req["reader"] = backend;
      Context ctx;
      auto scan = run(req, dir, ctx);
      expect(scan["complete"] == true && scan["count"] == 2, "live scan two chains");
      StoreReader stored(dir / scan["file"].get<std::string>());
      Chain chain;
      expect(stored.next(chain), "stored chain");
      Target t = target(getpid());
      Reader r(t.pid, backend);
      auto tr = resolve(chain, t, r);
      expect(tr["ok"] == true && tr["int32"] == 424242, "live resolution value");
      req["kind"] = "filter";
      req["file"] = scan["file"];
      Context ctx2;
      auto filtered = run(req, dir, ctx2);
      expect(filtered["count"] == 2 && filtered["failed"] == 0, "live filter");
    }
  });
  test("short reads never parse stale buffer", [&] {
    size_t page = sysconf(_SC_PAGESIZE);
    auto mem = static_cast<unsigned char*>(
        mmap(nullptr, page * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    expect(mem != MAP_FAILED, "mmap");
    uint64_t addr = reinterpret_cast<uint64_t>(mem), val = addr + page * 2 + 64;
    std::memcpy(mem, &val, 8);
    std::memcpy(mem + page * 2, &val, 8);
    mprotect(mem + page, page, PROT_NONE);
    Target t = target(getpid());
    Region reg;
    reg.start = addr;
    reg.end = addr + 3 * page;
    reg.kind = "A";
    reg.perms = "rw-p";
    t.regions = {reg};
    Config c = config();
    c.kinds = {"A"};
    c.memory_mb = 8;
    Reader reader(getpid(), "syscall");
    Context ctx;
    auto ix = collect(t, reader, c, ctx);
    munmap(mem, 3 * page);
    expect(ix.pointers.size() == 2, "no stale pointers");
    expect(ix.stats["failed_bytes"] == page && !ix.complete, "failure coverage");
  });
  test("4-byte step crosses collection block edge", [&] {
    size_t size = 512 * 1024;
    auto mem = static_cast<unsigned char*>(
        mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    expect(mem != MAP_FAILED, "mmap");
    uint64_t addr = reinterpret_cast<uint64_t>(mem), v = addr + size - 64;
    std::memcpy(mem + 256 * 1024 - 4, &v, 8);
    Target t = target(getpid());
    Region r;
    r.start = addr;
    r.end = addr + size;
    r.kind = "A";
    r.perms = "rw-p";
    t.regions = {r};
    Config c = config();
    c.step = 4;
    c.memory_mb = 8;
    Reader reader(getpid(), "syscall");
    Context ctx;
    auto ix = collect(t, reader, c, ctx);
    munmap(mem, size);
    expect(ix.pointers.size() == 1 && ix.pointers[0].address == addr + 256 * 1024 - 4,
           "edge pointer retained once");
  });
  test("random relation graphs match exhaustive traversal", [] {
    std::mt19937 gen(923);
    for (int iter = 0; iter < 120; ++iter) {
      auto c = config();
      c.relation = true;
      c.source = 0x1000;
      c.offset = 24;
      c.depth = 3;
      c.targets = {0x3038, 0x3020};
      std::vector<Pointer> pointers;
      for (unsigned i = 0; i < 10; ++i)
        pointers.push_back(
            {i < 4 ? 0x1000 + i * 8ULL : 0x3000 + (i - 4) * 8ULL, 0x3000 + (gen() % 8) * 8ULL});
      find(pointers, c);
    }
  });
  test("compact graph counts and seeks billions without expansion", [&] {
    ChainGraph graph;
    NodeId node = 1;
    for (int i = 0; i < 30; ++i) node = graph.intern(false, {{0, node}, {8, node}});
    Chain proto = Chain::parse("libx.so[1][Cd] + 0x10");
    graph.root(RootKey(proto), graph.intern(false, {{16, node}}));
    expect(graph.count() == (1ULL << 30), "billion count");
    save_graph(dir / "billion.cptr", graph, {{"complete", true}});
    StoreReader reader(dir / "billion.cptr");
    reader.skip((1ULL << 30) - 1);
    Chain c;
    expect(reader.next(c) && c.offsets.size() == 31 && c.offsets.back() == 8 && !reader.next(c),
           "billion seek");
    auto first = graph.select(17);
    expect(first->count() == 17, "graph limit");
    GraphCursor cursor(*first);
    unsigned n = 0;
    while (cursor.next(c)) ++n;
    expect(n == 17, "limit expansion");
    auto excluded = graph.select(0, 0, 4);
    expect(excluded->count() == 0, "depth selector");
    Context ctx;
    auto common = graph.intersect(*first, 8 * 1024 * 1024, ctx);
    expect(common->count() == 17, "shared intersection count");
    expect(fs::file_size(dir / "billion.cptr") < 4096, "graph stores shared paths");
  });
  test("mixed text and graph compare preserves partial provenance", [&] {
    auto c = config();
    Index ix;
    ix.pointers = {{0x1010, 0x3000}, {0x1020, 0x3000}, {0x3020, 0x5000}};
    Context ctx;
    auto built = search_graph(ix, model(), c, ctx);
    save_graph(dir / "mix-graph.cptr", *built.graph, {{"complete", true}});
    std::ofstream(dir / "mix.txt")
        << "# CSCAN-TXT 1 {\"complete\":false}\nlibfixture.so[1][Cd] + 0x10 -> + 0x20 -> + 0x30\n";
    Context compare_ctx;
    auto result = run({{"kind", "compare"}, {"files", J::array({"mix-graph.cptr", "mix.txt"})}},
                      dir, compare_ctx);
    expect(result["count"] == 1 && result["complete"] == false &&
               result["reason"] == "incomplete_input",
           "mixed intersection");
  });
  test("legacy CSCAN1 records remain readable", [&] {
    auto append = [](std::string& b, uint64_t n, int bytes) {
      for (int i = 0; i < bytes; ++i) b.push_back(char(n >> (i * 8)));
    };
    std::string record;
    append(record, 0, 1);
    append(record, 64, 1);
    append(record, 0, 2);
    append(record, 1, 4);
    std::string module = "legacy.so", region = "Cd";
    append(record, module.size(), 2);
    record += module;
    append(record, region.size(), 1);
    record += region;
    append(record, 2, 2);
    append(record, 16, 8);
    append(record, uint64_t(-32), 8);
    uint32_t crc = 0xffffffff;
    for (unsigned char ch : record) {
      crc ^= ch;
      for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    crc = ~crc;
    std::string file = "CSCAN01\n",
                head =
                    J({{"format", "CSCAN/1"}, {"complete", true}, {"count", uint64_t(1)}}).dump();
    append(file, head.size(), 4);
    file += head;
    append(file, record.size(), 4);
    file += record;
    append(file, crc, 4);
    std::ofstream(dir / "legacy.cptr", std::ios::binary).write(file.data(), file.size());
    StoreReader reader(dir / "legacy.cptr");
    Chain actual;
    expect(reader.next(actual) && actual == Chain::parse("legacy.so[1][Cd] + 0x10 -> - 0x20") &&
               !reader.next(actual),
           "legacy record decode");
  });
  test("text importer rejects truncated count and unbounded line", [&] {
    std::ofstream(dir / "bad-count.txt") << "# CSCAN-TXT 1 {\"count\":2}\nlibx.so[1][Cd] + 0x10\n";
    Context ctx;
    rejects([&] {
      run({{"kind", "import"}, {"file", "bad-count.txt"}, {"output", "bad-count.cptr"}}, dir, ctx);
    });
    expect(!fs::exists(dir / "bad-count.cptr"), "no truncated import published");
    std::ofstream(dir / "bad-line.txt") << std::string(17000, 'a');
    TextReader reader(dir / "bad-line.txt");
    Chain chain;
    rejects([&] { reader.next(chain); });
  });
  test("PID identity change fails", [] {
    auto t = target(getpid());
    t.identity = "invalid";
    rejects([&] { check_identity(t); });
  });
  std::cout << "SUMMARY " << passed << " passed, " << failed << " failed\n";
  std::error_code ec;
  fs::remove_all(dir, ec);
  return failed ? 1 : 0;
}
