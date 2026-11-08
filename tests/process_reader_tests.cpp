#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <sstream>

#include "core.hpp"
using namespace cs;
int main() {
  int checks = 0;
  auto check = [&](bool ok, const char* name) {
    ++checks;
    if (!ok)
      throw std::runtime_error(name);
  };
  auto dir = fs::temp_directory_path() / ("cscan-proc-" + unique_id());
  fs::create_directories(dir / "self");
  try {
    std::ofstream(dir / "self/status")
        << "Name: sandbox\nUid:\t10570\t10570\t10570\t10570\nCapEff:\t0000000000000000\n";
    auto run = runtime_info(dir);
    check(!run["root"].get<bool>() && run["kernel_euid"] == 10570, "kernel uid is authoritative");
    auto fake = [&](int pid, std::string comm, bool full) {
      auto p = dir / std::to_string(pid);
      fs::create_directories(p);
      std::ofstream(p / "comm") << comm << "\n";
      std::ofstream stat(p / "stat");
      stat << pid << " (name (nested)) ";
      for (int i = 3; i <= 52; ++i) stat << (i == 3 ? "S" : i == 22 ? "98765" : "0") << ' ';
      stat << '\n';
      std::ofstream(p / "maps") << "1000-2000 rw-p 00000000 00:00 0\n";
      if (full) {
        std::ofstream(p / "cmdline", std::ios::binary) << comm << '\0';
        std::ofstream(p / "status") << "Uid:\t10001 10001 10001 10001\n";
      }
    };
    fake(6215, "target.app", false);
    auto p = process_probe(6215, dir);
    check(p["name"] == "target.app" && p["name_source"] == "comm", "fallback comm");
    check(p["identity"] == "98765" && p["connectable"] == true, "optional metadata not mandatory");
    check(!p["metadata_complete"].get<bool>() && p["uid"] == -1, "missing status remains unknown");
    fs::remove(dir / "6215/comm");
    p = process_probe(6215, dir);
    check(p["name"] == "name (nested)" && p["name_source"] == "stat",
          "stat name fallback and nested parens");
    fs::remove(dir / "6215/stat");
    p = process_probe(6215, dir);
    check(p["state"] == "restricted" && p["name_source"] == "pid",
          "restricted placeholder retained");
    auto list = process_catalog(dir);
    check(list["count"] == 1 && list["restricted_count"] == 1, "restricted process not discarded");
    fake(6216, "healthy.app", true);
    p = process_probe(6216, dir);
    check(p["uid"] == 10001 && p["connectable"] == true, "healthy process");
    fs::remove(dir / "6216/maps");
    p = process_probe(6216, dir);
    check(p["state"] == "restricted" && p["maps_readable"] == false, "maps failure distinct");
    p = process_probe(9999, dir);
    check(p["state"] == "not_visible" && !p["connectable"].get<bool>(),
          "hidden-or-exited not false certainty");
    std::ofstream(dir / "self/status", std::ios::trunc) << "Uid:\t0 0 0 0\n";
    check(runtime_info(dir)["root"] == true, "native kernel root detected");
    Fixture fixture(dir);
    auto info = fixture.info();
    uint64_t addr = number(info["addresses"], true), value = 0;
    Reader reader(getpid(), "normal");
    check(reader.read_exact(addr, &value, 8) == 8 && value == 424242, "normal reader actual value");
    auto diag = reader.diagnostics();
    check(diag["read_verified"] == true && diag["syscall_reads"].get<int>() > 0, "method evidence");
    check(reader.read(UINT64_MAX - 2, &value, 8) == -1 && errno == EINVAL,
          "request overflow rejected");
    check(reader.read(addr, nullptr, 8) == -1, "null read rejected");
    size_t page = sysconf(_SC_PAGESIZE);
    auto* mem = static_cast<unsigned char*>(
        mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mem == MAP_FAILED)
      throw std::runtime_error("mmap");
    memset(mem, 0x42, page);
    mprotect(mem + page, page, PROT_NONE);
    Reader sys(getpid(), "syscall");
    std::vector<unsigned char> buf(page * 2, 0x11);
    auto n = sys.read_exact(reinterpret_cast<uint64_t>(mem), buf.data(), buf.size());
    check(n == ssize_t(page) && buf[page] == 0x11, "exact read returns confirmed prefix");
    munmap(mem, page * 2);
    fs::remove_all(dir);
    std::cout << "PASS " << checks << " process/runtime/reader checks\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FAIL " << e.what() << "\n";
    std::error_code ec;
    fs::remove_all(dir, ec);
    return 1;
  }
}
