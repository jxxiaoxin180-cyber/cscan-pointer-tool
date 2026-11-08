#include <unistd.h>

#include <csignal>
#include <iostream>
#include <set>
#include <sstream>
#include <thread>

#include "core.hpp"
namespace {
std::atomic_bool* cancel_flag = nullptr;
void interrupt(int) {
  if (cancel_flag)
    cancel_flag->store(true);
  else
    _exit(130);
}
}  // namespace
namespace cs {
int menu(const fs::path& dir) {
  for (;;) {
    std::cout << "\n╭─ C扫指针工具第一版 ─────────────────╮\n  1  打开网页工作台（推荐）\n  2  "
                 "查看进程\n  3  扫描指针链\n  4  比较结果\n  5  调试指针链\n  6  查看结果文件\n  "
                 "0  退出\n╰───────────────────────────────────╯\n选择 [1]："
              << std::flush;
    std::string choice;
    if (!std::getline(std::cin, choice))
      return 0;
    if (choice == "0")
      return 0;
    try {
      if (choice.empty() || choice == "1")
        return serve(dir, 18760);
      if (choice == "2") {
        for (auto& p : processes())
          std::cout << p["pid"] << "  " << p["name"].get<std::string>() << "  UID " << p["uid"]
                    << "\n";
        continue;
      }
      if (choice == "6") {
        std::cout << list_results(dir).dump(2) << "\n";
        continue;
      }
      auto ask = [](std::string title, std::string def = "") {
        std::cout << title << (def.empty() ? "" : (" [" + def + "]")) + "：" << std::flush;
        std::string s;
        if (!std::getline(std::cin, s))
          throw std::runtime_error("输入已结束");
        return s.empty() ? def : s;
      };
      J req;
      if (choice == "3" || choice == "5") {
        req["kind"] = choice == "3" ? "scan" : "trace";
        req["pid"] = number(ask("目标 PID"));
        req["reader"] = ask("读取器 syscall / pread / paradise35 / paradise-hook", "syscall");
        req["bits"] = number(ask("目标指针位数", "64"));
        if (choice == "3") {
          req["addresses"] = ask("目标地址（十六进制，多个用空格分隔）");
          req["depth"] = number(ask("最大深度", "6"));
          req["offset"] = ask("最大偏移（默认十进制，支持 0x）", "2000");
        } else
          req["chains"] = ask("指针链");
      } else if (choice == "4") {
        req["kind"] = "compare";
        std::istringstream s(ask("输入 2–8 个结果文件名，空格分隔"));
        std::string f;
        req["files"] = J::array();
        while (s >> f) req["files"].push_back(f);
      } else
        continue;
      Context ctx;
      cancel_flag = &ctx.cancel;
      ctx.event = [](J e) { std::cout << e["message"].get<std::string>() << "\n"; };
      auto result = run(req, dir, ctx);
      cancel_flag = nullptr;
      std::cout << result.dump(2) << "\n";
    } catch (const std::exception& e) {
      cancel_flag = nullptr;
      std::cerr << "错误：" << e.what() << "\n";
    }
  }
}
}  // namespace cs
int main(int argc, char** argv) {
  using namespace cs;
  try {
    std::string command = argc > 1 ? argv[1] : "serve";
    fs::path data = "cscan-data";
    int port = 18760;
    J req = J::object();
    std::string configfile;
    fs::path input_file;
    if (command == "--help" || command == "help" || command == "-h") {
      std::cout
          << "C扫指针工具第一版 v" << version
          << "\n\n直接运行：启动本地网页 http://127.0.0.1:18760\n用法：cscan "
             "[serve|menu|processes|modules|scan|relation|compare|count|filter|format|trace|reader-"
             "test|backend-status|read-memory|diagnose-pid|runtime|files|preview|export|"
             "import|fixture] [选项]\n\n  --data DIR           "
             "数据目录，默认 ./cscan-data\n  --port 18760         网页端口，仅监听本机\n  "
             "--config FILE        从 JSON 加载任务配置\n  --pid PID --bits 64 --reader "
             "normal|syscall|pread|paradise|paradise35|paradise-hook\n  --addresses HEX      "
             "一个或多个目标地址（空格分隔时需引号）\n  --depth 6 --offset 2000 --limit "
             "100000 --memory-mb 128\n  --negative --layer-offsets '1:0x40,2:0x100'\n  "
             "--source HEX         关系搜索 / 关系链调试的起点\n  --modules '模块[1][Cd]'  "
             "多个用逗号分隔，省略表示所有根模块\n  --ranges A,Ca,Ch,Cb,Cd --step 8 --mask "
             "none|topbyte|low48\n  --nonread --timeout 120 --max-nodes 5000000 --graph-memory-mb "
             "128 --threads 0\n  --files "
             "a.cptr,b.cptr 比较输入\n  --file a.cptr        过滤、预览或导出输入\n  "
             "--chains '链文本'     调试输入\n  --text-file FILE     流式导入文本（支持大文件）\n  "
             "--output "
             "NAME.cptr / NAME.txt   可选输出名称，不覆盖已有文件；format "
             "将二进制结果流式展开为文本\n  --output-format binary|text  过滤后保存的文件格式\n  "
             "--driver-fd N        Paradise 3.5 "
             "已继承的驱动 FD（可选）\n\n更多说明见项目 README.md。结果格式为 CSCAN/2（兼容读取 "
             "CSCAN/1），不是 "
             "FastScan OUT/NORM。\nformat 选项：--min-depth 0 --max-depth 256 --limit "
             "0（不限条数）。\n新增：diagnose-pid --pid PID；runtime；backend-status "
             "--reader paradise；read-memory --pid PID --addresses HEX --size 64。\n";
      return 0;
    }
    if (command == "--version") {
      std::cout << version << "\n";
      return 0;
    }
    const std::set<std::string> numkeys = {"pid",       "bits",      "depth",    "step",
                                           "limit",     "memory_mb", "timeout",  "max_nodes",
                                           "driver_fd", "page",      "size",     "graph_memory_mb",
                                           "threads",   "min_depth", "max_depth"};
    const std::set<std::string> strkeys = {"reader",        "addresses", "offset",       "source",
                                           "layer_offsets", "mask",      "file",         "chains",
                                           "output",        "text",      "output_format"};
    const std::set<std::string> listkeys = {"modules", "ranges", "files"};
    for (int i = 2; i < argc; ++i) {
      std::string key = argv[i];
      if (key.rfind("--", 0) != 0)
        throw std::runtime_error("无法识别参数：" + key);
      key = key.substr(2);
      std::replace(key.begin(), key.end(), '-', '_');
      if (key == "negative" || key == "nonread") {
        req[key] = true;
        continue;
      }
      if (i + 1 >= argc)
        throw std::runtime_error("选项缺少值：" + key);
      std::string val = argv[++i];
      if (key == "data")
        data = val;
      else if (key == "port")
        port = number(val);
      else if (key == "config")
        configfile = val;
      else if (key == "text_file")
        input_file = val;
      else if (listkeys.count(key)) {
        req[key] = J::array();
        std::istringstream s(val);
        std::string item;
        while (std::getline(s, item, ',')) req[key].push_back(item);
      } else if (numkeys.count(key))
        req[key] = number(val);
      else if (strkeys.count(key))
        req[key] = val;
      else
        throw std::runtime_error("未知选项：" + key);
    }
    if (!configfile.empty()) {
      J base = J::parse(text(configfile));
      base.update(req);
      req = base;
    }
    req["kind"] = command;
    if (!input_file.empty() && command != "import")
      throw std::runtime_error("--text-file 仅用于 import");
    data = fs::absolute(data);
    if (command != "runtime" && command != "diagnose-pid" && command != "processes" &&
        command != "modules")
      fs::create_directories(data);
    if (port < 1024 || port > 65535)
      throw std::runtime_error("端口范围为 1024–65535");
    if (command == "serve")
      return serve(data, port);
    if (command == "menu")
      return menu(data);
    if (command == "processes") {
      std::cout << processes().dump(2) << "\n";
      return 0;
    }
    if (command == "diagnose-pid") {
      auto info = process_probe(req.at("pid").get<int>());
      info["runtime"] = runtime_info();
      std::cout << info.dump(2) << "\n";
      return info["connectable"] == true ? 0 : 2;
    }
    if (command == "runtime") {
      std::cout << runtime_info().dump(2) << "\n";
      return 0;
    }
    if (command == "modules") {
      std::cout << modules(target(req.at("pid"))).dump(2) << "\n";
      return 0;
    }
    if (command == "files") {
      std::cout << list_results(data).dump(2) << "\n";
      return 0;
    }
    if (command == "preview") {
      std::cout << preview(safe_file(data, req.at("file")), req.value("page", size_t(0)), 50,
                           req.value("graph_memory_mb", size_t(128)) * 1024ULL * 1024ULL)
                       .dump(2)
                << "\n";
      return 0;
    }
    if (command == "fixture") {
      Fixture fixture(data);
      std::cout << fixture.info().dump() << std::endl;
      std::string line;
      std::getline(std::cin, line);
      return 0;
    }
    if (command == "export") {
      StoreReader r(safe_file(data, req.at("file")),
                    req.value("graph_memory_mb", size_t(128)) * 1024ULL * 1024ULL);
      Chain c;
      bool first = true;
      std::string signature;
      while (r.next(c)) {
        if (first || signature != std::to_string(c.bits) + c.mask) {
          signature = std::to_string(c.bits) + c.mask;
          std::cout << "# CSCAN-TXT 1 "
                    << J({{"bits", c.bits},
                          {"mask", c.mask},
                          {"complete", r.metadata.value("complete", false)}})
                           .dump()
                    << "\n";
          first = false;
        }
        std::cout << c.line() << "\n";
      }
      if (!std::cout)
        throw std::runtime_error("文本输出失败");
      return 0;
    }
    Context ctx;
    cancel_flag = &ctx.cancel;
    std::signal(SIGINT, interrupt);
    std::signal(SIGTERM, interrupt);
    ctx.event = [](J e) { std::cerr << e.dump() << "\n"; };
    auto result = run(req, data, ctx, input_file);
    cancel_flag = nullptr;
    std::cout << result.dump(2) << "\n";
    return result.value("complete", true) ? 0 : 2;
  } catch (const std::exception& e) {
    cancel_flag = nullptr;
    std::cerr << J({{"error", e.what()}}).dump() << "\n";
    return 1;
  }
}
