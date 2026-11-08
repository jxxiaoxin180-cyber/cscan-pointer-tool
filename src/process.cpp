#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstring>
#include <sstream>

#include "core.hpp"
namespace cs {
namespace {
struct Read {
  std::string data;
  int error = 0;
};
Read proc_read(const fs::path& path, size_t limit = 1024 * 1024) {
  Read out;
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    out.error = errno;
    return out;
  }
  char buffer[4096];
  while (out.data.size() <= limit) {
    ssize_t n = ::read(fd, buffer, std::min(sizeof(buffer), limit + 1 - out.data.size()));
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0) {
      out.error = errno;
      break;
    }
    if (n == 0)
      break;
    out.data.append(buffer, n);
    if (out.data.size() > limit) {
      out.error = EFBIG;
      break;
    }
  }
  close(fd);
  return out;
}
std::string trim(std::string s) {
  auto first = s.find_first_not_of(" \r\n\t");
  if (first == std::string::npos)
    return "";
  return s.substr(first, s.find_last_not_of(" \r\n\t") - first + 1);
}
std::string start_time(const std::string& s) {
  auto pos = s.rfind(')');
  if (pos == std::string::npos)
    return "";
  std::istringstream in(s.substr(pos + 2));
  std::string f;
  for (int i = 3; i <= 22; ++i)
    if (!(in >> f))
      return "";
  if (f.empty() || f == "0" || f.find_first_not_of("0123456789") != std::string::npos)
    return "";
  return f;
}
std::string process_error(const J& p, const std::string& field) {
  std::string message = "PID " + std::to_string(p.at("pid").get<int>()) + " ";
  if (p.value("state", "") == "not_visible")
    message += "当前不可见，可能已退出、PID 已改变，或被运行权限隔离。";
  else
    message += "无法读取 " + field + "。";
  for (const auto& e : p.at("errors"))
    if (e.at("field") == field) {
      message += " errno=" + std::to_string(e.at("errno").get<int>()) + " (" +
                 e.at("message").get<std::string>() + ")。";
      break;
    }
  if (!runtime_info().value("root", false))
    message += "请在 Android 原生 Root 终端启动工具；容器内显示 root 不代表内核权限。";
  return message;
}
}  // namespace
J runtime_info(const fs::path& proc_root) {
  auto status = proc_read(proc_root / "self/status", 65536);
  int real = -1, effective = -1;
  std::string caps, selinux;
  if (!status.error) {
    std::istringstream in(status.data);
    std::string line;
    while (std::getline(in, line)) {
      if (line.rfind("Uid:", 0) == 0) {
        std::istringstream s(line.substr(4));
        s >> real >> effective;
      } else if (line.rfind("CapEff:", 0) == 0)
        caps = trim(line.substr(7));
    }
  }
  auto se = proc_read(proc_root / "self/attr/current", 4096);
  if (!se.error) {
    selinux = trim(se.data);
    auto nul = selinux.find('\0');
    if (nul != std::string::npos)
      selinux.resize(nul);
  }
  bool known = effective >= 0, root = known && effective == 0;
  bool translated = known && int(geteuid()) != effective;
  return {{"pid", getpid()},
          {"reported_euid", geteuid()},
          {"kernel_uid", real},
          {"kernel_euid", effective},
          {"root", root},
          {"identity_known", known},
          {"identity_translated", translated},
          {"cap_effective", caps},
          {"selinux_context", selinux},
          {"source", "/proc/self/status"},
          {"process_scope", root ? "root" : "restricted"},
          {"message", root         ? "内核 UID 0，仍需满足目标访问策略"
                      : translated ? "容器显示 root，但实际内核 UID 为 " + std::to_string(effective)
                      : known      ? "普通权限，进程列表仅包含当前可见目标"
                                   : "无法确认实际运行权限"}};
}
J process_probe(int pid, const fs::path& proc_root) {
  if (pid <= 0)
    throw std::runtime_error("PID 必须是正整数");
  fs::path dir = proc_root / std::to_string(pid);
  struct stat st{};
  int stat_error = 0;
  bool exists = ::stat(dir.c_str(), &st) == 0;
  if (!exists)
    stat_error = errno;
  J out = {{"pid", pid},
           {"uid", -1},
           {"name", "[PID " + std::to_string(pid) + "]"},
           {"name_source", "pid"},
           {"bits", 0},
           {"identity", ""},
           {"directory_visible", exists},
           {"maps_readable", false},
           {"errors", J::array()}};
  auto read = [&](const char* field, size_t limit = 1024 * 1024) {
    auto r = proc_read(dir / field, limit);
    if (r.error)
      out["errors"].push_back(
          {{"field", field}, {"errno", r.error}, {"message", std::strerror(r.error)}});
    return r;
  };
  auto command = read("cmdline");
  std::string name;
  if (!command.error)
    name = trim(command.data.substr(0, command.data.find('\0')));
  if (!name.empty()) {
    out["name"] = name;
    out["name_source"] = "cmdline";
  } else {
    auto comm = read("comm", 65536);
    if (!comm.error && !trim(comm.data).empty()) {
      out["name"] = trim(comm.data);
      out["name_source"] = "comm";
    }
  }
  auto stat = read("stat", 65536);
  if (!stat.error) {
    out["identity"] = start_time(stat.data);
    if (out["name_source"] == "pid") {
      auto a = stat.data.find('('), b = stat.data.rfind(')');
      if (a != std::string::npos && b > a) {
        out["name"] = stat.data.substr(a + 1, b - a - 1);
        out["name_source"] = "stat";
      }
    }
  }
  auto status = read("status", 65536);
  if (!status.error) {
    std::istringstream in(status.data);
    std::string line;
    while (std::getline(in, line))
      if (line.rfind("Uid:", 0) == 0) {
        int uid = -1;
        std::istringstream(line.substr(4)) >> uid;
        out["uid"] = uid;
        break;
      }
  }

  int fd = open((dir / "exe").c_str(), O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    unsigned char header[5]{};
    ssize_t n;
    do {
      n = ::read(fd, header, 5);
    } while (n < 0 && errno == EINTR);
    close(fd);
    if (n == 5 && std::memcmp(header, "\177ELF", 4) == 0)
      out["bits"] = header[4] == 1 ? 32 : header[4] == 2 ? 64 : 0;
  }
  fd = open((dir / "maps").c_str(), O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    char c;
    ssize_t n;
    do {
      n = ::read(fd, &c, 1);
    } while (n < 0 && errno == EINTR);
    if (n > 0)
      out["maps_readable"] = true;
    else if (n < 0)
      out["errors"].push_back(
          {{"field", "maps"}, {"errno", errno}, {"message", std::strerror(errno)}});
    close(fd);
  } else {
    int err = errno;
    out["errors"].push_back({{"field", "maps"}, {"errno", err}, {"message", std::strerror(err)}});
  }
  bool evidence =
      exists || !command.error || !stat.error || !status.error || out["maps_readable"] == true;
  out["state"] =
      !evidence && stat_error == ENOENT
          ? "not_visible"
          : (out["identity"] != "" && out["maps_readable"] == true ? "ready" : "restricted");
  out["metadata_complete"] = out["errors"].empty();
  out["connectable"] = out["state"] == "ready";
  if (out["state"] == "not_visible")
    out["message"] = "当前运行环境看不到该 PID，不能仅据此判断应用已退出";
  else if (out["identity"] == "")
    out["message"] = "PID 可见，但启动身份不可读，暂时不能安全绑定目标";
  else if (out["maps_readable"] == false)
    out["message"] = "PID 可见，但 maps 不可读，需要更高运行权限";
  else
    out["message"] = "目标可连接";
  return out;
}
J process_catalog(const fs::path& proc_root) {
  J rows = J::array();
  size_t restricted = 0, vanished = 0;
  DIR* dir = opendir(proc_root.c_str());
  if (!dir)
    throw std::runtime_error("无法枚举 " + proc_root.string() + "：" + std::strerror(errno));
  while (auto entry = readdir(dir)) {
    std::string name = entry->d_name;
    if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos)
      continue;
    auto value = number(name);
    if (!value || value > INT32_MAX)
      continue;
    auto p = process_probe(value, proc_root);
    if (p["state"] == "not_visible") {
      ++vanished;
      continue;
    }
    if (p["state"] != "ready" || p["metadata_complete"] == false)
      ++restricted;
    rows.push_back(p);
  }
  closedir(dir);
  std::sort(rows.begin(), rows.end(),
            [](const J& a, const J& b) { return a["pid"].get<int>() < b["pid"].get<int>(); });
  return {{"processes", rows},
          {"count", rows.size()},
          {"restricted_count", restricted},
          {"vanished_count", vanished},
          {"runtime", runtime_info(proc_root)}};
}
J processes() {
  return process_catalog().at("processes");
}
void check_identity(const Target& t) {
  auto r = proc_read(fs::path("/proc") / std::to_string(t.pid) / "stat", 65536);
  if (r.error)
    throw std::runtime_error("目标身份读取失败：PID " + std::to_string(t.pid) +
                             "，errno=" + std::to_string(r.error) + "，" + std::strerror(r.error));
  auto current = start_time(r.data);
  if (current.empty() || current != t.identity)
    throw std::runtime_error("目标进程已经重启或身份失效，请重新连接");
}
Target target(int pid) {
  auto p = process_probe(pid);
  if (p["identity"] == "")
    throw std::runtime_error(process_error(p, "stat"));
  if (!p["maps_readable"].get<bool>())
    throw std::runtime_error(process_error(p, "maps"));
  Target t;
  t.pid = pid;
  t.uid = p["uid"];
  t.name = p["name"];
  t.bits = p["bits"];
  t.identity = p["identity"];
  auto input = proc_read(fs::path("/proc") / std::to_string(pid) / "maps", 64 * 1024 * 1024);
  if (input.error)
    throw std::runtime_error("读取 maps 失败：" + std::string(std::strerror(input.error)));
  std::istringstream in(input.data);
  std::string line;
  std::map<std::string, int> indices;
  while (std::getline(in, line)) {
    std::istringstream s(line);
    std::string bounds, off, dev, inode;
    Region r;
    if (!(s >> bounds >> r.perms >> off >> dev >> inode))
      continue;
    auto dash = bounds.find('-');
    if (dash == std::string::npos)
      continue;
    r.start = number(bounds.substr(0, dash), true);
    r.end = number(bounds.substr(dash + 1), true);
    r.file_offset = number(off, true);
    std::getline(s, r.path);
    r.path = trim(r.path);
    r.name = fs::path(r.path).filename().string();
    r.kind = r.path.empty() || r.path == "[anonymous]" ? "A"
             : r.path == "[heap]"                      ? "Ch"
             : r.path.rfind("[stack", 0) == 0          ? "S"
             : r.path.rfind("[anon:scudo:", 0) == 0 || r.path.rfind("[anon:libc_malloc", 0) == 0
                 ? "Ca"
             : r.path == "[anon:.bss]" ? "Cb"
             : r.path[0] == '/'        ? (r.perms.find('x') != std::string::npos ? "Xa" : "Cd")
                                       : "O";
    r.root = !r.path.empty() && r.path[0] == '/';
    if (r.kind == "Cb" && !t.regions.empty() && t.regions.back().root &&
        t.regions.back().end == r.start) {
      r.root = true;
      r.name = t.regions.back().name + ":bss";
    }
    if (r.root) {
      r.index = ++indices[r.name + "/" + r.kind];
      r.id = r.name + "[" + std::to_string(r.index) + "][" + r.kind + "]";
    }
    if (r.end > r.start)
      t.regions.push_back(r);
  }
  if (t.regions.empty())
    throw std::runtime_error("目标没有可读取的 maps 映射记录");
  check_identity(t);
  return t;
}
}  // namespace cs
