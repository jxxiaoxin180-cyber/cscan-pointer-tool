#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <limits>
#include <sstream>

#include "core.hpp"
namespace cs {
namespace {
const char* acquisition_name(int n) {
  switch (n) {
    case 1:
      return "existing-fd";
    case 2:
      return "current-0xF00DCAFE";
    case 3:
      return "legacy-0xCAFEBABE";
    case 4:
      return "decnet-socket";
    case 5:
      return "inherited-fd";
    default:
      return "none";
  }
}
}  // namespace
Reader::Reader(int pid, const std::string& backend, int inherited) : pid_(pid), backend_(backend) {
  if (pid <= 0)
    throw std::runtime_error("读取器需要有效 PID");
  if (backend == "pread")
    fd_ = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
  else if (backend == "paradise" || backend == "paradise35" || backend == "paradise-hook") {
    int mode = backend == "paradise" ? 0 : backend == "paradise35" ? 1 : 2;
    if (ahwb_paradise_open_mode(&paradise_, mode, inherited) < 0) {
      last_error_ = errno;
      std::ostringstream details;
      const char* names[] = {"已有 FD", "当前握手", "旧版握手", "Hook 通道"};
      for (int i = 0; i < 4; ++i)
        if (paradise_.open_errors[i])
          details << names[i] << " errno=" << paradise_.open_errors[i] << "; ";
      throw std::runtime_error("Paradise 初始化失败：" + std::string(std::strerror(last_error_)) +
                               "（" + details.str() +
                               "）。请核对原生运行环境及已加载驱动；未改用普通读取。");
    }
  } else if (backend != "syscall" && backend != "normal")
    throw std::runtime_error("不支持的读取器：" + backend);
  if (backend == "pread" && fd_ < 0)
    throw std::runtime_error("pread 初始化失败：errno=" + std::to_string(errno) + "，" +
                             std::strerror(errno));
}
Reader::~Reader() {
  if (fd_ >= 0)
    close(fd_);
  ahwb_paradise_close(&paradise_);
}
ssize_t Reader::read(uint64_t addr, void* buffer, size_t length) {
  std::lock_guard<std::mutex> lock(mutex_);
  ++read_calls_;
  last_error_ = 0;
  errno = 0;
  if (!buffer || !length || length > size_t(std::numeric_limits<ssize_t>::max()) ||
      addr > UINTPTR_MAX || length - 1 > UINT64_MAX - addr || addr + length - 1 > UINTPTR_MAX) {
    errno = last_error_ = EINVAL;
    return -1;
  }
  auto done = [&](ssize_t n) {
    if (n > 0)
      bytes_read_ += n;
    if (n < 0 || size_t(n) < length)
      last_error_ = errno ? errno : EIO;
    return n;
  };
  if (paradise_.fd >= 0) {
    ahwb_paradise_read_result result{};
    int status = ahwb_paradise_read(&paradise_, pid_, addr, buffer, length, &result);
    ioctl_calls_ += result.ioctl_calls;
    if (status < 0) {
      last_error_ = errno ? errno : EIO;
      errno = last_error_;
      if (result.transferred) {
        bytes_read_ += result.transferred;
        return result.transferred;
      }
      return -1;
    }
    return done(result.transferred);
  }
  auto proc_mem = [&](uint64_t address, void* dst, size_t size) -> ssize_t {
    if (address > uint64_t(INT64_MAX) || size - 1 > uint64_t(INT64_MAX) - address) {
      errno = EOVERFLOW;
      return -1;
    }
    if (fd_ < 0)
      fd_ = open(("/proc/" + std::to_string(pid_) + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0)
      return -1;
    ssize_t n;
    errno = 0;
    do {
      ++pread_reads_;
      n = pread64(fd_, dst, size, static_cast<off64_t>(address));
    } while (n < 0 && errno == EINTR);
    return n;
  };
  if (backend_ == "pread")
    return done(proc_mem(addr, buffer, length));
  iovec local{buffer, length}, remote{reinterpret_cast<void*>(uintptr_t(addr)), length};
  ssize_t n;
  do {
    ++syscall_reads_;
    n = syscall(SYS_process_vm_readv, pid_, &local, 1UL, &remote, 1UL, 0UL);
  } while (n < 0 && errno == EINTR);
  if (backend_ == "syscall" || n == ssize_t(length))
    return done(n);
  // Explicit 'normal' policy permits pread to fill only the unread suffix.
  size_t prefix = n > 0 ? size_t(n) : 0;
  ssize_t extra = proc_mem(addr + prefix, static_cast<char*>(buffer) + prefix, length - prefix);
  if (extra > 0)
    return done(prefix + size_t(extra));
  if (prefix)
    return done(prefix);
  return done(-1);
}
ssize_t Reader::read_exact(uint64_t addr, void* buffer, size_t length) {
  if (!buffer || !length || length > size_t(std::numeric_limits<ssize_t>::max()) ||
      length - 1 > UINT64_MAX - addr) {
    errno = EINVAL;
    return -1;
  }
  size_t done = 0;
  while (done < length) {
    auto n = read(addr + done, static_cast<unsigned char*>(buffer) + done, length - done);
    if (n <= 0)
      return done ? ssize_t(done) : n;
    if (size_t(n) > length - done) {
      errno = EIO;
      return done ? ssize_t(done) : -1;
    }
    done += n;
  }
  return done;
}
J Reader::diagnostics() const {
  const bool kernel =
      backend_ == "paradise" || backend_ == "paradise35" || backend_ == "paradise-hook";
  return {{"backend", backend_},
          {"channel_open", kernel ? paradise_.fd >= 0 : true},
          {"read_verified", bytes_read_ > 0},
          {"transport", kernel                 ? ahwb_paradise_transport_name(paradise_.transport)
                        : backend_ == "pread"  ? "proc-mem"
                        : backend_ == "normal" ? "process-vm+proc-mem"
                                               : "process-vm"},
          {"protocol", kernel ? (paradise_.transport == AHWBP_PARADISE_TRANSPORT_FD_IOREMAP
                                     ? "ioctl-W16-ioremap"
                                     : "ioctl-W9-read")
                              : "standard-linux"},
          {"acquisition", acquisition_name(paradise_.acquisition)},
          {"page_size", sysconf(_SC_PAGESIZE)},
          {"read_calls", read_calls_},
          {"ioctl_calls", ioctl_calls_},
          {"syscall_reads", syscall_reads_},
          {"pread_reads", pread_reads_},
          {"bytes_read", bytes_read_},
          {"last_errno", last_error_},
          {"last_error", last_error_ ? std::strerror(last_error_) : ""}};
}
}  // namespace cs
