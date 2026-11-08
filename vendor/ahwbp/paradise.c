#define _GNU_SOURCE

/*
 * Paradise userspace ABI adapter.
 * SPDX-License-Identifier: BSD-3-Clause
 * See LICENSE in this directory.
 */

#include "ahwbp/paradise.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AF_DECnet
#define AF_DECnet 12
#endif

#define PARADISE_DRIVER_NAME "[paradise_driver]"
#define PARADISE_INSTALL_MAGIC1 UINT32_C(0xDEADBEEF)
#define PARADISE_INSTALL_MAGIC2_CURRENT UINT32_C(0xF00DCAFE)
#define PARADISE_INSTALL_MAGIC2_LEGACY UINT32_C(0xCAFEBABE)
#define PARADISE_WMT_NORMAL 0

struct paradise_memory_cmd {
  pid_t pid;
  uintptr_t src_va;
  uintptr_t dst_va;
  size_t size;
  uintptr_t phy_addr;
};

struct paradise_memory_ioremap_cmd {
  pid_t pid;
  uintptr_t src_va;
  uintptr_t dst_va;
  size_t size;
  uintptr_t phy_addr;
  int prot;
};

#define PARADISE_IOCTL_READ_MEMORY _IOWR('W', 9, struct paradise_memory_cmd)
#define PARADISE_IOCTL_READ_MEMORY_IOREMAP                                     \
  _IOWR('W', 16, struct paradise_memory_ioremap_cmd)

_Static_assert(sizeof(uintptr_t) == 8U,
               "Paradise integration requires a 64-bit ABI");
_Static_assert(sizeof(struct paradise_memory_cmd) == 40U,
               "unexpected Paradise memory command ABI");
_Static_assert(sizeof(struct paradise_memory_ioremap_cmd) == 48U,
               "unexpected Paradise ioremap command ABI");

static bool parse_fd_name(const char *text, int *fd) {
  char *end;
  long value;

  if (text == NULL || fd == NULL || text[0] == '\0') {
    return false;
  }
  errno = 0;
  value = strtol(text, &end, 10);
  if (errno != 0 || *end != '\0' || value < 0 || value > INT_MAX) {
    return false;
  }
  *fd = (int)value;
  return true;
}

static bool fd_has_driver_name(int fd) {
  char link_path[64];
  char target[256];
  ssize_t length;

  if (snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd) >=
      (int)sizeof(link_path)) {
    return false;
  }
  length = readlink(link_path, target, sizeof(target) - 1U);
  if (length < 0) {
    return false;
  }
  target[length] = '\0';
  return strstr(target, PARADISE_DRIVER_NAME) != NULL;
}

static int duplicate_existing_driver_fd(void) {
  DIR *directory;
  struct dirent *entry;
  int directory_fd;
  int result = -1;

  directory = opendir("/proc/self/fd");
  if (directory == NULL) {
    return -1;
  }
  directory_fd = dirfd(directory);
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    int candidate;
    if (!parse_fd_name(entry->d_name, &candidate) ||
        candidate == directory_fd || !fd_has_driver_name(candidate)) {
      continue;
    }
    result = fcntl(candidate, F_DUPFD_CLOEXEC, 3);
    if (result >= 0) {
      break;
    }
  }
  {
    int saved_error = errno;
    (void)closedir(directory);
    errno = result >= 0 ? 0 : saved_error;
  }
  return result;
}

static int request_driver_fd(uint32_t second_magic) {
#if defined(SYS_reboot) || defined(__NR_reboot)
  int installed_fd = -1;
  long returned;
  int flags;
#if defined(SYS_reboot)
  const long syscall_number = SYS_reboot;
#else
  const long syscall_number = __NR_reboot;
#endif

  errno = 0;
  returned = syscall(syscall_number, (unsigned long)PARADISE_INSTALL_MAGIC1,
                     (unsigned long)second_magic, 0UL, &installed_fd);
  if (installed_fd < 0) {
    if (errno == 0) {
      errno = returned < 0 ? (int)-returned : ENODEV;
    }
    return -1;
  }
  flags = fcntl(installed_fd, F_GETFD);
  if (flags == -1) {
    int saved_error = errno;
    (void)close(installed_fd);
    errno = saved_error;
    return -1;
  }
  if (fcntl(installed_fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
    int saved_error = errno;
    (void)close(installed_fd);
    errno = saved_error;
    return -1;
  }
  return installed_fd;
#else
  (void)second_magic;
  errno = ENOSYS;
  return -1;
#endif
}

static int open_decnet_hook(void) {
  int fd = socket(AF_DECnet, SOCK_RAW, 0);
  int flags;

  if (fd == -1) {
    return -1;
  }
  flags = fcntl(fd, F_GETFD);
  if (flags == -1 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
    int saved_error = errno;
    (void)close(fd);
    errno = saved_error;
    return -1;
  }
  return fd;
}

/* CSCAN: explicit transport mode and acquisition diagnostics, no normal-reader fallback. */
int ahwb_paradise_open_mode(struct ahwb_paradise *driver, int mode, int inherited_fd) {
  int fd = -1;
  int saved_error = ENODEV;
  if (driver == NULL || mode < 0 || mode > 2 || inherited_fd < -1) {
    errno = EINVAL;
    return -1;
  }
  memset(driver, 0, sizeof(*driver));
  driver->fd = -1;
  if (inherited_fd >= 0) {
    if (!fd_has_driver_name(inherited_fd)) { errno = ENODEV; return -1; }
    fd = fcntl(inherited_fd, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return -1;
    driver->fd = fd;
    driver->transport = mode == 2 ? AHWBP_PARADISE_TRANSPORT_DECNET_HOOK : AHWBP_PARADISE_TRANSPORT_FD_IOREMAP;
    driver->acquisition = 5;
    return 0;
  }
  if (mode != 2) {
    fd = duplicate_existing_driver_fd();
    if (fd >= 0) {
      driver->fd = fd;
      driver->transport = AHWBP_PARADISE_TRANSPORT_FD_IOREMAP;
      driver->acquisition = 1;
      return 0;
    }
    driver->open_errors[0] = errno ? errno : ENODEV;
    fd = request_driver_fd(PARADISE_INSTALL_MAGIC2_CURRENT);
    if (fd >= 0) driver->acquisition = 2;
    else {
      driver->open_errors[1] = errno ? errno : ENODEV;
      fd = request_driver_fd(PARADISE_INSTALL_MAGIC2_LEGACY);
      if (fd >= 0) driver->acquisition = 3;
      else driver->open_errors[2] = errno ? errno : ENODEV;
    }
    if (fd >= 0) {
      driver->fd = fd;
      driver->transport = AHWBP_PARADISE_TRANSPORT_FD_IOREMAP;
      return 0;
    }
    saved_error = driver->open_errors[2];
  }
  if (mode != 1) {
    fd = open_decnet_hook();
    if (fd >= 0) {
      driver->fd = fd;
      driver->transport = AHWBP_PARADISE_TRANSPORT_DECNET_HOOK;
      driver->acquisition = 4;
      return 0;
    }
    driver->open_errors[3] = errno ? errno : ENODEV;
    saved_error = driver->open_errors[3];
  }
  errno = saved_error;
  return -1;
}
int ahwb_paradise_open(struct ahwb_paradise *driver) {
  return ahwb_paradise_open_mode(driver, 0, -1);
}

void ahwb_paradise_close(struct ahwb_paradise *driver) {
  if (driver == NULL) {
    return;
  }
  if (driver->fd >= 0) {
    (void)close(driver->fd);
  }
  driver->fd = -1;
  driver->transport = AHWBP_PARADISE_TRANSPORT_NONE;
}

const char *
ahwb_paradise_transport_name(enum ahwb_paradise_transport transport) {
  switch (transport) {
  case AHWBP_PARADISE_TRANSPORT_FD_IOREMAP:
    return "fd-ioremap";
  case AHWBP_PARADISE_TRANSPORT_DECNET_HOOK:
    return "decnet-hook";
  case AHWBP_PARADISE_TRANSPORT_NONE:
  default:
    return "none";
  }
}

unsigned long
ahwb_paradise_ioctl_request(enum ahwb_paradise_transport transport) {
  switch (transport) {
  case AHWBP_PARADISE_TRANSPORT_FD_IOREMAP:
    return PARADISE_IOCTL_READ_MEMORY_IOREMAP;
  case AHWBP_PARADISE_TRANSPORT_DECNET_HOOK:
    return PARADISE_IOCTL_READ_MEMORY;
  case AHWBP_PARADISE_TRANSPORT_NONE:
  default:
    return 0UL;
  }
}

size_t ahwb_paradise_command_size(enum ahwb_paradise_transport transport) {
  switch (transport) {
  case AHWBP_PARADISE_TRANSPORT_FD_IOREMAP:
    return sizeof(struct paradise_memory_ioremap_cmd);
  case AHWBP_PARADISE_TRANSPORT_DECNET_HOOK:
    return sizeof(struct paradise_memory_cmd);
  case AHWBP_PARADISE_TRANSPORT_NONE:
  default:
    return 0U;
  }
}

size_t ahwb_paradise_chunk_size(uint64_t address, size_t remaining,
                                size_t page_size) {
  size_t page_remaining;

  if (remaining == 0U || page_size == 0U) {
    return 0U;
  }
  page_remaining = page_size - (size_t)(address % page_size);
  return remaining < page_remaining ? remaining : page_remaining;
}

static int issue_read_ioctl(struct ahwb_paradise *driver, pid_t pid,
                            uint64_t address, void *buffer, size_t length, uint64_t *ioctl_calls) {
  int returned;

  do {
    ++(*ioctl_calls);
    if (driver->transport == AHWBP_PARADISE_TRANSPORT_FD_IOREMAP) {
      struct paradise_memory_ioremap_cmd command = {
          .pid = pid,
          .src_va = (uintptr_t)address,
          .dst_va = (uintptr_t)buffer,
          .size = length,
          .phy_addr = 0U,
          .prot = PARADISE_WMT_NORMAL,
      };
      returned =
          ioctl(driver->fd, PARADISE_IOCTL_READ_MEMORY_IOREMAP, &command);
    } else {
      struct paradise_memory_cmd command = {
          .pid = pid,
          .src_va = (uintptr_t)address,
          .dst_va = (uintptr_t)buffer,
          .size = length,
          .phy_addr = 0U,
      };
      returned = ioctl(driver->fd, PARADISE_IOCTL_READ_MEMORY, &command);
    }
  } while (returned == -1 && errno == EINTR);
  return returned;
}

int ahwb_paradise_read(struct ahwb_paradise *driver, pid_t pid,
                       uint64_t address, void *buffer, size_t length,
                       struct ahwb_paradise_read_result *result) {
  struct ahwb_paradise_read_result local_result = {0};
  long configured_page_size;
  size_t page_size;

  if (result == NULL) {
    result = &local_result;
  }
  memset(result, 0, sizeof(*result));
  if (driver == NULL || driver->fd < 0 ||
      driver->transport == AHWBP_PARADISE_TRANSPORT_NONE || pid <= 0 ||
      buffer == NULL || length == 0U || address > (uint64_t)UINTPTR_MAX ||
      length - 1U > UINT64_MAX - address ||
      address + length - 1U > (uint64_t)UINTPTR_MAX) {
    errno = EINVAL;
    return -1;
  }

  configured_page_size = sysconf(_SC_PAGESIZE);
  if (configured_page_size <= 0) { errno = EINVAL; return -1; }
  page_size = (size_t)configured_page_size;
  while (result->transferred < length) {
    uint64_t current_address = address + result->transferred;
    size_t chunk = ahwb_paradise_chunk_size(
        current_address, length - result->transferred, page_size);
    {
      int status =
          issue_read_ioctl(driver, pid, current_address,
                           (uint8_t *)buffer + result->transferred, chunk, &result->ioctl_calls);
      if (status != 0) {
        if (status > 0 || errno == 0) {
          errno = EIO;
        }
        return -1;
      }
    }
    result->transferred += chunk;
  }
  return 0;
}
