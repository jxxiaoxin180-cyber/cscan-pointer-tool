#ifndef AHWBP_PARADISE_H
#define AHWBP_PARADISE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ahwb_paradise_transport {
  AHWBP_PARADISE_TRANSPORT_NONE = 0,
  AHWBP_PARADISE_TRANSPORT_FD_IOREMAP,
  AHWBP_PARADISE_TRANSPORT_DECNET_HOOK,
};

struct ahwb_paradise {
  int fd;
  enum ahwb_paradise_transport transport;
  int acquisition; /* 1=existing, 2=current magic, 3=legacy magic, 4=socket, 5=inherited */
  int open_errors[4];
};

struct ahwb_paradise_read_result {
  size_t transferred;
  uint64_t ioctl_calls;
};

int ahwb_paradise_open(struct ahwb_paradise *driver);
/* CSCAN extension: mode 0=auto, 1=fd-only, 2=hook-only. */
int ahwb_paradise_open_mode(struct ahwb_paradise *driver, int mode, int inherited_fd);
void ahwb_paradise_close(struct ahwb_paradise *driver);

int ahwb_paradise_read(struct ahwb_paradise *driver, pid_t pid,
                       uint64_t address, void *buffer, size_t length,
                       struct ahwb_paradise_read_result *result);

const char *
ahwb_paradise_transport_name(enum ahwb_paradise_transport transport);

/* Exposed for ABI regression tests. */
unsigned long
ahwb_paradise_ioctl_request(enum ahwb_paradise_transport transport);
size_t ahwb_paradise_command_size(enum ahwb_paradise_transport transport);
size_t ahwb_paradise_chunk_size(uint64_t address, size_t remaining,
                                size_t page_size);

#ifdef __cplusplus
}
#endif

#endif
