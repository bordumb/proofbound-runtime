#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>

#ifdef __linux__

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#if defined(__x86_64__)
#define CONTROL_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CONTROL_ARCH_NAME "x86_64"
#elif defined(__aarch64__)
#define CONTROL_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define CONTROL_ARCH_NAME "aarch64"
#else
#error "broker child control supports only x86_64 and aarch64"
#endif

#define DENY_SYSCALL(NUMBER)                                                   \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (NUMBER), 0, 1),                        \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static const char *const usage =
    "usage: broker-child-control <retained-fd> "
    "<absolute-new-state-directory> -- <command> [args...]";

static int write_all(int descriptor, const void *data, size_t size) {
  const unsigned char *cursor = data;
  while (size > 0) {
    ssize_t written = write(descriptor, cursor, size);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return -1;
    }
    cursor += (size_t)written;
    size -= (size_t)written;
  }
  return 0;
}

static int write_new_at(int directory, const char *name, const void *data,
                        size_t size) {
  int descriptor =
      openat(directory, name,
             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
  if (descriptor < 0) {
    return -1;
  }
  int result = write_all(descriptor, data, size);
  if (result == 0 && fsync(descriptor) != 0) {
    result = -1;
  }
  if (close(descriptor) != 0) {
    result = -1;
  }
  return result;
}

static int parse_descriptor(const char *text, int *result) {
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value < 3 ||
      value > INT32_MAX) {
    return -1;
  }
  *result = (int)value;
  return 0;
}

static int validate_channel(int descriptor) {
  struct sockaddr_storage address;
  socklen_t address_size = sizeof(address);
  int socket_type = 0;
  socklen_t type_size = sizeof(socket_type);
  if (fcntl(descriptor, F_GETFD) < 0 ||
      getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socket_type, &type_size) != 0 ||
      type_size != sizeof(socket_type) || socket_type != SOCK_STREAM ||
      getsockname(descriptor, (struct sockaddr *)&address, &address_size) != 0 ||
      address_size < sizeof(sa_family_t) || address.ss_family != AF_UNIX) {
    return -1;
  }
  return 0;
}

static int close_foreign_descriptors(int retained, int state) {
  DIR *directory = opendir("/proc/self/fd");
  if (directory == NULL) {
    return -1;
  }
  int inventory = dirfd(directory);
  errno = 0;
  struct dirent *entry = NULL;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    long descriptor = strtol(entry->d_name, &end, 10);
    if (end == entry->d_name || *end != '\0' || descriptor < 3 ||
        descriptor == retained || descriptor == state || descriptor == inventory) {
      continue;
    }
    if (close((int)descriptor) != 0 && errno != EBADF) {
      closedir(directory);
      return -1;
    }
  }
  int read_error = errno;
  if (closedir(directory) != 0 || read_error != 0) {
    return -1;
  }
  return 0;
}

static const struct sock_filter filter_instructions[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CONTROL_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, nr)),
    DENY_SYSCALL(__NR_socket),
    DENY_SYSCALL(__NR_socketpair),
    DENY_SYSCALL(__NR_connect),
    DENY_SYSCALL(__NR_bind),
    DENY_SYSCALL(__NR_listen),
    DENY_SYSCALL(__NR_accept),
#ifdef __NR_accept4
    DENY_SYSCALL(__NR_accept4),
#endif
    DENY_SYSCALL(__NR_sendto),
    DENY_SYSCALL(__NR_recvfrom),
    DENY_SYSCALL(__NR_sendmsg),
    DENY_SYSCALL(__NR_recvmsg),
#ifdef __NR_sendmmsg
    DENY_SYSCALL(__NR_sendmmsg),
#endif
#ifdef __NR_recvmmsg
    DENY_SYSCALL(__NR_recvmmsg),
#endif
    DENY_SYSCALL(__NR_setsockopt),
    DENY_SYSCALL(__NR_getsockopt),
    DENY_SYSCALL(__NR_getpeername),
    DENY_SYSCALL(__NR_getsockname),
#ifdef __NR_io_uring_setup
    DENY_SYSCALL(__NR_io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
    DENY_SYSCALL(__NR_io_uring_enter),
#endif
#ifdef __NR_io_uring_register
    DENY_SYSCALL(__NR_io_uring_register),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

int main(int argc, char **argv) {
  if (argc < 5 || strcmp(argv[3], "--") != 0 || argv[4] == NULL) {
    fprintf(stderr, "%s\n", usage);
    return 2;
  }
  if (geteuid() != 0 || argv[2][0] != '/') {
    fprintf(stderr, "broker child control requires root and an absolute state path\n");
    return 3;
  }
  int retained = -1;
  if (parse_descriptor(argv[1], &retained) != 0 || validate_channel(retained) != 0) {
    fprintf(stderr, "retained descriptor is not one Unix stream channel\n");
    return 2;
  }
  int descriptor_flags = fcntl(retained, F_GETFD);
  if (descriptor_flags < 0 ||
      fcntl(retained, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
    perror("retain broker descriptor");
    return 4;
  }

  if (mkdir(argv[2], 0755) != 0) {
    perror("create broker boundary state");
    return 4;
  }
  int state = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (state < 0) {
    perror("open broker boundary state");
    return 4;
  }
  if (write_new_at(state, "seccomp-program.bin", filter_instructions,
                   sizeof(filter_instructions)) != 0) {
    perror("write seccomp program identity");
    close(state);
    return 4;
  }
  if (close_foreign_descriptors(retained, state) != 0) {
    perror("close foreign descriptors");
    close(state);
    return 4;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    perror("set no_new_privs");
    close(state);
    return 4;
  }
  struct sock_fprog program = {
      .len = (unsigned short)(sizeof(filter_instructions) /
                              sizeof(filter_instructions[0])),
      .filter = (struct sock_filter *)filter_instructions,
  };
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
    perror("install broker child seccomp filter");
    close(state);
    return 4;
  }

  char observations[256];
  int observations_size = snprintf(
      observations, sizeof(observations),
      "architecture=%s\ninstruction_count=%zu\nno_new_privs=true\n"
      "retained_fd=%d\nsocket_family=unix\nsocket_type=stream\n",
      CONTROL_ARCH_NAME,
      sizeof(filter_instructions) / sizeof(filter_instructions[0]), retained);
  if (observations_size <= 0 ||
      (size_t)observations_size >= sizeof(observations) ||
      write_new_at(state, "boundary-observations.txt", observations,
                   (size_t)observations_size) != 0) {
    perror("write broker boundary observations");
    close(state);
    return 4;
  }
  if (close(state) != 0) {
    perror("close broker boundary state");
    return 4;
  }
  if (setgroups(0, NULL) != 0 || setgid(65534) != 0 || setuid(65534) != 0) {
    perror("drop broker child identity");
    return 4;
  }
  execvp(argv[4], &argv[4]);
  perror("exec broker child");
  return errno == ENOENT ? 127 : 126;
}

#else

int main(void) {
  fprintf(stderr, "broker child control requires native Linux\n");
  return 3;
}

#endif
