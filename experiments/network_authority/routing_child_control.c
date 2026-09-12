#define _GNU_SOURCE

// Common scalar-syscall boundary for routing mechanisms A and B.

#include <errno.h>
#include <stdio.h>

#ifdef __linux__

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
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
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

#if defined(__x86_64__)
#define CONTROL_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CONTROL_ARCH_NAME "x86_64"
#elif defined(__aarch64__)
#define CONTROL_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define CONTROL_ARCH_NAME "aarch64"
#else
#error "routing child control supports only x86_64 and aarch64"
#endif

#define DENY_SYSCALL(NUMBER)                                                   \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (NUMBER), 0, 1),                        \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static const char *const usage =
    "usage: routing-child-control <absolute-new-state-directory> -- "
    "<command> [args...]";

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

static int close_foreign_descriptors(int state) {
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
        descriptor == state || descriptor == inventory) {
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

    // Only IPv4/IPv6 stream socket creation reaches the routing mechanism.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 8),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[1])),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0),
    BPF_STMT(BPF_RET | BPF_K,
             SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, nr)),
    DENY_SYSCALL(__NR_socketpair),
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
  if (argc < 4 || strcmp(argv[2], "--") != 0 || argv[3] == NULL) {
    fprintf(stderr, "%s\n", usage);
    return 2;
  }
  if (geteuid() != 0 || argv[1][0] != '/') {
    fprintf(stderr,
            "routing child control requires root and an absolute state path\n");
    return 3;
  }
  if (mkdir(argv[1], 0755) != 0) {
    perror("create routing boundary state");
    return 4;
  }
  int state = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (state < 0) {
    perror("open routing boundary state");
    return 4;
  }
  if (write_new_at(state, "seccomp-program.bin", filter_instructions,
                   sizeof(filter_instructions)) != 0) {
    perror("write routing seccomp program identity");
    close(state);
    return 4;
  }
  if (close_foreign_descriptors(state) != 0) {
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
    perror("install routing child seccomp filter");
    close(state);
    return 4;
  }

  char observations[256];
  int observations_size = snprintf(
      observations, sizeof(observations),
      "architecture=%s\ninstruction_count=%zu\nno_new_privs=true\n"
      "socket_policy=inet-stream-only\n",
      CONTROL_ARCH_NAME,
      sizeof(filter_instructions) / sizeof(filter_instructions[0]));
  if (observations_size <= 0 ||
      (size_t)observations_size >= sizeof(observations) ||
      write_new_at(state, "boundary-observations.txt", observations,
                   (size_t)observations_size) != 0) {
    perror("write routing boundary observations");
    close(state);
    return 4;
  }
  if (close(state) != 0) {
    perror("close routing boundary state");
    return 4;
  }
  if (setgroups(0, NULL) != 0 || setgid(65534) != 0 || setuid(65534) != 0) {
    perror("drop routing child identity");
    return 4;
  }
  execvp(argv[3], &argv[3]);
  perror("exec routing child");
  return errno == ENOENT ? 127 : 126;
}

#else

int main(void) {
  fprintf(stderr, "routing child control requires native Linux\n");
  return 3;
}

#endif
