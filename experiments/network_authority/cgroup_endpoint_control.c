#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define PBR_BPF_INSN(CODE, DST, SRC, OFF, IMM)                                \
  ((struct bpf_insn){.code = (CODE),                                           \
                     .dst_reg = (DST),                                         \
                     .src_reg = (SRC),                                         \
                     .off = (OFF),                                             \
                     .imm = (IMM)})
#define PBR_BPF_MOV64_IMM(DST, IMM)                                            \
  PBR_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define PBR_BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                   \
  PBR_BPF_INSN(BPF_LDX | BPF_MEM | SIZE, DST, SRC, OFF, 0)
#define PBR_BPF_JMP_IMM(OP, DST, IMM, OFF)                                     \
  PBR_BPF_INSN(BPF_JMP | OP | BPF_K, DST, 0, OFF, IMM)
#define PBR_BPF_EXIT() PBR_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

static const char *const usage =
    "usage: cgroup-endpoint-control <absolute-cgroup> <allowed-ipv4> "
    "<allowed-port> <absolute-new-state-directory> -- <command> [args...]";

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

static int bpf_call(enum bpf_cmd command, union bpf_attr *attributes) {
  return (int)syscall(__NR_bpf, command, attributes, sizeof(*attributes));
}

static int load_program(const struct bpf_insn *instructions, size_t count,
                        enum bpf_attach_type attach_type, char *log,
                        size_t log_size) {
  static const char license[] = "GPL";
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.prog_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
  attributes.expected_attach_type = attach_type;
  attributes.insn_cnt = (uint32_t)count;
  attributes.insns = (uint64_t)(uintptr_t)instructions;
  attributes.license = (uint64_t)(uintptr_t)license;
  attributes.log_buf = (uint64_t)(uintptr_t)log;
  attributes.log_size = (uint32_t)log_size;
  attributes.log_level = 1;
  return bpf_call(BPF_PROG_LOAD, &attributes);
}

static int attach_program(int cgroup, int program,
                          enum bpf_attach_type attach_type) {
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.target_fd = (uint32_t)cgroup;
  attributes.attach_bpf_fd = (uint32_t)program;
  attributes.attach_type = attach_type;
  return bpf_call(BPF_PROG_ATTACH, &attributes);
}

static int detach_program(int cgroup, int program,
                          enum bpf_attach_type attach_type) {
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.target_fd = (uint32_t)cgroup;
  attributes.attach_bpf_fd = (uint32_t)program;
  attributes.attach_type = attach_type;
  return bpf_call(BPF_PROG_DETACH, &attributes);
}

static int program_id(int program, uint32_t *identifier) {
  struct bpf_prog_info info;
  union bpf_attr attributes;
  memset(&info, 0, sizeof(info));
  memset(&attributes, 0, sizeof(attributes));
  attributes.info.bpf_fd = (uint32_t)program;
  attributes.info.info_len = (uint32_t)sizeof(info);
  attributes.info.info = (uint64_t)(uintptr_t)&info;
  if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0 || info.id == 0) {
    return -1;
  }
  *identifier = info.id;
  return 0;
}

static int enter_cgroup(int cgroup, pid_t process) {
  char text[32];
  int length = snprintf(text, sizeof(text), "%jd\n", (intmax_t)process);
  if (length <= 0 || (size_t)length >= sizeof(text)) {
    return -1;
  }
  int descriptor = openat(cgroup, "cgroup.procs",
                          O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return -1;
  }
  int result = write_all(descriptor, text, (size_t)length);
  if (close(descriptor) != 0) {
    result = -1;
  }
  return result;
}

static void run_child(int cgroup, char **command) {
  if (enter_cgroup(cgroup, getpid()) != 0) {
    _exit(125);
  }
  if (setgroups(0, NULL) != 0 || setgid(65534) != 0 || setuid(65534) != 0) {
    _exit(125);
  }
  execvp(command[0], command);
  _exit(errno == ENOENT ? 127 : 126);
}

static int child_exit_status(int status) {
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    int result = 128 + WTERMSIG(status);
    return result > 255 ? 255 : result;
  }
  return 125;
}

int main(int argc, char **argv) {
  if (argc < 7 || strcmp(argv[5], "--") != 0 || argv[6] == NULL) {
    fprintf(stderr, "%s\n", usage);
    return 2;
  }
  if (geteuid() != 0 || argv[1][0] != '/' || argv[4][0] != '/') {
    fprintf(stderr, "endpoint control requires root and absolute paths\n");
    return 3;
  }

  struct in_addr allowed_address;
  char *port_end = NULL;
  errno = 0;
  long port_value = strtol(argv[3], &port_end, 10);
  if (inet_pton(AF_INET, argv[2], &allowed_address) != 1 || errno != 0 ||
      port_end == argv[3] || *port_end != '\0' || port_value < 1 ||
      port_value > 65535) {
    fprintf(stderr, "invalid endpoint control tuple\n");
    return 2;
  }

  int cgroup = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (cgroup < 0) {
    perror("open cgroup");
    return 4;
  }
  if (mkdir(argv[4], 0755) != 0) {
    perror("create state directory");
    close(cgroup);
    return 4;
  }
  int state = open(argv[4], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (state < 0) {
    perror("open state directory");
    close(cgroup);
    return 4;
  }

  int32_t allowed_ip = (int32_t)allowed_address.s_addr;
  int32_t allowed_port = (int32_t)htons((uint16_t)port_value);
  const struct bpf_insn connect4[] = {
      PBR_BPF_MOV64_IMM(BPF_REG_0, 0),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip4)),
      PBR_BPF_JMP_IMM(BPF_JNE, BPF_REG_2, allowed_ip, 3),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                      (int16_t)offsetof(struct bpf_sock_addr, user_port)),
      PBR_BPF_JMP_IMM(BPF_JNE, BPF_REG_2, allowed_port, 1),
      PBR_BPF_MOV64_IMM(BPF_REG_0, 1),
      PBR_BPF_EXIT(),
  };
  const struct bpf_insn connect6[] = {
      PBR_BPF_MOV64_IMM(BPF_REG_0, 0),
      PBR_BPF_EXIT(),
  };
  if (write_new_at(state, "connect4-program.bin", connect4,
                   sizeof(connect4)) != 0 ||
      write_new_at(state, "connect6-program.bin", connect6,
                   sizeof(connect6)) != 0) {
    perror("write program identity");
    close(state);
    close(cgroup);
    return 4;
  }

  char connect4_log[65536];
  char connect6_log[65536];
  memset(connect4_log, 0, sizeof(connect4_log));
  memset(connect6_log, 0, sizeof(connect6_log));
  int connect4_fd = load_program(connect4, sizeof(connect4) / sizeof(connect4[0]),
                                 BPF_CGROUP_INET4_CONNECT, connect4_log,
                                 sizeof(connect4_log));
  int connect4_error = errno;
  if (write_new_at(state, "connect4-verifier.log", connect4_log,
                   strnlen(connect4_log, sizeof(connect4_log))) != 0) {
    perror("write connect4 verifier log");
    if (connect4_fd >= 0) {
      close(connect4_fd);
    }
    close(state);
    close(cgroup);
    return 4;
  }
  if (connect4_fd < 0) {
    errno = connect4_error;
    perror("load connect4 program");
    close(state);
    close(cgroup);
    return 4;
  }

  int connect6_fd = load_program(connect6, sizeof(connect6) / sizeof(connect6[0]),
                                 BPF_CGROUP_INET6_CONNECT, connect6_log,
                                 sizeof(connect6_log));
  int connect6_error = errno;
  if (write_new_at(state, "connect6-verifier.log", connect6_log,
                   strnlen(connect6_log, sizeof(connect6_log))) != 0) {
    perror("write connect6 verifier log");
    close(connect4_fd);
    if (connect6_fd >= 0) {
      close(connect6_fd);
    }
    close(state);
    close(cgroup);
    return 4;
  }
  if (connect6_fd < 0) {
    errno = connect6_error;
    perror("load connect6 program");
    close(connect4_fd);
    close(state);
    close(cgroup);
    return 4;
  }

  uint32_t connect4_id = 0;
  uint32_t connect6_id = 0;
  struct stat cgroup_status;
  if (program_id(connect4_fd, &connect4_id) != 0 ||
      program_id(connect6_fd, &connect6_id) != 0 ||
      fstat(cgroup, &cgroup_status) != 0) {
    perror("observe endpoint boundary identity");
    close(connect6_fd);
    close(connect4_fd);
    close(state);
    close(cgroup);
    return 4;
  }

  if (attach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT) != 0) {
    perror("attach connect4 program");
    close(connect6_fd);
    close(connect4_fd);
    close(state);
    close(cgroup);
    return 4;
  }
  if (attach_program(cgroup, connect6_fd, BPF_CGROUP_INET6_CONNECT) != 0) {
    perror("attach connect6 program");
    (void)detach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT);
    close(connect6_fd);
    close(connect4_fd);
    close(state);
    close(cgroup);
    return 4;
  }

  pid_t child = fork();
  if (child == 0) {
    run_child(cgroup, &argv[6]);
  }
  if (child < 0) {
    perror("fork endpoint child");
    (void)detach_program(cgroup, connect6_fd, BPF_CGROUP_INET6_CONNECT);
    (void)detach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT);
    close(connect6_fd);
    close(connect4_fd);
    close(state);
    close(cgroup);
    return 4;
  }

  int wait_status = 0;
  while (waitpid(child, &wait_status, 0) < 0) {
    if (errno != EINTR) {
      perror("wait endpoint child");
      wait_status = 125 << 8;
      break;
    }
  }
  int detach6 = detach_program(cgroup, connect6_fd, BPF_CGROUP_INET6_CONNECT);
  int detach4 = detach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT);

  char metadata[256];
  int metadata_size = snprintf(
      metadata, sizeof(metadata),
      "cgroup_id=%ju\nconnect4_program_id=%" PRIu32
      "\nconnect6_program_id=%" PRIu32 "\n",
      (uintmax_t)cgroup_status.st_ino, connect4_id, connect6_id);
  int metadata_result = -1;
  if (metadata_size > 0 && (size_t)metadata_size < sizeof(metadata)) {
    metadata_result = write_new_at(state, "boundary-observations.txt", metadata,
                                   (size_t)metadata_size);
  }

  close(connect6_fd);
  close(connect4_fd);
  close(state);
  close(cgroup);
  if (detach6 != 0 || detach4 != 0 || metadata_result != 0) {
    fprintf(stderr, "endpoint boundary cleanup or observation failed\n");
    return 4;
  }
  return child_exit_status(wait_status);
}

#else

int main(void) {
  fprintf(stderr, "cgroup endpoint control requires native Linux\n");
  return 3;
}

#endif
