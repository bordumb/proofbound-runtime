#define _GNU_SOURCE

// Dual-stack cgroup-BPF endpoint control for experiment 0001F.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
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
#define PBR_BPF_MOV64_REG(DST, SRC)                                            \
  PBR_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define PBR_BPF_MOV64_IMM(DST, IMM)                                            \
  PBR_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define PBR_BPF_ADD64_IMM(DST, IMM)                                            \
  PBR_BPF_INSN(BPF_ALU64 | BPF_ADD | BPF_K, DST, 0, 0, IMM)
#define PBR_BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                   \
  PBR_BPF_INSN(BPF_LDX | BPF_MEM | SIZE, DST, SRC, OFF, 0)
#define PBR_BPF_STX_MEM(SIZE, DST, SRC, OFF)                                   \
  PBR_BPF_INSN(BPF_STX | BPF_MEM | SIZE, DST, SRC, OFF, 0)
#define PBR_BPF_JMP_IMM(OP, DST, IMM, OFF)                                     \
  PBR_BPF_INSN(BPF_JMP | OP | BPF_K, DST, 0, OFF, IMM)
#define PBR_BPF_CALL(HELPER)                                                   \
  PBR_BPF_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER)
#define PBR_BPF_EXIT() PBR_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define PBR_BPF_LD_MAP_FD(DST, FD)                                             \
  PBR_BPF_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, FD),     \
      PBR_BPF_INSN(0, 0, 0, 0, 0)

static const char *const usage =
    "usage: routing-endpoint-control <absolute-cgroup> <allowed-ipv4> "
    "<allowed-ipv6> <allowed-port> <absolute-new-state-directory> -- "
    "<command> [args...]";

struct endpoint4_key {
  uint32_t address;
  uint32_t port;
};

struct endpoint6_key {
  uint32_t address[4];
  uint32_t port;
};

_Static_assert(sizeof(struct endpoint4_key) == 8,
               "IPv4 endpoint key must have no padding");
_Static_assert(sizeof(struct endpoint6_key) == 20,
               "IPv6 endpoint key must have no padding");

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

static int create_endpoint_map(uint32_t key_size) {
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.map_type = BPF_MAP_TYPE_HASH;
  attributes.key_size = key_size;
  attributes.value_size = 1;
  attributes.max_entries = 1;
  return bpf_call(BPF_MAP_CREATE, &attributes);
}

static int update_endpoint_map(int map, const void *key,
                               const uint8_t *value) {
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.map_fd = (uint32_t)map;
  attributes.key = (uint64_t)(uintptr_t)key;
  attributes.value = (uint64_t)(uintptr_t)value;
  attributes.flags = BPF_NOEXIST;
  return bpf_call(BPF_MAP_UPDATE_ELEM, &attributes);
}

static int lookup_endpoint_map(int map, const void *key, uint8_t *value) {
  union bpf_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.map_fd = (uint32_t)map;
  attributes.key = (uint64_t)(uintptr_t)key;
  attributes.value = (uint64_t)(uintptr_t)value;
  return bpf_call(BPF_MAP_LOOKUP_ELEM, &attributes);
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

static int map_id(int map, uint32_t expected_key_size, uint32_t *identifier) {
  struct bpf_map_info info;
  union bpf_attr attributes;
  memset(&info, 0, sizeof(info));
  memset(&attributes, 0, sizeof(attributes));
  attributes.info.bpf_fd = (uint32_t)map;
  attributes.info.info_len = (uint32_t)sizeof(info);
  attributes.info.info = (uint64_t)(uintptr_t)&info;
  if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0 || info.id == 0 ||
      info.type != BPF_MAP_TYPE_HASH || info.max_entries != 1 ||
      info.key_size != expected_key_size || info.value_size != 1) {
    return -1;
  }
  *identifier = info.id;
  return 0;
}

static int patch_map_fd(struct bpf_insn *instructions, size_t count, int map) {
  size_t matches = 0;
  for (size_t index = 0; index < count; ++index) {
    if (instructions[index].code == (BPF_LD | BPF_DW | BPF_IMM) &&
        instructions[index].src_reg == BPF_PSEUDO_MAP_FD &&
        instructions[index].imm == 0) {
      instructions[index].imm = map;
      ++matches;
    }
  }
  return matches == 1 ? 0 : -1;
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
  if (argc < 8 || strcmp(argv[6], "--") != 0 || argv[7] == NULL) {
    fprintf(stderr, "%s\n", usage);
    return 2;
  }
  if (geteuid() != 0 || argv[1][0] != '/' || argv[5][0] != '/') {
    fprintf(stderr, "endpoint control requires root and absolute paths\n");
    return 3;
  }

  struct endpoint4_key key4;
  struct endpoint6_key key6;
  memset(&key4, 0, sizeof(key4));
  memset(&key6, 0, sizeof(key6));
  char *port_end = NULL;
  errno = 0;
  long port_value = strtol(argv[4], &port_end, 10);
  struct in_addr address4;
  struct in6_addr address6;
  if (inet_pton(AF_INET, argv[2], &address4) != 1 ||
      inet_pton(AF_INET6, argv[3], &address6) != 1 || errno != 0 ||
      port_end == argv[4] || *port_end != '\0' || port_value < 1 ||
      port_value > 65535) {
    fprintf(stderr, "invalid dual-stack endpoint control tuples\n");
    return 2;
  }
  key4.address = address4.s_addr;
  key4.port = (uint32_t)htons((uint16_t)port_value);
  memcpy(key6.address, &address6, sizeof(key6.address));
  key6.port = (uint32_t)htons((uint16_t)port_value);

  int cgroup = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (cgroup < 0) {
    perror("open cgroup");
    return 4;
  }
  if (mkdir(argv[5], 0755) != 0) {
    perror("create endpoint state");
    close(cgroup);
    return 4;
  }
  int state = open(argv[5], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (state < 0) {
    perror("open endpoint state");
    close(cgroup);
    return 4;
  }

  int map4 = create_endpoint_map((uint32_t)sizeof(key4));
  int map6 = create_endpoint_map((uint32_t)sizeof(key6));
  uint8_t allowed = 1;
  uint8_t observed4 = 0;
  uint8_t observed6 = 0;
  if (map4 < 0 || map6 < 0 || update_endpoint_map(map4, &key4, &allowed) != 0 ||
      update_endpoint_map(map6, &key6, &allowed) != 0 ||
      lookup_endpoint_map(map4, &key4, &observed4) != 0 ||
      lookup_endpoint_map(map6, &key6, &observed6) != 0 || observed4 != allowed ||
      observed6 != allowed) {
    perror("create and verify endpoint maps");
    if (map6 >= 0) {
      close(map6);
    }
    if (map4 >= 0) {
      close(map4);
    }
    close(state);
    close(cgroup);
    return 4;
  }

  struct bpf_insn connect4[] = {
      PBR_BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
      PBR_BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
      PBR_BPF_ADD64_IMM(BPF_REG_2, -8),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip4)),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -8),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_port)),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -4),
      PBR_BPF_LD_MAP_FD(BPF_REG_1, 0),
      PBR_BPF_CALL(BPF_FUNC_map_lookup_elem),
      PBR_BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
      PBR_BPF_MOV64_IMM(BPF_REG_0, 1),
      PBR_BPF_EXIT(),
  };
  struct bpf_insn connect6[] = {
      PBR_BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
      PBR_BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
      PBR_BPF_ADD64_IMM(BPF_REG_2, -24),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip6[0])),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -24),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip6[1])),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -20),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip6[2])),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -16),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_ip6[3])),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -12),
      PBR_BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
                      (int16_t)offsetof(struct bpf_sock_addr, user_port)),
      PBR_BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, -8),
      PBR_BPF_LD_MAP_FD(BPF_REG_1, 0),
      PBR_BPF_CALL(BPF_FUNC_map_lookup_elem),
      PBR_BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
      PBR_BPF_MOV64_IMM(BPF_REG_0, 1),
      PBR_BPF_EXIT(),
  };
  size_t connect4_count = sizeof(connect4) / sizeof(connect4[0]);
  size_t connect6_count = sizeof(connect6) / sizeof(connect6[0]);
  if (patch_map_fd(connect4, connect4_count, map4) != 0 ||
      patch_map_fd(connect6, connect6_count, map6) != 0) {
    fprintf(stderr, "endpoint map reference patch is not exact\n");
    close(map6);
    close(map4);
    close(state);
    close(cgroup);
    return 4;
  }

  char connect4_log[65536];
  char connect6_log[65536];
  memset(connect4_log, 0, sizeof(connect4_log));
  memset(connect6_log, 0, sizeof(connect6_log));
  int connect4_fd = load_program(connect4, connect4_count,
                                 BPF_CGROUP_INET4_CONNECT, connect4_log,
                                 sizeof(connect4_log));
  int connect4_error = errno;
  int connect6_fd = load_program(connect6, connect6_count,
                                 BPF_CGROUP_INET6_CONNECT, connect6_log,
                                 sizeof(connect6_log));
  int connect6_error = errno;
  if (write_new_at(state, "connect4-program.bin", connect4, sizeof(connect4)) !=
          0 ||
      write_new_at(state, "connect6-program.bin", connect6, sizeof(connect6)) !=
          0 ||
      write_new_at(state, "connect4-map-key.bin", &key4, sizeof(key4)) != 0 ||
      write_new_at(state, "connect6-map-key.bin", &key6, sizeof(key6)) != 0 ||
      write_new_at(state, "map-value.bin", &allowed, sizeof(allowed)) != 0 ||
      write_new_at(state, "connect4-verifier.log", connect4_log,
                   strnlen(connect4_log, sizeof(connect4_log))) != 0 ||
      write_new_at(state, "connect6-verifier.log", connect6_log,
                   strnlen(connect6_log, sizeof(connect6_log))) != 0) {
    perror("write endpoint identities");
    if (connect6_fd >= 0) {
      close(connect6_fd);
    }
    if (connect4_fd >= 0) {
      close(connect4_fd);
    }
    close(map6);
    close(map4);
    close(state);
    close(cgroup);
    return 4;
  }
  if (connect4_fd < 0 || connect6_fd < 0) {
    errno = connect4_fd < 0 ? connect4_error : connect6_error;
    perror("load endpoint programs");
    if (connect6_fd >= 0) {
      close(connect6_fd);
    }
    if (connect4_fd >= 0) {
      close(connect4_fd);
    }
    close(map6);
    close(map4);
    close(state);
    close(cgroup);
    return 4;
  }

  uint32_t connect4_id = 0;
  uint32_t connect6_id = 0;
  uint32_t map4_id = 0;
  uint32_t map6_id = 0;
  struct stat cgroup_status;
  if (program_id(connect4_fd, &connect4_id) != 0 ||
      program_id(connect6_fd, &connect6_id) != 0 ||
      map_id(map4, (uint32_t)sizeof(key4), &map4_id) != 0 ||
      map_id(map6, (uint32_t)sizeof(key6), &map6_id) != 0 ||
      fstat(cgroup, &cgroup_status) != 0) {
    perror("observe endpoint identities");
    close(connect6_fd);
    close(connect4_fd);
    close(map6);
    close(map4);
    close(state);
    close(cgroup);
    return 4;
  }
  if (attach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT) != 0 ||
      attach_program(cgroup, connect6_fd, BPF_CGROUP_INET6_CONNECT) != 0) {
    perror("attach endpoint programs");
    (void)detach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT);
    close(connect6_fd);
    close(connect4_fd);
    close(map6);
    close(map4);
    close(state);
    close(cgroup);
    return 4;
  }

  pid_t child = fork();
  if (child == 0) {
    run_child(cgroup, &argv[7]);
  }
  int wait_status = 125 << 8;
  if (child < 0) {
    perror("fork endpoint child");
  } else {
    while (waitpid(child, &wait_status, 0) < 0) {
      if (errno != EINTR) {
        perror("wait endpoint child");
        wait_status = 125 << 8;
        break;
      }
    }
  }
  int detach6 = detach_program(cgroup, connect6_fd, BPF_CGROUP_INET6_CONNECT);
  int detach4 = detach_program(cgroup, connect4_fd, BPF_CGROUP_INET4_CONNECT);

  char observations[512];
  int observations_size = snprintf(
      observations, sizeof(observations),
      "cgroup_id=%ju\nconnect4_map_id=%" PRIu32
      "\nconnect4_program_id=%" PRIu32 "\nconnect6_map_id=%" PRIu32
      "\nconnect6_program_id=%" PRIu32
      "\nmap_entries=1\nmap_readback=true\n",
      (uintmax_t)cgroup_status.st_ino, map4_id, connect4_id, map6_id,
      connect6_id);
  int observations_result = -1;
  if (observations_size > 0 &&
      (size_t)observations_size < sizeof(observations)) {
    observations_result = write_new_at(state, "boundary-observations.txt",
                                       observations,
                                       (size_t)observations_size);
  }

  close(connect6_fd);
  close(connect4_fd);
  close(map6);
  close(map4);
  close(state);
  close(cgroup);
  if (child < 0 || detach6 != 0 || detach4 != 0 || observations_result != 0) {
    fprintf(stderr, "endpoint boundary cleanup or observation failed\n");
    return 4;
  }
  return child_exit_status(wait_status);
}

#else

int main(void) {
  fprintf(stderr, "routing endpoint control requires native Linux\n");
  return 3;
}

#endif
