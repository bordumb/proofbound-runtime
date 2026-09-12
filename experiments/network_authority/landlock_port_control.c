#define _GNU_SOURCE

// Installs the port-only Landlock control for network experiment 0001.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                   size_t size, unsigned int flags) {
  return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd,
                             enum landlock_rule_type rule_type,
                             const void *rule_attr, unsigned int flags) {
  return (int)syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                      flags);
}

static int landlock_restrict_self(int ruleset_fd, unsigned int flags) {
  return (int)syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static int fail_errno(const char *phase) {
  int saved_errno = errno;
  fprintf(stderr, "landlock-port-control: %s: errno=%d\n", phase,
          saved_errno);
  return 4;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fputs("usage: landlock-port-control --print-abi | <command> [argument ...]\n",
          stderr);
    return 2;
  }

  int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (argc == 2 && strcmp(argv[1], "--print-abi") == 0) {
    if (abi < 0) {
      fprintf(stderr,
              "landlock-port-control: landlock ABI unavailable: errno=%d\n",
              errno);
      return 3;
    }
    printf("%d\n", abi);
    return 0;
  }
  if (abi < 4) {
    if (abi < 0) {
      fprintf(stderr,
              "landlock-port-control: landlock ABI unavailable: errno=%d\n",
              errno);
    } else {
      fprintf(stderr,
              "landlock-port-control: Landlock ABI %d lacks TCP network rules\n",
              abi);
    }
    return 3;
  }

  const struct landlock_ruleset_attr ruleset = {
      .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
  };
  int ruleset_fd = landlock_create_ruleset(&ruleset, sizeof(ruleset), 0);
  if (ruleset_fd < 0) {
    return fail_errno("create-ruleset");
  }

  const struct landlock_net_port_attr port = {
      .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
      .port = 443,
  };
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port, 0) < 0) {
    int status = fail_errno("add-port-rule");
    close(ruleset_fd);
    return status;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    int status = fail_errno("set-no-new-privileges");
    close(ruleset_fd);
    return status;
  }
  if (landlock_restrict_self(ruleset_fd, 0) < 0) {
    int status = fail_errno("restrict-self");
    close(ruleset_fd);
    return status;
  }
  if (close(ruleset_fd) < 0) {
    return fail_errno("close-ruleset");
  }

  execvp(argv[1], &argv[1]);
  return fail_errno("execute-command");
}

#else

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  fputs("landlock-port-control: Linux is required\n", stderr);
  return 3;
}

#endif
