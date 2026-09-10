#define _GNU_SOURCE

// Port-only Landlock control for experiment 0001F mechanism A.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

// Network rules entered the Landlock UAPI after the initial filesystem-only
// header.  Use the frozen ABI-4 wire layouts directly so an older userspace
// header cannot prevent a capable kernel from running the experiment.
#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

struct routing_landlock_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
};

struct routing_landlock_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};

_Static_assert(sizeof(struct routing_landlock_ruleset_attr) == 16,
               "Landlock ruleset ABI layout changed");
_Static_assert(sizeof(struct routing_landlock_net_port_attr) == 16,
               "Landlock network-port ABI layout changed");

static const char *const usage =
    "usage: routing-landlock-control <allowed-port> "
    "<absolute-new-state-directory> -- <command> [args...]";

static int landlock_create_ruleset(const void *attr, size_t size,
                                   unsigned int flags) {
  return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset, int rule_type,
                             const void *attributes, unsigned int flags) {
  return (int)syscall(SYS_landlock_add_rule, ruleset, rule_type, attributes,
                      flags);
}

static int landlock_restrict_self(int ruleset, unsigned int flags) {
  return (int)syscall(SYS_landlock_restrict_self, ruleset, flags);
}

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

static int fail_errno(const char *phase) {
  int saved = errno;
  fprintf(stderr, "routing-landlock-control: %s: errno=%d\n", phase, saved);
  return 4;
}

int main(int argc, char **argv) {
  if (argc < 5 || strcmp(argv[3], "--") != 0 || argv[4] == NULL ||
      argv[2][0] != '/') {
    fprintf(stderr, "%s\n", usage);
    return 2;
  }
  char *end = NULL;
  errno = 0;
  unsigned long port_value = strtoul(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || port_value < 1 ||
      port_value > 65535) {
    fprintf(stderr, "routing Landlock port is invalid\n");
    return 2;
  }

  int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 4) {
    if (abi < 0) {
      return fail_errno("read-abi");
    }
    fprintf(stderr, "routing Landlock ABI %d lacks TCP network rules\n", abi);
    return 3;
  }
  const struct routing_landlock_ruleset_attr ruleset_attributes = {
      .handled_access_net =
          LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
  };
  int ruleset =
      landlock_create_ruleset(&ruleset_attributes, sizeof(ruleset_attributes), 0);
  if (ruleset < 0) {
    return fail_errno("create-ruleset");
  }
  const struct routing_landlock_net_port_attr port_rule = {
      .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
      .port = port_value,
  };
  if (landlock_add_rule(ruleset, LANDLOCK_RULE_NET_PORT, &port_rule, 0) != 0) {
    int result = fail_errno("add-connect-rule");
    close(ruleset);
    return result;
  }

  if (mkdir(argv[2], 0755) != 0) {
    int result = fail_errno("create-state");
    close(ruleset);
    return result;
  }
  int state = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (state < 0) {
    int result = fail_errno("open-state");
    close(ruleset);
    return result;
  }
  char configuration[256];
  int configuration_size = snprintf(
      configuration, sizeof(configuration),
      "allowed_access=connect-tcp\nallowed_port=%lu\n"
      "handled_access=bind-tcp,connect-tcp\nrule_count=1\n",
      port_value);
  char observations[128];
  int observations_size = snprintf(observations, sizeof(observations),
                                   "landlock_abi=%d\nno_new_privs=true\n", abi);
  if (configuration_size <= 0 ||
      (size_t)configuration_size >= sizeof(configuration) ||
      observations_size <= 0 ||
      (size_t)observations_size >= sizeof(observations) ||
      write_new_at(state, "ruleset-configuration.txt", configuration,
                   (size_t)configuration_size) != 0) {
    int result = fail_errno("write-configuration");
    close(state);
    close(ruleset);
    return result;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      landlock_restrict_self(ruleset, 0) != 0) {
    int result = fail_errno("install-boundary");
    close(state);
    close(ruleset);
    return result;
  }
  if (close(ruleset) != 0 ||
      write_new_at(state, "boundary-observations.txt", observations,
                   (size_t)observations_size) != 0 ||
      close(state) != 0) {
    return fail_errno("publish-observations");
  }
  execvp(argv[4], &argv[4]);
  return fail_errno("execute-command");
}

#else

int main(void) {
  fprintf(stderr, "routing Landlock control requires native Linux\n");
  return 3;
}

#endif
