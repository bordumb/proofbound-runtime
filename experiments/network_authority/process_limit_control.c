#define _GNU_SOURCE

// Experiment-only process limit installed after the child identity is dropped.

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__

#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3 || strcmp(argv[1], "--") != 0 || argv[2] == NULL) {
    fprintf(stderr, "usage: process-limit-control -- <command> [args...]\n");
    return 2;
  }
  if (geteuid() == 0 || getuid() != getgid()) {
    fprintf(stderr, "process limit requires an equal dropped identity\n");
    return 3;
  }
  struct rlimit limit = {.rlim_cur = 1, .rlim_max = 1};
  if (setrlimit(RLIMIT_NPROC, &limit) != 0) {
    perror("set process limit");
    return 4;
  }
  execvp(argv[2], &argv[2]);
  perror("exec process-limited child");
  return errno == ENOENT ? 127 : 126;
}

#else

int main(void) {
  fprintf(stderr, "process limit control requires native Linux\n");
  return 3;
}

#endif
