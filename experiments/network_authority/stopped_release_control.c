#define _GNU_SOURCE

// Launcher-shaped stop, acknowledge, and release control for experiment 0001H.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static int write_new(const char *directory, const char *name, const char *data) {
  int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root < 0) return -1;
  int output = openat(root, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
  if (output < 0) { close(root); return -1; }
  size_t size = strlen(data);
  ssize_t written = write(output, data, size);
  int result = written == (ssize_t)size && fsync(output) == 0 && close(output) == 0 && fsync(root) == 0 ? 0 : -1;
  if (result != 0) close(output);
  close(root);
  return result;
}

int main(int argc, char **argv) {
  if (argc < 4 || strcmp(argv[2], "--") != 0 || argv[3] == NULL || argv[1][0] != '/') {
    fprintf(stderr, "usage: stopped-release-control <absolute-state-directory> -- <command> [args...]\n");
    return 2;
  }
  pid_t child = fork();
  if (child < 0) { perror("fork stopped child"); return 4; }
  if (child == 0) {
    if (raise(SIGSTOP) != 0) _exit(4);
    if (write_new(argv[1], "boundary-acknowledged.txt", "boundary-acknowledged\n") != 0) _exit(4);
    execvp(argv[3], &argv[3]);
    _exit(errno == ENOENT ? 127 : 126);
  }
  int status = 0;
  if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
    kill(child, SIGKILL); waitpid(child, NULL, 0);
    fprintf(stderr, "child did not stop before release\n");
    return 4;
  }
  if (write_new(argv[1], "child-stopped.txt", "child-stopped\n") != 0 || kill(child, SIGCONT) != 0) {
    kill(child, SIGKILL); waitpid(child, NULL, 0);
    return 4;
  }
  if (waitpid(child, &status, 0) != child) return 4;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 4;
}

#else
int main(void) { fprintf(stderr, "stopped release control requires native Linux\n"); return 3; }
#endif
