#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int landlock_fd_exec_preflight(const char *program, const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) {
        perror("landlock preflight executable open");
        return 69;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("landlock preflight no_new_privs");
        return 70;
    }
    struct landlock_ruleset_attr ruleset_attributes = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
    };
    int ruleset = syscall(SYS_landlock_create_ruleset, &ruleset_attributes,
                          sizeof(ruleset_attributes.handled_access_fs), 0);
    if (ruleset < 0) {
        perror("landlock preflight ruleset");
        return 71;
    }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
        .parent_fd = descriptor,
    };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0) {
        perror("landlock preflight rule");
        return 72;
    }
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
        perror("landlock preflight restriction");
        return 73;
    }
    close(ruleset);
    char *const child_argv[] = { (char *)program, "preflight", NULL };
    syscall(SYS_execveat, descriptor, "", child_argv, environ, AT_EMPTY_PATH);
    perror("landlock preflight execveat");
    return 74;
}

static int emit(int descriptor, const char *text) {
    size_t remaining = strlen(text);
    while (remaining > 0) {
        ssize_t written = write(descriptor, text, remaining);
        if (written < 0) {
            return 90;
        }
        text += written;
        remaining -= (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 64;
    }
    if (strcmp(argv[1], "preflight") == 0) {
        return 0;
    }
    if (strcmp(argv[1], "fd-exec-preflight") == 0 && argc == 3) {
        int descriptor = open(argv[2], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (descriptor < 0) {
            return 66;
        }
        char *const child_argv[] = { argv[0], "preflight", NULL };
        syscall(SYS_execveat, descriptor, "", child_argv, environ, AT_EMPTY_PATH);
        return errno == EACCES ? 67 : 68;
    }
    if (strcmp(argv[1], "landlock-fd-exec-preflight") == 0 && argc == 3) {
        return landlock_fd_exec_preflight(argv[0], argv[2]);
    }
    if (strcmp(argv[1], "positive") == 0) {
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || getuid() == 0 || getuid() != geteuid()) {
            return 20;
        }
        return emit(STDOUT_FILENO, "boundary-installed\n");
    }
    if (strcmp(argv[1], "read-allowed") == 0 && argc == 3) {
        int descriptor = open(argv[2], O_RDONLY);
        if (descriptor < 0) {
            return 21;
        }
        char byte = 0;
        int result = read(descriptor, &byte, 1) == 1 && byte == 'p' ? 0 : 22;
        close(descriptor);
        return result;
    }
    if (strcmp(argv[1], "read-denied") == 0 && argc == 3) {
        int descriptor = open(argv[2], O_RDONLY);
        if (descriptor >= 0) {
            close(descriptor);
            return 23;
        }
        return errno == EACCES ? emit(STDOUT_FILENO, "filesystem-denied\n") : 24;
    }
    if (strcmp(argv[1], "network-denied") == 0) {
        int descriptor = socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor >= 0) {
            close(descriptor);
            return 25;
        }
        return errno == EPERM ? emit(STDOUT_FILENO, "network-denied\n") : 26;
    }
    if (strcmp(argv[1], "fork-denied") == 0) {
        pid_t child = fork();
        if (child == 0) {
            _exit(0);
        }
        if (child > 0) {
            waitpid(child, NULL, 0);
            return 27;
        }
        return errno == EAGAIN ? emit(STDOUT_FILENO, "process-denied\n") : 28;
    }
    if (strcmp(argv[1], "fd-closed") == 0 && argc == 3) {
        int descriptor = atoi(argv[2]);
        errno = 0;
        return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF ? 0 : 29;
    }
    if (strcmp(argv[1], "output-over-limit") == 0) {
        char bytes[4096];
        memset(bytes, 'x', sizeof(bytes));
        return write(STDOUT_FILENO, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes) ? 0 : 30;
    }
    if (strcmp(argv[1], "timeout") == 0) {
        for (;;) {
            pause();
        }
    }
    if (strcmp(argv[1], "lingering-descendant") == 0) {
        pid_t child = fork();
        if (child < 0) {
            return 31;
        }
        if (child == 0) {
            for (;;) {
                pause();
            }
        }
        return 0;
    }
    return 65;
}
