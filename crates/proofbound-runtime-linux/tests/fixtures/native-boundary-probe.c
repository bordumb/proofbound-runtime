#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int landlock_fd_exec_preflight(const char *program, const char *path,
                                      int grant_read, int expect_denial) {
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
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int ruleset = syscall(SYS_landlock_create_ruleset, &ruleset_attributes,
                          sizeof(ruleset_attributes.handled_access_fs), 0);
    if (ruleset < 0) {
        perror("landlock preflight ruleset");
        return 71;
    }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
                          (grant_read ? LANDLOCK_ACCESS_FS_READ_FILE : 0),
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
    char *const child_argv[] = {
        (char *)program,
        expect_denial ? "unexpected-exec" : "preflight",
        NULL,
    };
    syscall(SYS_execveat, descriptor, "", child_argv, environ, AT_EMPTY_PATH);
    if (expect_denial && errno == EACCES) {
        return 0;
    }
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

static int parse_size(const char *text, size_t *output) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0 ||
        value > (unsigned long long)SIZE_MAX) {
        return -1;
    }
    *output = (size_t)value;
    return 0;
}

static void touch_writable_pages(unsigned char *memory, size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        _exit(88);
    }
    for (size_t offset = 0; offset < size; offset += (size_t)page_size) {
        memory[offset] = (unsigned char)(offset / (size_t)page_size);
    }
    memory[size - 1] = 1;
}

static int allocate_anonymous(size_t size, int retain) {
    unsigned char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        return errno == ENOMEM ? 0 : 81;
    }
    touch_writable_pages(memory, size);
    if (retain) {
        for (;;) {
            pause();
        }
    }
    return munmap(memory, size) == 0 ? 0 : 82;
}

static int allocate_until_denied(size_t chunk_size) {
    for (;;) {
        unsigned char *memory = mmap(NULL, chunk_size, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) {
            return errno == ENOMEM
                       ? emit(STDOUT_FILENO, "allocation-denied\n")
                       : 83;
        }
        touch_writable_pages(memory, chunk_size);
    }
}

static int mapped_file(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return 84;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || status.st_size <= 0) {
        close(descriptor);
        return 85;
    }
    size_t size = (size_t)status.st_size;
    const unsigned char *memory = mmap(NULL, size, PROT_READ, MAP_PRIVATE,
                                       descriptor, 0);
    if (memory == MAP_FAILED) {
        close(descriptor);
        return 86;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return 87;
    }
    volatile unsigned char checksum = 0;
    for (size_t offset = 0; offset < size; offset += (size_t)page_size) {
        checksum ^= memory[offset];
    }
    checksum ^= memory[size - 1];
    int result = munmap((void *)memory, size) == 0 && close(descriptor) == 0
                     ? 0
                     : 89;
    return checksum == 0xff ? 91 : result;
}

static int read_page_cache(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return 92;
    }
    unsigned char buffer[65536];
    volatile unsigned char checksum = 0;
    for (;;) {
        ssize_t received = read(descriptor, buffer, sizeof(buffer));
        if (received < 0) {
            close(descriptor);
            return 93;
        }
        if (received == 0) {
            break;
        }
        for (ssize_t index = 0; index < received; index += 4096) {
            checksum ^= buffer[index];
        }
    }
    int result = close(descriptor) == 0 ? 0 : 94;
    return checksum == 0xff ? 95 : result;
}

static int allocate_shared(size_t size) {
    int descriptor = memfd_create("proofbound-memory", MFD_CLOEXEC);
    if (descriptor < 0 || ftruncate(descriptor, (off_t)size) != 0) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return 96;
    }
    unsigned char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, descriptor, 0);
    if (memory == MAP_FAILED) {
        close(descriptor);
        return 97;
    }
    touch_writable_pages(memory, size);
    int result = munmap(memory, size) == 0 && close(descriptor) == 0 ? 0 : 98;
    return result;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 64;
    }
    if (strcmp(argv[1], "preflight") == 0) {
        return 0;
    }
    if (strcmp(argv[1], "unexpected-exec") == 0) {
        return 75;
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
    if (strcmp(argv[1], "landlock-exec-only-denied") == 0 && argc == 3) {
        return landlock_fd_exec_preflight(argv[0], argv[2], 0, 1);
    }
    if (strcmp(argv[1], "landlock-fd-exec-preflight") == 0 && argc == 3) {
        return landlock_fd_exec_preflight(argv[0], argv[2], 1, 0);
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
    if (strcmp(argv[1], "memory-anonymous") == 0 && argc == 3) {
        size_t size = 0;
        return parse_size(argv[2], &size) == 0 && allocate_anonymous(size, 0) == 0
                   ? emit(STDOUT_FILENO, "anonymous-accounted\n")
                   : 100;
    }
    if (strcmp(argv[1], "memory-over-limit") == 0 && argc == 3) {
        size_t chunk_size = 0;
        return parse_size(argv[2], &chunk_size) == 0
                   ? allocate_until_denied(chunk_size)
                   : 101;
    }
    if (strcmp(argv[1], "memory-process-tree-over-limit") == 0 && argc == 4) {
        size_t chunk_size = 0;
        size_t children = 0;
        if (parse_size(argv[2], &chunk_size) != 0 ||
            parse_size(argv[3], &children) != 0) {
            return 102;
        }
        for (size_t index = 0; index < children; ++index) {
            pid_t child = fork();
            if (child < 0) {
                return 103;
            }
            if (child == 0) {
                _exit(allocate_until_denied(chunk_size));
            }
        }
        return allocate_until_denied(chunk_size);
    }
    if (strcmp(argv[1], "memory-mapped-file") == 0 && argc == 3) {
        return mapped_file(argv[2]) == 0
                   ? emit(STDOUT_FILENO, "mapped-file-accounted\n")
                   : 104;
    }
    if (strcmp(argv[1], "memory-page-cache") == 0 && argc == 3) {
        return read_page_cache(argv[2]) == 0
                   ? emit(STDOUT_FILENO, "page-cache-accounted\n")
                   : 105;
    }
    if (strcmp(argv[1], "memory-shared") == 0 && argc == 3) {
        size_t size = 0;
        return parse_size(argv[2], &size) == 0 && allocate_shared(size) == 0
                   ? emit(STDOUT_FILENO, "shared-memory-accounted\n")
                   : 106;
    }
    if (strcmp(argv[1], "memory-pressure-timeout") == 0 && argc == 3) {
        size_t size = 0;
        if (parse_size(argv[2], &size) != 0 || allocate_anonymous(size, 0) != 0) {
            return 107;
        }
        for (;;) {
            pause();
        }
    }
    return 65;
}
