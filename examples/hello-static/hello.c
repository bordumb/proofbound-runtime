#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

static int write_all(int descriptor, const char *bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(descriptor, bytes + written, length - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return -1;
        }
        written += (size_t)result;
    }
    return 0;
}

int main(void) {
    static const char output[] = "hello from a bounded Proofbound Runtime execution\n";
    int descriptor = open("output/hello.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        perror("open output/hello.txt");
        return 10;
    }
    if (write_all(descriptor, output, sizeof(output) - 1) != 0) {
        perror("write output/hello.txt");
        (void)close(descriptor);
        return 11;
    }
    if (close(descriptor) != 0) {
        perror("close output/hello.txt");
        return 12;
    }
    if (fputs("bounded hello completed\n", stdout) == EOF) {
        return 13;
    }
    return 0;
}
