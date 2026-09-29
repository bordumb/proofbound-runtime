#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/vm_sockets.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/un.h>
#endif

static int connect_loopback(int family, unsigned short port) {
    int descriptor = socket(family, SOCK_STREAM, 0);
    if (descriptor < 0) return -1;
    int result;
    if (family == AF_INET) {
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
        result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    } else {
        struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
            .sin6_addr = IN6ADDR_LOOPBACK_INIT,
        };
        result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    }
    if (result < 0) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int proxy_request(const char *request, const char *status, int tunnel) {
    int descriptor = connect_loopback(AF_INET, 3128);
    if (descriptor < 0) return 10;
    size_t length = strlen(request);
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(descriptor, request + sent, length - sent, MSG_NOSIGNAL);
        if (count <= 0) {
            if (strncmp(status, "HTTP/1.1 400 ", 13) == 0 &&
                (errno == EPIPE || errno == ECONNRESET)) break;
            close(descriptor);
            return 11;
        }
        sent += (size_t)count;
    }
    char reply[256] = {0};
    size_t used = 0;
    while (used < sizeof(reply) - 1) {
        ssize_t received = recv(descriptor, reply + used, sizeof(reply) - 1 - used, 0);
        if (received <= 0) return 12;
        used += (size_t)received;
        if (strstr(reply, "\r\n\r\n") != NULL) break;
    }
    if (strncmp(reply, status, strlen(status)) != 0) return 13;
    if (tunnel) {
        static const char message[] = "egress-ping";
        if (send(descriptor, message, sizeof(message) - 1, MSG_NOSIGNAL)
            != (ssize_t)sizeof(message) - 1) return 14;
        char echoed[sizeof(message)] = {0};
        if (recv(descriptor, echoed, sizeof(message) - 1, MSG_WAITALL)
            != (ssize_t)sizeof(message) - 1) return 15;
        if (memcmp(echoed, message, sizeof(message) - 1) != 0) return 16;
    }
    close(descriptor);
    return 0;
}

static int open_proxy_tunnel(const char *request) {
    int descriptor = connect_loopback(AF_INET, 3128);
    if (descriptor < 0) return -1;
    struct timeval timeout = {.tv_sec = 3};
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    size_t length = strlen(request);
    if (send(descriptor, request, length, MSG_NOSIGNAL) != (ssize_t)length)
        return -1;
    char reply[256] = {0};
    size_t used = 0;
    while (used < sizeof(reply) - 1 && strstr(reply, "\r\n\r\n") == NULL) {
        ssize_t count = recv(descriptor, reply + used, sizeof(reply) - 1 - used, 0);
        if (count <= 0) return -1;
        used += (size_t)count;
    }
    if (strncmp(reply, "HTTP/1.1 200 ", 13) != 0) return -1;
    return descriptor;
}

static void tls_u16(unsigned char *buffer, size_t *used, size_t value) {
    buffer[(*used)++] = (unsigned char)(value >> 8);
    buffer[(*used)++] = (unsigned char)value;
}

static int proxy_sni_case(const char *name) {
    int descriptor = connect_loopback(AF_INET, 3128);
    if (descriptor < 0) return 41;
    struct timeval timeout = {.tv_sec = 3};
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return 42;
    const char request[] = "CONNECT secure.fixture.test:48126 HTTP/1.1\r\n\r\n";
    if (send(descriptor, request, sizeof(request) - 1, MSG_NOSIGNAL)
        != (ssize_t)sizeof(request) - 1) return 43;
    char reply[256] = {0};
    size_t received = 0;
    while (received < sizeof(reply) - 1 && strstr(reply, "\r\n\r\n") == NULL) {
        ssize_t count = recv(descriptor, reply + received, sizeof(reply) - 1 - received, 0);
        if (count <= 0) return 44;
        received += (size_t)count;
    }
    if (strncmp(reply, "HTTP/1.1 200 ", 13) != 0) return 45;

    unsigned char body[256] = {0};
    size_t body_len = 0;
    body[body_len++] = 3;
    body[body_len++] = 3;
    body_len += 32;
    body[body_len++] = 0;
    tls_u16(body, &body_len, 2);
    tls_u16(body, &body_len, 0x1301);
    body[body_len++] = 1;
    body[body_len++] = 0;
    const char *server_name = strcmp(name, "proxy-sni-mismatch") == 0
        ? "other.fixture.test" : "secure.fixture.test";
    size_t name_len = strlen(server_name);
    size_t extensions_len = strcmp(name, "proxy-sni-absent") == 0 ? 0 : 9 + name_len;
    if (strcmp(name, "proxy-sni-ech") == 0) extensions_len += 4;
    tls_u16(body, &body_len, extensions_len);
    if (extensions_len != 0) {
        tls_u16(body, &body_len, 0);
        tls_u16(body, &body_len, 5 + name_len);
        tls_u16(body, &body_len, 3 + name_len);
        body[body_len++] = 0;
        tls_u16(body, &body_len, name_len);
        memcpy(body + body_len, server_name, name_len);
        body_len += name_len;
    }
    if (strcmp(name, "proxy-sni-ech") == 0) {
        tls_u16(body, &body_len, 0xfe0d);
        tls_u16(body, &body_len, 0);
    }
    unsigned char handshake[300] = {1, 0, 0, 0};
    handshake[2] = (unsigned char)(body_len >> 8);
    handshake[3] = (unsigned char)body_len;
    memcpy(handshake + 4, body, body_len);
    size_t handshake_len = body_len + 4;
    unsigned char wire[400] = {0};
    size_t wire_len = 0;
    size_t first_len = strcmp(name, "proxy-sni-split") == 0 ? 7 : handshake_len;
    wire[wire_len++] = strcmp(name, "proxy-sni-malformed") == 0 ? 23 : 22;
    wire[wire_len++] = 3;
    wire[wire_len++] = 3;
    tls_u16(wire, &wire_len, strcmp(name, "proxy-sni-oversized") == 0 ? 16385 : first_len);
    if (strcmp(name, "proxy-sni-oversized") != 0) {
        memcpy(wire + wire_len, handshake, first_len);
        wire_len += first_len;
        if (first_len != handshake_len) {
            wire[wire_len++] = 22;
            wire[wire_len++] = 3;
            wire[wire_len++] = 3;
            tls_u16(wire, &wire_len, handshake_len - first_len);
            memcpy(wire + wire_len, handshake + first_len, handshake_len - first_len);
            wire_len += handshake_len - first_len;
        }
    }
    if (send(descriptor, wire, wire_len, MSG_NOSIGNAL) != (ssize_t)wire_len)
        return 46;
    unsigned char response[5];
    ssize_t count = recv(descriptor, response, sizeof(response), MSG_WAITALL);
    int receive_error = errno;
    close(descriptor);
    if (strcmp(name, "proxy-sni-matched") == 0 ||
        strcmp(name, "proxy-sni-split") == 0)
        return count == 5 && memcmp(response, wire, 5) == 0 ? 0 : 47;
    return count == 0 || (count < 0 && (receive_error == ECONNRESET || receive_error == EPIPE)) ? 0 : 48;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) return 2;
    if (strcmp(argv[1], "proxy-fault-hold") == 0) {
        sleep(3);
        return 0;
    }
    if (strcmp(argv[1], "proxy-literal") == 0) {
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-ipv6") == 0) {
        return proxy_request("CONNECT [::1]:48124 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-named") == 0) {
        return proxy_request("CONNECT echo.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-named-ipv6") == 0) {
        return proxy_request("CONNECT echo6.fixture.test:48127 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-http10") == 0) {
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.0\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-headers") == 0) {
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n"
                             "Host: unrelated.fixture.test\r\n"
                             "Proxy-Authorization: ignored\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-sequential") == 0 ||
        strcmp(argv[1], "proxy-reconnect") == 0) {
        for (int index = 0; index < 4; ++index) {
            int result = proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                                       "HTTP/1.1 200 ", 1);
            if (result != 0) return 49;
        }
        return 0;
    }
    if (strcmp(argv[1], "proxy-concurrent") == 0 ||
        strcmp(argv[1], "proxy-descendant") == 0) {
        int concurrent = strcmp(argv[1], "proxy-concurrent") == 0;
        int count = concurrent ? 8 : 1;
        pid_t children[8];
        int barrier[2];
        if (pipe(barrier) != 0) return 67;
        for (int index = 0; index < count; ++index) {
            children[index] = fork();
            if (children[index] < 0) return 50;
            if (children[index] == 0) {
                close(barrier[1]);
                char start;
                if (read(barrier[0], &start, 1) != 1) _exit(68);
                close(barrier[0]);
                if (concurrent) {
                    int descriptor = open_proxy_tunnel(
                        "CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n");
                    if (descriptor < 0) _exit(69);
                    usleep(500000);
                    char echo = 0;
                    if (send(descriptor, "p", 1, MSG_NOSIGNAL) != 1 ||
                        recv(descriptor, &echo, 1, MSG_WAITALL) != 1 || echo != 'p')
                        _exit(70);
                    close(descriptor);
                    _exit(0);
                }
                _exit(proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                                    "HTTP/1.1 200 ", 1));
            }
        }
        close(barrier[0]);
        for (int index = 0; index < count; ++index)
            if (write(barrier[1], "x", 1) != 1) return 71;
        close(barrier[1]);
        for (int index = 0; index < count; ++index) {
            int status = 0;
            if (waitpid(children[index], &status, 0) != children[index] ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 51;
        }
        return 0;
    }
    if (strcmp(argv[1], "proxy-plugin") == 0 && argc == 3) {
        char *const arguments[] = {argv[2], "proxy-literal", NULL};
        execv(argv[2], arguments);
        return 52;
    }
    if (strncmp(argv[1], "proxy-sni-", 10) == 0)
        return proxy_sni_case(argv[1]);
    if (strcmp(argv[1], "proxy-undeclared-port") == 0) {
        return proxy_request("CONNECT 127.0.0.1:48124 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 403 ", 0);
    }
    if (strcmp(argv[1], "proxy-undeclared-address") == 0) {
        return proxy_request("CONNECT 127.0.0.2:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 403 ", 0);
    }
    if (strcmp(argv[1], "proxy-undeclared-name") == 0) {
        return proxy_request("CONNECT unknown.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 403 ", 0);
    }
    if (strcmp(argv[1], "proxy-literal-of-name") == 0 && argc == 3) {
        char request[128];
        int length = snprintf(request, sizeof(request),
                              "CONNECT %s:48125 HTTP/1.1\r\n\r\n", argv[2]);
        if (length < 0 || (size_t)length >= sizeof(request)) return 53;
        return proxy_request(request, "HTTP/1.1 403 ", 0);
    }
    if (strcmp(argv[1], "proxy-noncanonical-ipv4") == 0) {
        return proxy_request("CONNECT 127.0.00.1:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 400 ", 0);
    }
    if (strcmp(argv[1], "proxy-private-scope-denied") == 0) {
        return proxy_request("CONNECT private-denied.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-loopback-rebinding-denied") == 0) {
        return proxy_request("CONNECT loopback-denied.fixture.test:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-cname-chain") == 0) {
        return proxy_request("CONNECT alias.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 200 ", 1);
    }
    if (strcmp(argv[1], "proxy-ttl-zero") == 0) {
        return proxy_request("CONNECT zero-ttl.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-dns-change") == 0) {
        int first = proxy_request("CONNECT flip.fixture.test:48125 HTTP/1.1\r\n\r\n",
                                  "HTTP/1.1 200 ", 1);
        if (first != 0) return 54;
        sleep(2);
        return proxy_request("CONNECT flip.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-dns-malformed") == 0) {
        return proxy_request("CONNECT malformed.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-dns-truncated") == 0) {
        return proxy_request("CONNECT truncated.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-dns-excess") == 0) {
        return proxy_request("CONNECT excess.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "proxy-dns-oversized") == 0) {
        return proxy_request("CONNECT echo.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 502 ", 0);
    }
    if (strncmp(argv[1], "proxy-scope-", 12) == 0 && argc == 3) {
        char request[128];
        int length = snprintf(request, sizeof(request),
                              "CONNECT %s:48125 HTTP/1.1\r\n\r\n", argv[2]);
        if (length < 0 || (size_t)length >= sizeof(request)) return 72;
        return proxy_request(request, "HTTP/1.1 502 ", 0);
    }
    if (strcmp(argv[1], "limit-connections") == 0) {
        int first = proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                                  "HTTP/1.1 200 ", 1);
        if (first != 0) return 55;
        sleep(1);
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 429 ", 0);
    }
    if (strcmp(argv[1], "limit-concurrent") == 0) {
        const char request[] = "CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n";
        int first = open_proxy_tunnel(request);
        if (first < 0) return 56;
        int second = proxy_request(request, "HTTP/1.1 429 ", 0);
        close(first);
        return second;
    }
    if (strcmp(argv[1], "limit-resolutions") == 0) {
        int first = proxy_request("CONNECT echo.fixture.test:48125 HTTP/1.1\r\n\r\n",
                                  "HTTP/1.1 200 ", 1);
        if (first != 0) return 60;
        return proxy_request("CONNECT alias.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 429 ", 0);
    }
    if (strcmp(argv[1], "limit-dns-messages") == 0) {
        return proxy_request("CONNECT alias.fixture.test:48125 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 429 ", 0);
    }
    if (strcmp(argv[1], "limit-client-bytes") == 0 ||
        strcmp(argv[1], "limit-remote-bytes") == 0) {
        int descriptor = open_proxy_tunnel("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n");
        if (descriptor < 0) return 61;
        if (send(descriptor, "AB", 2, MSG_NOSIGNAL) != 2) return 62;
        char echo[2];
        ssize_t received = recv(descriptor, echo, sizeof(echo), MSG_WAITALL);
        close(descriptor);
        if (received < 0 || received >= 2) return 63;
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 429 ", 0);
    }
    if (strcmp(argv[1], "proxy-idle-timeout") == 0) {
        int descriptor = open_proxy_tunnel("CONNECT 127.0.0.1:48123 HTTP/1.1\r\n\r\n");
        if (descriptor < 0) return 64;
        sleep(1);
        char byte;
        ssize_t received = recv(descriptor, &byte, 1, 0);
        close(descriptor);
        return received == 0 ? 0 : 65;
    }
    if (strcmp(argv[1], "inherited-host-socket") == 0) {
        for (int descriptor = 3; descriptor < 1024; ++descriptor) {
            struct sockaddr_storage peer = {0};
            socklen_t length = sizeof(peer);
            if (getpeername(descriptor, (struct sockaddr *)&peer, &length) != 0 ||
                peer.ss_family != AF_INET) continue;
            const struct sockaddr_in *address = (const struct sockaddr_in *)&peer;
            if (ntohs(address->sin_port) == 48123 &&
                address->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) return 66;
        }
        return 0;
    }
    if (strcmp(argv[1], "proxy-absolute-form") == 0) {
        return proxy_request("GET http://127.0.0.1:48123/ HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 405 ", 0);
    }
    if (strcmp(argv[1], "proxy-noncanonical-port") == 0) {
        return proxy_request("CONNECT 127.0.0.1:048123 HTTP/1.1\r\n\r\n",
                             "HTTP/1.1 400 ", 0);
    }
    if (strcmp(argv[1], "proxy-malformed-version") == 0) {
        return proxy_request("CONNECT 127.0.0.1:48123 HTTP/9.9\r\n\r\n",
                             "HTTP/1.1 400 ", 0);
    }
    if (strcmp(argv[1], "proxy-oversized-head") == 0) {
        char request[10000];
        size_t used = (size_t)snprintf(request, sizeof(request),
            "CONNECT 127.0.0.1:48123 HTTP/1.1\r\nX-Fill: ");
        memset(request + used, 'a', 9000);
        used += 9000;
        memcpy(request + used, "\r\n\r\n", 5);
        return proxy_request(request, "HTTP/1.1 400 ", 0);
    }
    if (strcmp(argv[1], "direct-ipv4") == 0 ||
        strcmp(argv[1], "direct-ipv6") == 0) {
        int family = strcmp(argv[1], "direct-ipv4") == 0 ? AF_INET : AF_INET6;
        int descriptor = connect_loopback(family, 48123);
        if (descriptor >= 0) {
            close(descriptor);
            return 20;
        }
        return errno == EACCES || errno == EPERM || errno == ENETUNREACH ||
                       errno == ECONNREFUSED ? 0 : 21;
    }
    if (strcmp(argv[1], "udp") == 0) {
        int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
        if (descriptor >= 0) {
            close(descriptor);
            return 22;
        }
        return errno == EPERM || errno == EACCES ? 0 : 23;
    }
    if (strcmp(argv[1], "direct-tcp-fast-open") == 0) {
        int descriptor = socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor < 0) return 32;
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(48123),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
        int result = sendto(descriptor, "x", 1, MSG_FASTOPEN,
                            (struct sockaddr *)&address, sizeof(address));
        int saved = errno;
        if (result < 0 && saved == EINPROGRESS) {
            struct pollfd event = {.fd = descriptor, .events = POLLOUT};
            if (poll(&event, 1, 1000) > 0) {
                socklen_t length = sizeof(saved);
                if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &saved, &length) != 0)
                    saved = errno;
            } else {
                saved = ETIMEDOUT;
            }
        }
        close(descriptor);
        return result < 0 && (saved == EACCES || saved == EPERM ||
               saved == ENETUNREACH || saved == ECONNREFUSED ||
               saved == EOPNOTSUPP || saved == ETIMEDOUT) ? 0 : 33;
    }
#ifdef __linux__
    if (strcmp(argv[1], "descendant-scm-rights") == 0) {
        int pair[2];
        int pipefd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 || pipe(pipefd) != 0)
            return 34;
        pid_t child = fork();
        if (child < 0) return 35;
        if (child == 0) {
            close(pair[0]);
            close(pipefd[0]);
            close(pipefd[1]);
            char payload = 0;
            char control[CMSG_SPACE(sizeof(int))] = {0};
            struct iovec iov = {.iov_base = &payload, .iov_len = 1};
            struct msghdr message = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = control, .msg_controllen = sizeof(control),
            };
            if (recvmsg(pair[1], &message, 0) != 1) _exit(36);
            struct cmsghdr *header = CMSG_FIRSTHDR(&message);
            if (!header || header->cmsg_level != SOL_SOCKET ||
                header->cmsg_type != SCM_RIGHTS ||
                header->cmsg_len != CMSG_LEN(sizeof(int))) _exit(37);
            int received;
            memcpy(&received, CMSG_DATA(header), sizeof(received));
            char byte = 0;
            if (read(received, &byte, 1) != 1 || byte != 'x') _exit(38);
            _exit(0);
        }
        close(pair[1]);
        char payload = 'x';
        char control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = {.iov_base = &payload, .iov_len = 1};
        struct msghdr message = {
            .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control),
        };
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &pipefd[0], sizeof(int));
        if (write(pipefd[1], "x", 1) != 1 || sendmsg(pair[0], &message, 0) != 1)
            return 39;
        close(pair[0]);
        close(pipefd[0]);
        close(pipefd[1]);
        int status = 0;
        return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0 ? 0 : 40;
    }
    struct socket_case {
        const char *name;
        int family;
        int type;
        int protocol;
    };
    static const struct socket_case socket_cases[] = {
        {"quic-udp", AF_INET, SOCK_DGRAM, IPPROTO_UDP},
        {"icmp-datagram", AF_INET, SOCK_DGRAM, IPPROTO_ICMP},
        {"raw", AF_INET, SOCK_RAW, IPPROTO_TCP},
        {"packet", AF_PACKET, SOCK_RAW, 0},
        {"netlink", AF_NETLINK, SOCK_RAW, 0},
        {"vsock", AF_VSOCK, SOCK_STREAM, 0},
        {"sctp", AF_INET, SOCK_STREAM, 132},
        {"mptcp", AF_INET, SOCK_STREAM, 262},
    };
    for (size_t index = 0; index < sizeof(socket_cases) / sizeof(socket_cases[0]); ++index) {
        if (strcmp(argv[1], socket_cases[index].name) == 0) {
            int descriptor = socket(socket_cases[index].family,
                                    socket_cases[index].type,
                                    socket_cases[index].protocol);
            if (descriptor >= 0) {
                close(descriptor);
                return 24;
            }
            return errno == EPERM || errno == EACCES ? 0 : 25;
        }
    }
    if (strcmp(argv[1], "host-unix-path") == 0 && argc == 3) {
        int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor < 0) return 26;
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(argv[2]) >= sizeof(address.sun_path)) return 27;
        strcpy(address.sun_path, argv[2]);
        int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
        int saved = errno;
        close(descriptor);
        return result < 0 && (saved == EACCES || saved == EPERM) ? 0 : 28;
    }
    if (strcmp(argv[1], "host-unix-abstract") == 0) {
        int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor < 0) return 29;
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        memcpy(address.sun_path + 1, "pbr-egress-host", 15);
        socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 16);
        int result = connect(descriptor, (struct sockaddr *)&address, length);
        int saved = errno;
        close(descriptor);
        return result < 0 && (saved == EACCES || saved == EPERM) ? 0 : 30;
    }
    struct syscall_case {
        const char *name;
        long number;
        long first;
        int expected;
    };
    static const struct syscall_case syscall_cases[] = {
        {"unshare", SYS_unshare, CLONE_NEWNET, EPERM},
        {"setns", SYS_setns, -1, EPERM},
        {"clone-namespace", SYS_clone, CLONE_NEWNET | SIGCHLD, EPERM},
        {"clone3", SYS_clone3, 0, ENOSYS},
        {"ptrace", SYS_ptrace, 0, EPERM},
        {"pidfd-getfd", SYS_pidfd_getfd, -1, EPERM},
        {"io-uring", SYS_io_uring_setup, 0, EPERM},
        {"kill-parent", SYS_kill, -1, EPERM},
        {"pidfd-signal", SYS_pidfd_send_signal, -1, EPERM},
    };
    for (size_t index = 0; index < sizeof(syscall_cases) / sizeof(syscall_cases[0]); ++index) {
        if (strcmp(argv[1], syscall_cases[index].name) == 0) {
            long result = syscall(syscall_cases[index].number, syscall_cases[index].first,
                                  0, 0, 0, 0, 0);
            return result == -1 && errno == syscall_cases[index].expected ? 0 : 31;
        }
    }
#endif
    return 3;
}
