// Test target for the integration test. Each step prints "<name> ok" or "<name> errno <n>".
// usage: probe <learn|enforce> <base> <fake-home> <port>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void report(const char *name, int ok) {
    if (ok) printf("%s ok\n", name);
    else printf("%s errno %d\n", name, errno);
}

static void readfile(const char *name, const char *path) {
    char buf[64];
    int fd = open(path, O_RDONLY);
    report(name, fd >= 0 && read(fd, buf, sizeof buf) >= 0);
    if (fd >= 0) close(fd);
}

static void writefile(const char *name, const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    report(name, fd >= 0 && write(fd, "x\n", 2) == 2);
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: probe <learn|enforce> <base> <home> <port>\n"); return 2; }
    const char *mode = argv[1], *base = argv[2], *home = argv[3];
    int port = atoi(argv[4]);
    char path[4096];

    snprintf(path, sizeof path, "%s/input.txt", base);
    readfile("read-input", path);
    snprintf(path, sizeof path, "%s/allowed/out.txt", base);
    writefile("write-allowed", path);
    snprintf(path, sizeof path, "%s/.ssh/id_test", home);
    readfile("read-ssh", path);
    snprintf(path, sizeof path, "%s/Library/LaunchAgents/evil.plist", home);
    writefile("write-launchagent", path);

    pid_t child;
    char *echo_argv[] = {"/bin/echo", "probe-echo", NULL};
    int rc = posix_spawn(&child, "/bin/echo", NULL, NULL, echo_argv, environ);
    int status = 0;
    if (rc == 0) waitpid(child, &status, 0); else errno = rc;
    report("exec-echo", rc == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int c = s >= 0 ? connect(s, (struct sockaddr *)&addr, sizeof addr) : -1;
    // ECONNREFUSED means the sandbox allowed the attempt; EPERM means it was denied.
    printf("connect-localhost %s\n", c == 0 ? "ok" : (errno == ECONNREFUSED ? "refused" : strerror(errno)));
    if (s >= 0) close(s);

    if (strcmp(mode, "enforce") == 0) {
        snprintf(path, sizeof path, "%s/other/new.txt", base);
        writefile("write-unlearned", path);
    }
    fflush(stdout);
    // Stay alive briefly: the kernel can drop deny reports from processes that exit immediately.
    usleep(400 * 1000);
    return 0;
}
