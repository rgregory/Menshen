// Plays an exploited document viewer: tries to get out of the disposable sandbox.
// Each step prints "<name> ok" or "<name> errno <n>".
// usage: escapeprobe <document> <box-folder> <secret-in-home> <outside-file> <port> [repeat]
// With a repeat count, every step runs that many times, 100 ms apart, like a real app retrying.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
    if (argc < 6) { fprintf(stderr, "usage: escapeprobe <doc> <box> <secret> <outside> <port>\n"); return 2; }
    char path[4096];
    struct stat st;
    int rounds = argc > 6 ? atoi(argv[6]) : 1;

    for (int round = 0; round < rounds; round++) {
    if (round > 0) usleep(100000);
    readfile("read-document", argv[1]);
    snprintf(path, sizeof path, "%s/scratch.txt", argv[2]);
    writefile("write-box", path);
    readfile("read-home", argv[3]);
    report("stat-home", stat(argv[3], &st) == 0);
    writefile("write-outside", argv[4]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[5])) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    report("connect", s >= 0 && connect(s, (struct sockaddr *)&addr, sizeof addr) == 0);
    if (s >= 0) close(s);

    pid_t pid;
    char *child[] = { "/usr/bin/true", NULL };
    int rc = posix_spawn(&pid, child[0], NULL, NULL, child, environ);
    if (rc == 0) waitpid(pid, NULL, 0);
    errno = rc;
    report("exec", rc == 0);
    }
    fflush(stdout);
    usleep(300000);   // reports from a process that exits at once are often dropped (finding 12)
    return 0;
}
