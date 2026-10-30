// Executable of the dummy app used by the swap/launcher tests.
// usage: Dummy <document>
//   reads <document>, writes <document>.out, and writes <dir>/unlearned-<pid>.txt
//   (a fresh name every run, so under enforce it is always an unlearned write).
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char buf[64], path[4096];
    int fd = open(argv[1], O_RDONLY);
    if (fd >= 0) { read(fd, buf, sizeof buf); close(fd); }

    snprintf(path, sizeof path, "%s.out", argv[1]);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) { write(fd, "ok\n", 3); close(fd); }

    char copy[4096];
    strncpy(copy, argv[1], sizeof copy - 1);
    copy[sizeof copy - 1] = 0;
    snprintf(path, sizeof path, "%s/unlearned-%d.txt", dirname(copy), getpid());
    fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);

    // Stay alive briefly: the kernel can drop deny reports from processes that exit immediately.
    usleep(400 * 1000);
    return 0;
}
