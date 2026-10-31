// nameprobe <shm|reg|global|sysctl> <name>: tries one named operation and prints "ok", "EPERM"
// or "err=<n>". Plays an app whose learned rules name the shared memory it creates, the Mach
// services it registers (reg: per-pid, global: in the login session), and the sysctls it writes.
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

// How AppKit registers per-pid names (com.apple.axserver, com.apple.coredrag, …).
extern kern_return_t bootstrap_register2(mach_port_t bp, const char *name, mach_port_t sp, uint64_t flags);
#define BOOTSTRAP_PER_PID_SERVICE 1

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *what = argv[1], *name = argv[2];
    if (!strcmp(what, "shm")) {
        int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
        if (fd < 0) { printf(errno == EPERM ? "EPERM\n" : "err=%d\n", errno); return 1; }
        close(fd);
        shm_unlink(name);
        printf("ok\n");
        return 0;
    }
    if (!strcmp(what, "reg") || !strcmp(what, "global")) {
        mach_port_t port;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        uint64_t flags = strcmp(what, "reg") ? 0 : BOOTSTRAP_PER_PID_SERVICE;
        kern_return_t kr = bootstrap_register2(bootstrap_port, name, port, flags);
        printf(kr == KERN_SUCCESS ? "ok\n" : "err=%d\n", kr);
        return kr == KERN_SUCCESS ? 0 : 1;
    }
    if (!strcmp(what, "sysctl")) {
        // Write only. kern.tcsm_enable is writable without root; 0 turns TCSM off for this thread.
        int value = 0;
        if (sysctlbyname(name, NULL, NULL, &value, sizeof value) != 0) {
            printf(errno == EPERM ? "EPERM\n" : "err=%d\n", errno);
            return 1;
        }
        printf("ok\n");
        return 0;
    }
    return 2;
}
