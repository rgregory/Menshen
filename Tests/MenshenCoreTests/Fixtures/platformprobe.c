// Checks user-space-mediated access that learning can't observe (ADR-004).
// usage: platformprobe pref <domain | ->   exit 0 if CFPreferences returns any keys ("-" = global domain)
//        platformprobe mach <service>      exit 0 if bootstrap_look_up succeeds; prints its kr
//        platformprobe unix <path>         exit 0 if connecting to the Unix-domain socket succeeds
#include <CoreFoundation/CoreFoundation.h>
#include <bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[1], "pref") == 0) {
        CFStringRef domain = strcmp(argv[2], "-") == 0 ? kCFPreferencesAnyApplication
            : CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingUTF8);
        CFArrayRef keys = CFPreferencesCopyKeyList(domain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        long n = keys ? CFArrayGetCount(keys) : 0;
        printf("pref %s keys=%ld\n", argv[2], n);
        return n > 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "mach") == 0) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, argv[2], &port);
        printf("mach %s kr=%d\n", argv[2], kr);
        return kr == KERN_SUCCESS ? 0 : 1;
    }
    if (strcmp(argv[1], "unix") == 0) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, argv[2], sizeof addr.sun_path - 1);
        int ok = s >= 0 && connect(s, (struct sockaddr *)&addr, sizeof addr) == 0;
        printf("unix %s %s\n", argv[2], ok ? "ok" : "failed");
        if (s >= 0) close(s);
        return ok ? 0 : 1;
    }
    return 2;
}
