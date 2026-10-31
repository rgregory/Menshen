// Plays a confined app asking LaunchServices to open something: an app bundle or a URL.
// usage: lsopenprobe <path-or-url>   prints "lsopen ok" or "lsopen status <OSStatus>"
// With no arguments it is the app being opened (copied into a dummy bundle): it writes
// launched-<pid>.txt next to its bundle with "ppid <n> sandboxed <0|1>", so a test can see that
// it ran, and whether the opener's sandbox came with it.
#include <CoreServices/CoreServices.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

static int launched(void) {
    char exe[4096], tmp[4096], path[4096];
    uint32_t size = sizeof exe;
    if (_NSGetExecutablePath(exe, &size) != 0) return 1;
    // <dir>/X.app/Contents/MacOS/X → <dir>
    for (int i = 0; i < 4; i++) { char *slash = strrchr(exe, '/'); if (!slash) return 1; *slash = 0; }
    snprintf(tmp, sizeof tmp, "%s/.launched-%d", exe, getpid());
    snprintf(path, sizeof path, "%s/launched-%d.txt", exe, getpid());
    FILE *f = fopen(tmp, "w");
    if (!f) return 1;
    fprintf(f, "ppid %d sandboxed %d\n", getppid(), sandbox_check(getpid(), NULL, 0) != 0);
    fclose(f);
    return rename(tmp, path);   // appears complete, so a test never reads it half written
}

int main(int argc, char **argv) {
    if (argc < 2 || !strncmp(argv[1], "-psn", 4)) return launched();
    CFStringRef text = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFURLRef url = argv[1][0] == '/'
        ? CFURLCreateWithFileSystemPath(NULL, text, kCFURLPOSIXPathStyle, true)
        : CFURLCreateWithString(NULL, text, NULL);
    OSStatus status = url ? LSOpenCFURLRef(url, NULL) : paramErr;
    if (status == noErr) printf("lsopen ok\n");
    else printf("lsopen status %d\n", (int)status);
    fflush(stdout);
    usleep(300000);   // reports from a process that exits at once are often dropped (finding 12)
    return 0;
}
