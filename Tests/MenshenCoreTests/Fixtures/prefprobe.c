// Saves a preference through cfprefsd, the way every Mac app keeps its settings: the file is
// written by cfprefsd, not by the app, so file-write rules don't see it.
// usage: prefprobe <domain>; prints "sync ok" or "sync failed".
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    CFStringRef domain = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFPreferencesSetAppValue(CFSTR("probe"), CFSTR("written"), domain);
    Boolean ok = CFPreferencesAppSynchronize(domain);
    printf("sync %s\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
