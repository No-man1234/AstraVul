#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#define PING_FMT "ping -n 1 %s"
#else
#define PING_FMT "ping -c 1 %s"
#endif

void run_diagnostics(const char *hostname) {
    char cmd[128];
    
    // VULNERABLE: Direct command string formatting into system shell (CWE-78)
    sprintf(cmd, PING_FMT, hostname);
    system(cmd);
}

int main(int argc, char **argv) {
    const char *target = (argc > 1) ? argv[1] : "127.0.0.1 & echo [!] Command Injection Triggered";
    run_diagnostics(target);
    return 0;
}
