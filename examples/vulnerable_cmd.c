#include <stdio.h>
#include <stdlib.h>

void run_diagnostics(const char *hostname) {
    char cmd[128];
    
    // VULNERABLE: Direct command string formatting into system shell (CWE-78)
    sprintf(cmd, "ping -c 1 %s", hostname);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        run_diagnostics(argv[1]);
    }
    return 0;
}
