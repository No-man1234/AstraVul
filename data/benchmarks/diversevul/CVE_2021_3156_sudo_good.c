/* DiverseVul Real-World Benchmark Case
 * Target: Sudo 1.8.31p2 - CVE-2021-3156 (Remediated / Patched)
 * Vulnerability: Heap Buffer Overflow (CWE-120 / CWE-122)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void set_cmnd_good(char *from) {
    char user_args[32];
    
    // FIX (CVE-2021-3156): Strict length check preventing buffer overrun
    if (strlen(from) < sizeof(user_args)) {
        strncpy(user_args, from, sizeof(user_args) - 1);
        user_args[sizeof(user_args) - 1] = '\0';
        printf("Executing sudo command with args: %s\n", user_args);
    } else {
        fprintf(stderr, "sudo: argument list too long\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        set_cmnd_good(argv[1]);
    }
    return 0;
}
