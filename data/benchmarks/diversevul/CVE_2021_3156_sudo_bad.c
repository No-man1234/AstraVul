/* DiverseVul Real-World Benchmark Case
 * Target: Sudo 1.8.31 - CVE-2021-3156 ("Baron Samedit")
 * Vulnerability: Heap Buffer Overflow (CWE-120 / CWE-122)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void set_cmnd_bad(char *from) {
    char user_args[32];
    
    // FLAW (CVE-2021-3156): Unchecked copy of unescaped backslash string into buffer
    strcpy(user_args, from);
    printf("Executing sudo command with args: %s\n", user_args);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        set_cmnd_bad(argv[1]);
    }
    return 0;
}
