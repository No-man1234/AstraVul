/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-78: OS Command Injection
 * File: CWE78_OS_Command_Injection__bad.c
 */
#include <stdio.h>
#include <stdlib.h>

void CWE78_OS_Command_Injection__bad(const char *user_input) {
    char command[128];
    // FLAW: Unsanitized user string directly executed via shell
    sprintf(command, "cat %s", user_input);
    system(command);
}

int main() {
    CWE78_OS_Command_Injection__bad("file.txt; rm -rf /");
    return 0;
}
