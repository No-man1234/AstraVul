/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-78: OS Command Injection (Fixed / Benign)
 * File: CWE78_OS_Command_Injection__good.c
 */
#include <stdio.h>
#include <stdlib.h>

void CWE78_OS_Command_Injection__good() {
    // FIX: Hardcoded static command, no external tainted string
    const char *safe_command = "echo 'Status: OK'";
    system(safe_command);
}

int main() {
    CWE78_OS_Command_Injection__good();
    return 0;
}
