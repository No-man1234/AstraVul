/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-121: Stack-Based Buffer Overflow
 * File: CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_bad.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SRC_STR "0123456789012345678901234567890123456789"

void CWE121_Stack_Based_Buffer_Overflow__bad() {
    char dataBuffer[16];
    char *data = dataBuffer;
    
    // FLAW: copy 40 bytes into 16-byte stack buffer without validation
    strcpy(data, SRC_STR);
    printf("Result: %s\n", data);
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__bad();
    return 0;
}
