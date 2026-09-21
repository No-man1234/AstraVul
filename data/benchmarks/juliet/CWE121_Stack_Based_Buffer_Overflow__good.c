/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-121: Stack-Based Buffer Overflow (Fixed / Benign)
 * File: CWE121_Stack_Based_Buffer_Overflow__good.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SRC_STR "0123456789012345678901234567890123456789"

void CWE121_Stack_Based_Buffer_Overflow__good() {
    char dataBuffer[16];
    char *data = dataBuffer;
    
    // FIX: Verify source string length is strictly bounded by destination capacity
    if (strlen(SRC_STR) < sizeof(dataBuffer)) {
        strcpy(data, SRC_STR);
        printf("Result: %s\n", data);
    } else {
        printf("Prevented overflow: input too large.\n");
    }
}

int main() {
    CWE121_Stack_Based_Buffer_Overflow__good();
    return 0;
}
