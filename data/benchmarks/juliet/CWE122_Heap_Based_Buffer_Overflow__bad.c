/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-122: Heap-Based Buffer Overflow
 * File: CWE122_Heap_Based_Buffer_Overflow__bad.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void CWE122_Heap_Based_Buffer_Overflow__bad() {
    char *heapBuffer = (char *)malloc(16 * sizeof(char));
    if (heapBuffer == NULL) return;
    
    char large_source[64];
    memset(large_source, 'A', 63);
    large_source[63] = '\0';
    
    // FLAW: Copying 64 bytes into 16 byte allocated heap chunk
    strcpy(heapBuffer, large_source);
    
    printf("Heap content: %s\n", heapBuffer);
    free(heapBuffer);
}

int main() {
    CWE122_Heap_Based_Buffer_Overflow__bad();
    return 0;
}
