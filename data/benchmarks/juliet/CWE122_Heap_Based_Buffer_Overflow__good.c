/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-122: Heap-Based Buffer Overflow (Fixed / Benign)
 * File: CWE122_Heap_Based_Buffer_Overflow__good.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void CWE122_Heap_Based_Buffer_Overflow__good() {
    size_t alloc_size = 64;
    char *heapBuffer = (char *)malloc(alloc_size * sizeof(char));
    if (heapBuffer == NULL) return;
    
    char large_source[64];
    memset(large_source, 'A', 63);
    large_source[63] = '\0';
    
    // FIX: Ensure copy does not exceed allocated capacity
    if (strlen(large_source) < alloc_size) {
        strcpy(heapBuffer, large_source);
        printf("Heap content: %s\n", heapBuffer);
    }
    
    free(heapBuffer);
}

int main() {
    CWE122_Heap_Based_Buffer_Overflow__good();
    return 0;
}
