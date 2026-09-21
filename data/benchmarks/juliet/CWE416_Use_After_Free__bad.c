/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-416: Use After Free
 * File: CWE416_Use_After_Free__bad.c
 */
#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__bad() {
    int *data = (int *)malloc(10 * sizeof(int));
    if (data == NULL) return;
    
    data[0] = 100;
    free(data);
    
    // FLAW: Dereference after free
    printf("Accessing freed value: %d\n", data[0]);
}

int main() {
    CWE416_Use_After_Free__bad();
    return 0;
}
