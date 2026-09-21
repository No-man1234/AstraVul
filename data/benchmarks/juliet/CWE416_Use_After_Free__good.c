/* NIST Juliet Test Suite v1.3 Benchmark Case
 * CWE-416: Use After Free (Fixed / Benign)
 * File: CWE416_Use_After_Free__good.c
 */
#include <stdio.h>
#include <stdlib.h>

void CWE416_Use_After_Free__good() {
    int *data = (int *)malloc(10 * sizeof(int));
    if (data == NULL) return;
    
    data[0] = 100;
    printf("Accessing value prior to free: %d\n", data[0]);
    
    // FIX: Deallocate and immediately assign NULL, no subsequent use
    free(data);
    data = NULL;
}

int main() {
    CWE416_Use_After_Free__good();
    return 0;
}
