/* DiverseVul Real-World Benchmark Case
 * Target: libgit2 - CVE-2022-24975 (Remediated / Patched)
 * Vulnerability: Use-After-Free (CWE-416)
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *ptr;
    size_t size;
} git_buf;

int git_buf_dispose_good(git_buf *buf) {
    if (buf && buf->ptr) {
        free(buf->ptr);
        // FIX: Clear pointer to NULL and do not dereference
        buf->ptr = NULL;
        buf->size = 0;
        return 0;
    }
    return -1;
}

int main() {
    git_buf b;
    b.ptr = (char *)malloc(16);
    b.size = 16;
    git_buf_dispose_good(&b);
    return 0;
}
