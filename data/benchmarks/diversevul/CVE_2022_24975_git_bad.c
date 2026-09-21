/* DiverseVul Real-World Benchmark Case
 * Target: libgit2 - CVE-2022-24975
 * Vulnerability: Use-After-Free (CWE-416)
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *ptr;
    size_t size;
} git_buf;

int git_buf_dispose_bad(git_buf *buf) {
    if (buf && buf->ptr) {
        free(buf->ptr);
        
        // FLAW: buf->ptr dereferenced and returned after free
        return (int)buf->ptr[0];
    }
    return 0;
}

int main() {
    git_buf b;
    b.ptr = (char *)malloc(16);
    b.size = 16;
    git_buf_dispose_bad(&b);
    return 0;
}
