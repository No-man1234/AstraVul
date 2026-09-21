#include <stdio.h>
#include <stdlib.h>

void read_user_file(const char *user_path) {
    // Insecure: no check for ".." traversal sequences
    FILE *fp = fopen(user_path, "r");
    if (fp) {
        fclose(fp);
    }
}
