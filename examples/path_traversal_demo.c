#include <stdio.h>
#include <stdlib.h>

void read_user_file(const char *user_path) {
    // Insecure: no check for ".." traversal sequences
    FILE *fp = fopen(user_path, "r");
    if (fp) {
        char line[128];
        puts("Opened file via unsanitized path:");
        puts(user_path);
        if (fgets(line, sizeof(line), fp)) {
            fputs("First line: ", stdout);
            fputs(line, stdout);
        }
        fclose(fp);
    } else {
        puts("Attempted to open unsanitized path:");
        puts(user_path);
    }
}

int main(int argc, char **argv) {
    const char *target_path = (argc > 1) ? argv[1] : "../examples/path_traversal_demo.c";
    read_user_file(target_path);
    return 0;
}
