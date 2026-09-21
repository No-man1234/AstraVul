#include <stdio.h>
#include <string.h>

void log_message(char *user_input) {
    // Unsafe: direct format string vulnerability
    printf(user_input);
}

int main() {
    char buf[128];
    fgets(buf, sizeof(buf), stdin);
    log_message(buf);
    return 0;
}
