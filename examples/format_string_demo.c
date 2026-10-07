#include <stdio.h>
#include <string.h>

void log_message(char *user_input) {
    // Unsafe: direct format string vulnerability
    printf(user_input);
}

int main(int argc, char **argv) {
    char default_input[] = "Format string demo payload: %x %x\n";
    char *input = (argc > 1) ? argv[1] : default_input;
    log_message(input);
    return 0;
}
