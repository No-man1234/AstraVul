#include <stdio.h>
#include <string.h>

void process_user_packet(const char *network_input) {
    char internal_buffer[32];
    
    // VULNERABLE: Direct unbounded copy into fixed-size stack buffer
    strcpy(internal_buffer, network_input);
    printf("Processed: %s\n", internal_buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_user_packet(argv[1]);
    }
    return 0;
}
