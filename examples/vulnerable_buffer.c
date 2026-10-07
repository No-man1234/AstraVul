#include <stdio.h>
#include <string.h>

void process_user_packet(const char *network_input) {
    char internal_buffer[32];
    
    // VULNERABLE: Direct unbounded copy into fixed-size stack buffer
    strcpy(internal_buffer, network_input);
    printf("Processed: %s\n", internal_buffer);
}

int main(int argc, char **argv) {
    const char *default_packet = "012345678901234567890123456789012345";
    const char *input = (argc > 1) ? argv[1] : default_packet;
    process_user_packet(input);
    return 0;
}
