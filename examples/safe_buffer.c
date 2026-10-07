#include <stdio.h>
#include <string.h>

void safe_process_user_packet(const char *network_input) {
    char internal_buffer[32];
    
    // SAFE: Explicit bounds check verifying length is strictly bounded by sizeof(internal_buffer)
    if (strlen(network_input) < sizeof(internal_buffer)) {
        strcpy(internal_buffer, network_input);
        printf("Safely Processed: %s\n", internal_buffer);
    } else {
        fprintf(stderr, "Input length exceeds buffer limit!\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_process_user_packet(argv[1]);
    } else {
        safe_process_user_packet("Valid_Packet_Payload");
        safe_process_user_packet("012345678901234567890123456789012345");
    }
    return 0;
}
