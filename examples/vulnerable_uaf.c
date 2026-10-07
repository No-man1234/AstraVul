#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char username[24];
    int privileges;
} Session;

void handle_session_cleanup(Session *sess) {
    free(sess);
    
    // VULNERABLE: Dereferencing sess after deallocation (CWE-416)
    sess->privileges = 0;
}

int main() {
    Session *s = (Session *)malloc(sizeof(Session));
    if (s) {
        s->privileges = 1;
        puts("Session allocated (privileges = 1). Running vulnerable cleanup...");
        handle_session_cleanup(s);
        puts("Vulnerable cleanup complete (dereferenced freed session pointer).");
    }
    return 0;
}
