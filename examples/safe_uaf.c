#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char username[24];
    int privileges;
} Session;

void safe_session_cleanup(Session **sess_ptr) {
    if (sess_ptr && *sess_ptr) {
        free(*sess_ptr);
        // SAFE: Pointer immediately cleared to NULL, preventing dangling references
        *sess_ptr = NULL;
    }
}

int main() {
    Session *s = (Session *)malloc(sizeof(Session));
    if (s) {
        safe_session_cleanup(&s);
    }
    return 0;
}
