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
        s->privileges = 1;
        puts("Session allocated (privileges = 1). Running safe cleanup...");
        safe_session_cleanup(&s);
        puts("Safe cleanup complete (session pointer cleared to NULL).");
    }
    return 0;
}
