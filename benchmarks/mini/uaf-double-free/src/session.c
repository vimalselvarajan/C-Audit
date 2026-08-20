/* CWE-416: use after free.
 *
 * close_session releases the buffer but leaves the pointer set, and
 * touch_session then reads through it. The freed pointer is never nulled, so
 * ownership is ambiguous at every call site.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {
    char *buffer;
    size_t length;
};

void close_session(struct session *s)
{
    free(s->buffer);
    s->length = 0;
}

size_t touch_session(struct session *s)
{
    return strlen(s->buffer); /* use after free: buffer was released above */
}

int main(void)
{
    struct session s;

    s.buffer = malloc(32);
    if (s.buffer == NULL) {
        return 1;
    }
    memcpy(s.buffer, "hello", 6);
    s.length = 5;

    close_session(&s);
    printf("%zu\n", touch_session(&s));
    return 0;
}
