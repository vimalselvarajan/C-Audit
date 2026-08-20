/* CWE-134: externally-controlled format string.
 *
 * emit_log passes the caller's string as printf's format. A caller that
 * forwards user input gives the user control of the format, which is enough
 * to read the stack with %x or write with %n.
 */
#include <stdio.h>

void emit_log(const char *user_text)
{
    printf(user_text); /* format string is attacker-controlled */
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 1;
    }
    emit_log(argv[1]);
    return 0;
}
