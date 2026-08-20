/* CWE-787: out-of-bounds write.
 *
 * store_name copies an attacker-controlled string into a fixed stack buffer
 * without bounding the copy. Any input longer than 15 bytes writes past the
 * end of `slot`.
 */
#include <stdio.h>
#include <string.h>

struct record {
    char slot[16];
    int id;
};

void store_name(struct record *out, const char *name)
{
    strcpy(out->slot, name); /* out-of-bounds write when strlen(name) >= 16 */
    out->id = 1;
}

int main(int argc, char **argv)
{
    struct record r;

    if (argc < 2) {
        return 1;
    }
    store_name(&r, argv[1]);
    printf("%s %d\n", r.slot, r.id);
    return 0;
}
