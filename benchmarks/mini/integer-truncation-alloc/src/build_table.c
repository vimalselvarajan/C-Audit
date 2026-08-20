/* CWE-197: numeric truncation feeding an allocation.
 *
 * The size arrives as a size_t from another translation unit, is truncated to
 * unsigned short for the allocation, and then the *untruncated* value drives
 * the fill loop. For an input of 65537 the allocation is one element and the
 * loop writes 65537, so the heap overflow only exists because of the
 * truncation.
 *
 * Deliberately split across translation units: an analyzer confined to one
 * TU sees an opaque call and cannot relate the two widths.
 */
#include <stdio.h>
#include <stdlib.h>

#include "sizes.h"

int *build_table(const char *text)
{
    size_t requested = parse_length(text);
    unsigned short count = (unsigned short)requested; /* truncation */
    int *table = malloc((size_t)count * sizeof(*table));

    if (table == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < requested; i++) {
        table[i] = (int)i;
    }
    return table;
}

int main(int argc, char **argv)
{
    int *table;

    if (argc < 2) {
        return 1;
    }
    table = build_table(argv[1]);
    if (table == NULL) {
        return 1;
    }
    printf("%d\n", table[0]);
    free(table);
    return 0;
}
