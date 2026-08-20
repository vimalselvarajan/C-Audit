#ifndef MINI_SIZES_H
#define MINI_SIZES_H

#include <stddef.h>

/* Defined in parse_length.c — the value is not visible to a single-TU
 * analyzer looking only at build_table.c. */
size_t parse_length(const char *text);

int *build_table(const char *text);

#endif /* MINI_SIZES_H */
