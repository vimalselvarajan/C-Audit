/* Supplies the attacker-controlled length that build_table truncates. */
#include <stdlib.h>

#include "sizes.h"

size_t parse_length(const char *text)
{
    return (size_t)strtoull(text, NULL, 10);
}
