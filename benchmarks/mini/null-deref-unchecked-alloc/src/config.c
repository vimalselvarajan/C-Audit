/* CWE-476: NULL pointer dereference.
 *
 * load_config writes through the result of calloc without checking it. On
 * allocation failure the very first store dereferences NULL.
 */
#include <stdio.h>
#include <stdlib.h>

struct config {
    int verbosity;
    int retries;
};

struct config *load_config(int verbosity)
{
    struct config *c = calloc(1, sizeof(*c));

    c->verbosity = verbosity; /* NULL dereference when calloc fails */
    c->retries = 3;
    return c;
}

int main(void)
{
    struct config *c = load_config(2);

    printf("%d %d\n", c->verbosity, c->retries);
    free(c);
    return 0;
}
