/* Fixture for T-06-05 and T-06-15 … T-06-18.
 *
 * The comment on the line below mentions parse_header at file scope, outside
 * any function. A citation naming the symbol *there* is what v1 resolved as
 * OK and what the index-backed resolver rejects.
 */
/* parse_header validates a header and delegates to b_func. */

#include "b.h"

int parse_header(const char *header)
{
    if (header == 0) {
        return -1;
    }
    return b_func(header);
}

int never_called_fn(void)
{
    return 0;
}
