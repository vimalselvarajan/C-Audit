/* The rejection path that makes the leak in load_record reachable. */
#include <string.h>

#include "policy.h"

int policy_check_header(const char *header)
{
    if (strncmp(header, "MINI", 4) != 0) {
        return -1;
    }
    return 0;
}
