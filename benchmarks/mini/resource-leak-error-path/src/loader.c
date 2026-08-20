/* CWE-772: missing release of a resource on an error path.
 *
 * load_record opens the file, then returns early when the policy check
 * rejects the header — without closing it. The success path closes normally,
 * so the leak only exists on the branch whose reachability depends on
 * policy_check_header, which lives in another translation unit.
 */
#include <stdio.h>
#include <string.h>

#include "policy.h"

int load_record(const char *path)
{
    char header[8];
    FILE *fp = fopen(path, "rb");

    if (fp == NULL) {
        return -1;
    }
    memset(header, 0, sizeof(header));
    if (fread(header, 1, sizeof(header) - 1, fp) == 0) {
        fclose(fp);
        return -1;
    }
    if (policy_check_header(header) != 0) {
        return -2; /* leak: fp is never closed on this path */
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 1;
    }
    return load_record(argv[1]) == 0 ? 0 : 1;
}
