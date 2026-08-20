#ifndef MINI_POLICY_H
#define MINI_POLICY_H

/* Defined in policy.c. Returns 0 when the header is acceptable. */
int policy_check_header(const char *header);

int load_record(const char *path);

#endif /* MINI_POLICY_H */
