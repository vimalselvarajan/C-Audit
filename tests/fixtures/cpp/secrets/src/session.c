/* Fixture for T-10-09 and T-10-10.
 *
 * Two different privacy promises meet in this tree. `secrets/keys.h` is
 * excluded by configuration, and DEPLOY_TOKEN — which session_authorised
 * expands — is defined there, so part 09 will retrieve it and part 10 must
 * withhold it. The credential-shaped literals below are *not* excluded, so
 * they reach assembly and have to be scrubbed without touching the code
 * around them.
 *
 * No system header is included: the libclang wheel ships no resource
 * directory, so a unit that includes <string.h> does not parse here.
 */

#include "../secrets/keys.h"

struct session {
    char token[16];
    int  live;
};

/* A credential-shaped string at file scope. session_open touches it, so the
 * global-reference closure retrieves this declaration too. */
static const char *const service_password = "hunter2-not-a-real-password";

int session_length(const char *text);

void session_open(struct session *out, const char *supplied)
{
    /* A second credential shape, this time inside the primary unit. */
    const char *const fallback_key = "AKIAIOSFODNN7EXAMPLE";
    int index;

    if (supplied == 0) {
        supplied = service_password;
    }
    /* No bound: `supplied` may be longer than `token`. */
    for (index = 0; index < session_length(supplied); index++) {
        out->token[index] = supplied[index];
    }
    out->live = fallback_key[0] != 0;
}

int session_authorised(const struct session *session)
{
    return session->live && session->token[0] == DEPLOY_TOKEN[0];
}
