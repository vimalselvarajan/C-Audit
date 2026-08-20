/* Fixture for T-09-06.
 *
 * A leak candidate whose decisive code is the error path: `goto cleanup`, the
 * label at the bottom, and the two release sites. buffer_release is defined in
 * this repository and is where the question "was it actually freed?" is
 * settled — a name that reads like a release is not a release.
 *
 * There is no <stdlib.h>: the libclang wheel ships no resource directory, so
 * the allocator is declared locally rather than included.
 */

typedef unsigned long size_t_local;

void *local_alloc(size_t_local bytes);
void local_free(void *block);

struct buffer {
    char *data;
    int   length;
};

void buffer_release(struct buffer *buffer)
{
    local_free(buffer->data);
    buffer->data = 0;
    buffer->length = 0;
}

int load_record(struct buffer *out, const char *source, int length)
{
    struct buffer scratch;
    int status;

    status = -1;
    scratch.data = local_alloc((size_t_local)length);
    scratch.length = length;
    if (scratch.data == 0) {
        return -1;
    }

    if (length <= 0) {
        goto cleanup;
    }

    out->data = scratch.data;
    out->length = scratch.length;
    status = 0;
    return status;

cleanup:
    local_free(scratch.data);
    buffer_release(&scratch);
    return status;
}
