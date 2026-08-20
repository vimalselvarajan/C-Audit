/* Fixture for T-09-03 and T-09-04.
 *
 * The bounds check that makes copy_into safe is not visible in copy_into. It
 * lives in CHECK_LEN, three lines above, and a reader shown only the function
 * body would conclude that `len` is unbounded and the copy overflows `buf`.
 * That is the whole argument for computing a dependency closure rather than
 * retrieving a window of lines: dropping this macro does not make the answer
 * less precise, it makes it the opposite answer.
 *
 * Keep the layout stable: the tests assert that the macro definition on line
 * 16 is retrieved and that copy_into spans lines 20-27.
 */

#define BUF_LEN 16

/* Expands to the guard. A retrieval that omits it hides the guard. */
#define CHECK_LEN(n) if ((n) >= 0 && (n) < BUF_LEN)

struct Frame { char buf[BUF_LEN]; int used; };

void copy_into(struct Frame *frame, const char *src, int len)
{
    int index;

    CHECK_LEN(len) {
        for (index = 0; index < len; index++) {
            frame->buf[index] = src[index];
        }
        frame->used = len;
    }
}
