/* Fixture for T-06-06 and T-06-09: a call through a function-pointer table,
 * and a function containing inline assembly.
 */
typedef int (*handler_fn)(int);

static int accept_all(int value)
{
    return value;
}

static int reject_all(int value)
{
    (void)value;
    return -1;
}

static handler_fn handlers[2] = { accept_all, reject_all };

int dispatch(int which, int value)
{
    /* The target is chosen at run time: the index records the edge with an
     * unknown callee rather than pretending there is no call here.
     */
    return handlers[which & 1](value);
}

int direct(int value)
{
    return accept_all(value);
}

void barrier(void)
{
    __asm__ volatile ("" ::: "memory");
}
