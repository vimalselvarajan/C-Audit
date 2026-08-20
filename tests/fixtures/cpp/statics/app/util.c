/* Fixture for T-06-03, half two. See statics/lib/util.c. */
static int helper(int value)
{
    return value - 1;
}

int app_entry(int value)
{
    return helper(value);
}
