/* Fixture for T-06-03, half one. Same file name and same static function name
 * as statics/app/util.c: Clang spells a file-local USR with the *basename*, so
 * these two would collide without the repository-relative qualification.
 */
static int helper(int value)
{
    return value + 1;
}

int lib_entry(int value)
{
    return helper(value);
}
