/* Parses cleanly, so the tests can show that one broken unit does not cost
 * the run the others (T-06-10, T-06-11).
 */
int healthy(void)
{
    return 1;
}
