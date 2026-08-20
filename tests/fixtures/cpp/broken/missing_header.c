/* Fixture for T-06-10: generated_config.h is produced by a build step that
 * never ran, so this unit cannot be parsed and must not be guessed at.
 */
#include "generated_config.h"

int configured_limit(void)
{
    return GENERATED_LIMIT;
}
