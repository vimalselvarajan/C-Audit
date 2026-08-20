/* Fixture for the partial-closure case.
 *
 * take_slot is readable on its own; the struct layout and the constant that
 * sizes it are not in this file. That split is the point: a run where the
 * header becomes unreadable must come back saying the closure is incomplete,
 * not come back with a function and a confident silence about its type.
 */

#include "types.h"

int take_slot(struct slot_table *table, int value)
{
    if (table->used >= SLOT_COUNT) {
        return -1;
    }
    table->slots[table->used] = value;
    table->used = table->used + 1;
    return table->used;
}
