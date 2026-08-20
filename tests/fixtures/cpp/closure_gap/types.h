/* The half of the closure that lives somewhere else. Removing this header
 * after indexing leaves the index still naming a region in it, which is the
 * partial-closure case AC-09-2 says must never pass silently.
 */
#define SLOT_COUNT 8

struct slot_table {
    int used;
    int slots[SLOT_COUNT];
};
