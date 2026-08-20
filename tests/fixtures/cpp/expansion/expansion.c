/* Fixture for T-09-01, T-09-02, T-09-05, T-09-07 and T-09-18.
 *
 * long_walk is deliberately long. A candidate reported in the middle of it is
 * the case the plan names: retrieval has to come back with the whole function,
 * both boundaries exact, rather than a window of lines around the diagnostic.
 * The padding below is dull on purpose — the point is its length.
 *
 * It also carries, in one function, everything the dependency closure has to
 * find: a typedef, a struct layout, a macro constant, and two file-scope
 * variables. stage_one -> stage_two -> stage_three is a separate chain, for
 * the source-to-sink case where the analyzer's path crosses three functions.
 *
 * Nothing here includes a system header: the libclang wheel ships no resource
 * directory, so a fixture that included <stddef.h> would not parse.
 */

#define MAX_SLOTS 32

typedef unsigned int u32;

struct hdr {
    u32 magic;
    int count;
};

int g_slots;
static u32 g_flags;

static u32 helper_one(const struct hdr *head)
{
    return head->magic + (u32)head->count;
}

static int helper_two(int count)
{
    return count < 0 ? 0 : count;
}

u32 long_walk(struct hdr *head, const u32 *values, int count)
{
    u32 total;
    int index;

    total = head->magic;
    if (count > MAX_SLOTS) {
        count = MAX_SLOTS;
    }
    g_slots = count;

    for (index = 0; index < count; index++) {
        total += values[index];
    }
    if (total > 100u) {
        total -= 1u;
    }
    if (total > 200u) {
        total -= 2u;
    }
    if (total > 300u) {
        total -= 3u;
    }
    if (total > 400u) {
        total -= 4u;
    }
    if (total > 500u) {
        total -= 5u;
    }
    if (total > 600u) {
        total -= 6u;
    }
    if (total > 700u) {
        total -= 7u;
    }
    if (total > 800u) {
        total -= 8u;
    }
    if (total > 900u) {
        total -= 9u;
    }
    if (total > 1000u) {
        total -= 10u;
    }
    if (total > 1100u) {
        total -= 11u;
    }
    if (total > 1200u) {
        total -= 12u;
    }
    if (total > 1300u) {
        total -= 13u;
    }
    if (total > 1400u) {
        total -= 14u;
    }
    if (total > 1500u) {
        total -= 15u;
    }
    if (total > 1600u) {
        total -= 16u;
    }
    if (total > 1700u) {
        total -= 17u;
    }
    if (total > 1800u) {
        total -= 18u;
    }
    if (total > 1900u) {
        total -= 19u;
    }
    if (total > 2000u) {
        total -= 20u;
    }
    if (total > 2100u) {
        total -= 21u;
    }
    if (total > 2200u) {
        total -= 22u;
    }
    if (total > 2300u) {
        total -= 23u;
    }
    if (total > 2400u) {
        total -= 24u;
    }
    if (total > 2500u) {
        total -= 25u;
    }
    if (total > 2600u) {
        total -= 26u;
    }
    if (total > 2700u) {
        total -= 27u;
    }
    if (total > 2800u) {
        total -= 28u;
    }
    if (total > 2900u) {
        total -= 29u;
    }
    if (total > 3000u) {
        total -= 30u;
    }
    if (total > 3100u) {
        total -= 31u;
    }
    if (total > 3200u) {
        total -= 32u;
    }
    if (total > 3300u) {
        total -= 33u;
    }
    if (total > 3400u) {
        total -= 34u;
    }
    if (total > 3500u) {
        total -= 35u;
    }
    if (total > 3600u) {
        total -= 36u;
    }
    if (total > 3700u) {
        total -= 37u;
    }
    if (total > 3800u) {
        total -= 38u;
    }
    if (total > 3900u) {
        total -= 39u;
    }
    if (total > 4000u) {
        total -= 40u;
    }
    if (total > 4100u) {
        total -= 41u;
    }
    if (total > 4200u) {
        total -= 42u;
    }
    if (total > 4300u) {
        total -= 43u;
    }
    if (total > 4400u) {
        total -= 44u;
    }
    if (total > 4500u) {
        total -= 45u;
    }
    if (total > 4600u) {
        total -= 46u;
    }
    if (total > 4700u) {
        total -= 47u;
    }
    if (total > 4800u) {
        total -= 48u;
    }
    if (total > 4900u) {
        total -= 49u;
    }
    if (total > 5000u) {
        total -= 50u;
    }
    if (total > 5100u) {
        total -= 51u;
    }
    if (total > 5200u) {
        total -= 52u;
    }
    if (total > 5300u) {
        total -= 53u;
    }
    if (total > 5400u) {
        total -= 54u;
    }
    if (total > 5500u) {
        total -= 55u;
    }
    total += helper_one(head);
    total += (u32)helper_two(count);
    total ^= g_flags;
    return total;
}

u32 caller_a(struct hdr *head, const u32 *values, int count)
{
    return long_walk(head, values, count);
}

u32 caller_b(struct hdr *head, const u32 *values)
{
    return long_walk(head, values, MAX_SLOTS);
}

u32 caller_c(struct hdr *head)
{
    return long_walk(head, 0, 0);
}

u32 outer(struct hdr *head, const u32 *values, int count)
{
    return caller_a(head, values, count);
}

/* A source-to-sink path that crosses three functions. */

static int stage_three(const char *text, int offset)
{
    return text[offset];
}

static int stage_two(const char *text, int offset)
{
    return stage_three(text, offset);
}

int stage_one(const char *text, int offset)
{
    return stage_two(text, offset);
}
