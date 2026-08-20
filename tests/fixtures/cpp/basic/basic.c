/* Fixture for T-06-01, T-06-04 and T-06-08. parse_header spans lines 10-30
 * exactly and line 5 is at file scope; both are asserted, so keep the layout
 * stable when editing.
 */
#define BUF_SZ 16
#define CHECK_LEN(n) if ((n) < BUF_SZ)

struct Packet { int len; char data[BUF_SZ]; };
int packets_seen;
int parse_header(struct Packet *packet)
{
    int copied;

    copied = 0;
    CHECK_LEN(packet->len) {
        copied = packet->len;
    }

    packets_seen = packets_seen + 1;

    /* Padding, so the function occupies the asserted span. The body is
     * deliberately dull: this fixture is about the index rather than about
     * anything being wrong in it.
     */
    if (copied < 0) {
        copied = 0;
    }

    return copied;
}

static int checksum(const struct Packet *packet)
{
    return packet->len & 0xff;
}

int total(struct Packet *packet)
{
    return parse_header(packet) + checksum(packet);
}
