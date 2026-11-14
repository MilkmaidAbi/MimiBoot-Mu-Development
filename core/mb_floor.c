/*
 * MimiBoot - protected rollback floors
 *
 * The boot log holds the anti-rollback floor (min_security) and the newest
 * golden version, but the log is ordinary flash the running app writes, so an
 * app that has been taken over could write a record with a lower floor. A
 * port that can protect part of its own flash from the app (nRF: BPROT/ACL
 * locks the bootloader region until reset) keeps a second copy there: an
 * append-only list of entries in one erase unit,
 *
 *     [tag][value][~value][~tag]   (16 bytes; padded to the chip's program unit)
 *
 * tag "MBF0" is the security floor, "MBF1" the golden version, "MBF2" the
 * signed config version, "MBF3" the stage-1 floor. A value is the highest one
 * found for its tag. Two-stage builds also count entries here (tags 14 and
 * 15: which stage 1 worked, and boots of one that hasn't yet). Raising writes one new entry into blank
 * flash: it never erases, so a power cut leaves either the old entries or the
 * old entries plus a complete new one (a torn entry fails its check and is
 * skipped). When the unit is full the floors stay where they are (the log
 * copy still works); at one entry per security-version bump that takes
 * hundreds of releases.
 *
 * The effective floor is max(log, store): the store can only make the log
 * stricter.
 */
#include "core/mimiboot.h"
#include <string.h>

#define FLOOR_TAG(w) (0x3046424Du + ((uint32_t)(w) << 24)) /* "MBF0", "MBF1" */

typedef struct {
    uint32_t tag, value, inv, ntag;
} entry_t;

static bool blank(const entry_t *e) {
    return e->tag == 0xFFFFFFFFu && e->value == 0xFFFFFFFFu && e->inv == 0xFFFFFFFFu && e->ntag == 0xFFFFFFFFu;
}

// Walk the store: highest value per tag, and the first blank entry (or size)
static int scan(const mb_floor_store_t *s, uint32_t out[MB_FLOOR_COUNT], uint32_t *free_off) {
    for (int i = 0; i < MB_FLOOR_COUNT; i++)
        out[i] = 0;
    uint32_t off = 0;
    for (; off + s->entry <= s->size; off += s->entry) {
        entry_t e;
        if (s->read(s->off + off, &e, sizeof e) != MB_OK)
            return MB_E_IO;
        if (blank(&e))
            break;
        if (e.inv != ~e.value || e.ntag != ~e.tag)
            continue; // torn by a power cut: skip it, never reuse it
        for (int w = 0; w < MB_FLOOR_COUNT; w++)
            if (e.tag == FLOOR_TAG(w) && e.value > out[w])
                out[w] = e.value;
    }
    if (free_off)
        *free_off = off;
    return MB_OK;
}

int mb_floor_get(const mb_port_t *p, uint32_t out[MB_FLOOR_COUNT]) {
    for (int i = 0; i < MB_FLOOR_COUNT; i++)
        out[i] = 0;
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || s->entry < sizeof(entry_t) || s->entry > 256)
        return MB_E_UNSUPP;
    return scan(s, out, NULL);
}

// How many valid entries with this tag and value (two-stage: stage-1 boot attempts)
int mb_store_count(const mb_port_t *p, int tag, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || s->entry < sizeof(entry_t) || s->entry > 256)
        return 0;
    int n = 0;
    for (uint32_t off = 0; off + s->entry <= s->size; off += s->entry) {
        entry_t e;
        if (s->read(s->off + off, &e, sizeof e) != MB_OK || blank(&e))
            break;
        if (e.inv == ~e.value && e.ntag == ~e.tag && e.tag == FLOOR_TAG(tag) && e.value == value)
            n++;
    }
    return n;
}

// Write one more counted entry (MB_STORE_S1_*). Attempts stop short of the
// last MB_STORE_RESERVE entries, so counting boots can never use up the room
// a floor raise needs. Read back like a floor: it counts only if it reads as
// written.
int mb_store_append(const mb_port_t *p, int tag, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || !s->program || tag < MB_FLOOR_COUNT || tag > 15)
        return MB_E_UNSUPP;
    if (s->entry < sizeof(entry_t) || s->entry > 256)
        return MB_E_BADARG;
    uint32_t cur[MB_FLOOR_COUNT], at;
    int rc = scan(s, cur, &at);
    if (rc != MB_OK)
        return rc;
    uint32_t keep = tag == MB_STORE_S1_ATTEMPT ? MB_STORE_RESERVE * s->entry : 0;
    if (at > s->size || s->size - at < s->entry + keep)
        return MB_E_NOSPACE;
    int before = mb_store_count(p, tag, value);
    uint8_t buf[256];
    memset(buf, 0xFF, s->entry);
    entry_t e = {FLOOR_TAG(tag), value, ~value, ~FLOOR_TAG(tag)};
    memcpy(buf, &e, sizeof e);
    rc = s->program(s->off + at, buf, s->entry);
    if (rc != MB_OK)
        return rc;
    return mb_store_count(p, tag, value) > before ? MB_OK : MB_E_IO;
}

int mb_floor_raise(const mb_port_t *p, int which, uint32_t value) {
    const mb_floor_store_t *s = p->floor;
    if (!s || !s->read || !s->program || which < 0 || which >= MB_FLOOR_COUNT)
        return MB_E_UNSUPP;
    if (s->entry < sizeof(entry_t) || s->entry > 256)
        return MB_E_BADARG;
    uint32_t cur[MB_FLOOR_COUNT], at;
    int rc = scan(s, cur, &at);
    if (rc != MB_OK)
        return rc;
    if (value <= cur[which])
        return MB_OK; // already there: nothing written
    if (at + s->entry > s->size)
        return MB_E_NOSPACE;
    uint8_t buf[256];
    memset(buf, 0xFF, s->entry);
    entry_t e = {FLOOR_TAG(which), value, ~value, ~FLOOR_TAG(which)};
    memcpy(buf, &e, sizeof e);
    rc = s->program(s->off + at, buf, s->entry);
    if (rc != MB_OK)
        return rc;
    uint32_t now[MB_FLOOR_COUNT];
    rc = scan(s, now, NULL); // read back: the write counts only if it reads as written
    if (rc != MB_OK)
        return rc;
    return now[which] >= value ? MB_OK : MB_E_IO;
}
