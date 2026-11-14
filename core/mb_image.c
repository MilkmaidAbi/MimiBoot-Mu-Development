/*
 * MimiBoot - image headers, verification, writing slots
 */
#include "core/mimiboot.h"
#include <string.h>

_Static_assert(sizeof(mb_image_hdr_t) == MB_IMG_HDR_SIZE, "image header must be 256 bytes");
_Static_assert(MB_IMG_SIGNED_BYTES == 188, "signed part of the header moved");
_Static_assert(sizeof(mb_bcl_rec_t) == MB_BCL_REC_SIZE, "log record must be 256 bytes");
_Static_assert(sizeof(mb_bcl_sect_t) == MB_BCL_REC_SIZE, "log sector header must be one record");
_Static_assert(sizeof(mb_handoff_t) == 160 && offsetof(mb_handoff_t, crc) == 156, "handoff layout moved");

const char* mb_slot_name(const mb_port_t* p, int slot) {
    if (slot == MB_SLOT_AB) return "ab";
    if (slot < 0 || slot >= p->layout->n_slots) return "-";
    return p->layout->slot[slot].name;
}

int mb_slot_role(const mb_port_t* p, int slot) {
    return slot >= 0 && slot < p->layout->n_slots ? p->layout->slot[slot].role : MB_ROLE_NONE;
}

int mb_slot_parse(const mb_port_t* p, const char* s) {
    if (!s || !*s) return -1;
    for (int i = 0; i < p->layout->n_slots; i++) {
        const char* n = p->layout->slot[i].name;
        size_t k = 0;
        while (n[k] && (s[k] | 0x20) == n[k]) k++;
        if (!n[k] && !s[k]) return i;
    }
    if (!strcmp(s, "golden")) return MB_SLOT_GOLDEN;
    if (s[0] >= '0' && s[0] <= '9' && !s[1] && s[0] - '0' < p->layout->n_slots) return s[0] - '0';
    return -1;
}

void mb_image_seal(mb_image_hdr_t* h) {
    h->hdr_crc = mb_crc32(0, h, offsetof(mb_image_hdr_t, hdr_crc));
}

// Structural checks only (no hash, no signature): `room` is the slot size
int mb_image_check_header(const mb_port_t* p, const mb_image_hdr_t* h, uint32_t room) {
    if (h->magic != MB_IMG_MAGIC) return MB_E_CORRUPT;
    if (h->hdr_version != MB_IMG_HDR_VERSION || h->hdr_size != MB_IMG_HDR_SIZE) return MB_E_CORRUPT;
    if (mb_crc32(0, h, offsetof(mb_image_hdr_t, hdr_crc)) != h->hdr_crc) return MB_E_CORRUPT;
    if (h->payload_offset < sizeof(*h) || h->payload_offset % p->layout->sector_size) return MB_E_CORRUPT;
    if (h->payload_size == 0 || h->payload_offset > room || h->payload_size > room - h->payload_offset) return MB_E_CORRUPT;
    return MB_OK;
}

// Which format does the slot hold? MIMG first, then MCUboot, then a bare
// vector table (the magics of the first two can never pass as a stack pointer).
int mb_image_read_header(const mb_port_t* p, int slot, mb_slot_info_t* out) {
    memset(out, 0, sizeof(*out));
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    const mb_slot_def_t* r = &p->layout->slot[slot];
#if MB_FEAT_IMG_NATIVE
    if (p->flash_read(r->offset, &out->hdr, sizeof(out->hdr)) != MB_OK) return MB_E_IO;
    if (mb_image_check_header(p, &out->hdr, r->size) == MB_OK) {
        out->header_ok = true;
        out->fmt = MB_FMT_NATIVE;
        out->hash_off = out->hdr.payload_offset;
        out->hash_len = out->hdr.payload_size;
        return MB_OK;
    }
    memset(out, 0, sizeof(*out));
#else
    (void)r;
#endif
#if MB_FEAT_IMG_MCUBOOT
    if (mb_mcuboot_probe(p, slot, out) == MB_OK) return MB_OK;
    memset(out, 0, sizeof(*out));
#endif
#if MB_FEAT_IMG_RAW
    if (mb_raw_probe(p, slot, out) == MB_OK) return MB_OK;
    memset(out, 0, sizeof(*out));
#endif
    return MB_E_CORRUPT;
}

static int hash_flash(const mb_port_t* p, uint32_t off, uint32_t len, uint8_t out[32]) {
    if (p->hash_flash && p->hash_flash(off, len, out) == MB_OK) return MB_OK;
    mb_sha256_t s;
    uint8_t buf[256];
    mb_sha256_init(&s);
    for (uint32_t done = 0; done < len;) {
        uint32_t n = len - done < sizeof(buf) ? len - done : (uint32_t)sizeof(buf);
        if (p->flash_read(off + done, buf, n) != MB_OK) return MB_E_IO;
        mb_sha256_update(&s, buf, n);
        done += n;
    }
    mb_sha256_final(&s, out);
    return MB_OK;
}

volatile uint8_t mb_checking_slot = MB_SLOT_NONE;

// Two-stage builds: what may go into (and start from) a slot. A stage-1 slot
// takes only a stage 1 for this target, linked for that very slot; every other
// slot refuses a stage 1 (the flag is in the signed bytes, so it can't be
// stripped). Stage 0 and uploads both ask this; "not the copy that is
// running" is the upload's own rule (mb_sink_slot_begin).
int mb_stage1_accepts(const mb_port_t* p, int slot, const mb_image_hdr_t* h) {
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    bool s1 = (h->flags & MB_IMG_F_STAGE1) != 0;
    if (mb_slot_role(p, slot) != MB_ROLE_STAGE1) return s1 ? MB_E_REFUSED : MB_OK;
    if (!s1 || h->load_type != MB_LOAD_CHAIN) return MB_E_REFUSED;
    if (strncmp(h->target, p->target, sizeof(h->target))) return MB_E_UNSUPP;
    if (h->entry != p->layout->slot[slot].offset + h->payload_offset) return MB_E_REFUSED;   // linked for the other copy
    return MB_OK;
}

// The header's `entry` is only a claim: the payload's own reset vector must
// point into it where it says it is linked. A build for the other copy (or
// anything else) fails here, before stage 0 jumps into it.
int mb_stage1_vectors_ok(const mb_port_t* p, int slot, const mb_image_hdr_t* h) {
    uint32_t v[2];
    if (h->payload_size < 8 || p->flash_read(p->layout->slot[slot].offset + h->payload_offset, v, sizeof(v)) != MB_OK)
        return MB_E_IO;
    uint32_t lo = p->flash_base + h->entry, pc = v[1] & ~1u;
    return pc >= lo && pc - lo < h->payload_size ? MB_OK : MB_E_REFUSED;
}

// A stage 1's signature, against the stage-1 keys only: a leaked app key must
// not be enough to replace the bootloader.
int mb_stage1_check_sig(const mb_port_t* p, mb_slot_info_t* info) {
    mb_port_t q = *p;
    q.keys = p->stage1_keys;
    q.p256_keys = p->stage1_p256_keys;
    return mb_image_check_sig(&q, info);
}

uint32_t mb_ct_diff(const void* a, const void* b, size_t n) {
    const volatile uint8_t* x = a;
    const volatile uint8_t* y = b;
    volatile uint32_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint32_t)(x[i] ^ y[i]);
    return d;
}

int mb_image_verify(const mb_port_t* p, int slot, mb_slot_info_t* info) {
    if (!info->header_ok) return MB_E_CORRUPT;
    if (info->hash_state) return info->hash_state > 0 ? MB_OK : MB_E_CORRUPT;
    if (info->fmt == MB_FMT_RAW) {              // nothing to check against: bootable as it is
        info->hash_state = 1;
        info->proof_hash = MB_PROOF_HASH;
        return MB_OK;
    }
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint32_t off = info->hdr.payload_offset, len = info->hdr.payload_size;
    if (info->fmt == MB_FMT_MCUBOOT) { off = info->hash_off; len = info->hash_len; }
    uint8_t got[32];
    if (hash_flash(p, r->offset + off, len, got) != MB_OK) return MB_E_IO;
    info->hash_state = -1;
    // compared twice, independently: one skipped branch doesn't pass a wrong hash
    if (mb_ct_diff(got, info->hdr.sha256, 32) != 0) return MB_E_CORRUPT;
    if (mb_ct_diff(info->hdr.sha256, got, 32) == 0) {
        info->hash_state = 1;
        info->proof_hash = MB_PROOF_HASH;
    }
    return info->hash_state > 0 ? MB_OK : MB_E_CORRUPT;
}

#if MB_FEAT_SIGNATURES
static uint32_t key_id_of(const uint8_t* key) {
    return (uint32_t)key[0] | (uint32_t)key[1] << 8 | (uint32_t)key[2] << 16 | (uint32_t)key[3] << 24;
}
#endif

// Signed: the key named by key_id must be in the build's keyring and the
// signature must verify. Unsigned: fine unless the build requires signatures.
// Ed25519 (the default) signs the first MB_IMG_SIGNED_BYTES of the header;
// ECDSA P-256 (MB_IMG_F_ECDSA) signs their SHA-256. MCUboot images: the
// signature is over the image's 32-byte SHA-256 digest (imgtool's default,
// non-pure mode) and any key of the right kind may match; mb_image_verify then
// makes sure the digest is the real one.
int mb_image_check_sig(const mb_port_t* p, mb_slot_info_t* info) {
    if (info->sig_state) return info->sig_state > 0 ? MB_OK : MB_E_SIGNATURE;
    const mb_image_hdr_t* h = &info->hdr;
    info->sig_state = -1;
    if (!(h->flags & MB_IMG_F_SIGNED)) {
        if (!p->require_signature) { info->sig_state = 1; info->proof_sig = MB_PROOF_UNSIGNED; }
        return info->sig_state > 0 ? MB_OK : MB_E_SIGNATURE;
    }
#if MB_FEAT_SIGNATURES
    bool ecdsa = (h->flags & MB_IMG_F_ECDSA) != 0;
    bool have_keys = ecdsa ? (MB_FEAT_ECDSA && p->p256_keys && p->p256_keys->count) : (p->keys && p->keys->count);
    if (!have_keys) {
        if (p->require_signature) return MB_E_SIGNATURE;
        info->sig_state = 1;
        info->proof_sig = MB_PROOF_UNSIGNED;      // nothing to check it against: counts as unsigned
        return MB_OK;
    }
    if (ecdsa) {
#if MB_FEAT_ECDSA
        uint8_t digest[32];
        if (info->fmt == MB_FMT_MCUBOOT) {
            memcpy(digest, h->sha256, 32);
        } else {
            mb_sha256_t s;
            mb_sha256_init(&s);
            mb_sha256_update(&s, h, MB_IMG_SIGNED_BYTES);
            mb_sha256_final(&s, digest);
        }
        for (int k = 0; k < p->p256_keys->count; k++) {
            const uint8_t* key = p->p256_keys->keys[k];
            if (info->fmt != MB_FMT_MCUBOOT && key_id_of(key) != h->key_id) continue;
            if (mb_ecdsa_p256_verify(h->signature, digest, key)) {
                info->sig_state = 1;
                info->proof_sig = MB_PROOF_SIG;
                return MB_OK;
            }
        }
#endif
        return MB_E_SIGNATURE;
    }
    for (int k = 0; k < p->keys->count; k++) {
        const uint8_t* key = p->keys->keys[k];
        bool ok;
        if (info->fmt == MB_FMT_MCUBOOT) {
            ok = mb_ed25519_verify(h->signature, h->sha256, 32, key);
        } else {
            if (key_id_of(key) != h->key_id) continue;
            ok = mb_ed25519_verify(h->signature, h, MB_IMG_SIGNED_BYTES, key);
        }
        if (ok) { info->sig_state = 1; info->proof_sig = MB_PROOF_SIG; return MB_OK; }
    }
    return MB_E_SIGNATURE;
#else
    // Built without signature support: a signed image counts as unsigned.
    if (!p->require_signature) { info->sig_state = 1; info->proof_sig = MB_PROOF_UNSIGNED; }
    return info->sig_state > 0 ? MB_OK : MB_E_SIGNATURE;
#endif
}

// ---------------------------------------------------------------------------
// Writing. Erase the header sector first (the slot is now "empty"), write
// the payload, and only then the header: a power cut anywhere before the
// header lands leaves an empty slot, never one that claims a payload.
// ---------------------------------------------------------------------------

int mb_slot_erase(const mb_port_t* p, int slot, uint32_t bytes) {
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint32_t ss = p->layout->sector_size;
    uint32_t len = MB_IMG_PAYLOAD_OFF + bytes;
    len = (len + ss - 1) / ss * ss;
    if (len > r->size) return MB_E_NOSPACE;
    int rc = p->flash_erase(r->offset, ss);
    if (rc == MB_OK && len > ss) rc = p->flash_erase(r->offset + ss, len - ss);
#if MB_FEAT_IMG_MCUBOOT
    // an MCUboot trailer left at the end of the slot by an earlier image would
    // confirm the next one before it ever ran (mb_mcuboot_confirmed)
    if (rc == MB_OK && len < r->size) rc = p->flash_erase(r->offset + r->size - ss, ss);
#endif
    return rc;
}

int mb_slot_write(const mb_port_t* p, int slot, uint32_t payload_off, const void* data, size_t len) {
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    const mb_slot_def_t* r = &p->layout->slot[slot];
    uint32_t page = p->layout->page_size;
    uint32_t start = MB_IMG_PAYLOAD_OFF + payload_off;
    if (start + len > r->size) return MB_E_NOSPACE;
    uint8_t buf[256];
    if (page > sizeof(buf)) return MB_E_UNSUPP;
    const uint8_t* src = data;
    while (len) {
        uint32_t at = start % page;
        uint32_t n = page - at < len ? page - at : (uint32_t)len;
        memset(buf, 0xFF, page);                        // 0xFF programs nothing
        memcpy(buf + at, src, n);
        int rc = p->flash_program(r->offset + start - at, buf, page);
        if (rc != MB_OK) return rc;
        start += n; src += n; len -= n;
    }
    return MB_OK;
}

int mb_slot_write_header(const mb_port_t* p, int slot, const mb_image_hdr_t* hdr) {
    if (slot < 0 || slot >= p->layout->n_slots) return MB_E_BADARG;
    uint8_t buf[256];
    memcpy(buf, hdr, sizeof(*hdr));
    return p->flash_program(p->layout->slot[slot].offset, buf, sizeof(buf));
}
