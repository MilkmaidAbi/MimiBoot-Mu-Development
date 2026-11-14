/*
 * Fuzz target: the console upload protocol (core/mb_recv.c) into a flash slot.
 * The first 256 bytes become the image header (magic, version, size and CRC
 * made right, so the fuzzer gets past them); the rest is a list of
 * [off32][len16][data] frames, each sent with a correct CRC (byte 0 bit 0
 * clear) or as given.
 */
#include "tests/sim_port.h"
#include <string.h>

static uint8_t script[1 << 18];
static size_t sn;
static void put(uint8_t b) { if (sn < sizeof(script)) script[sn++] = b; }
static void put32(uint32_t v) { for (int i = 0; i < 4; i++) put((uint8_t)(v >> (8 * i))); }

static int r_getc(void* io, uint32_t ms) { (void)io; return sim_port.getc(ms); }
static void r_puts(void* io, const char* s) { (void)io; sim_port.write(s, strlen(s)); }

static void run(void* ctx) {
    mb_slot_sink_t* sink = ctx;
    mb_recv_t r = { .ctx = sink, .getc = r_getc, .puts = r_puts, .max_frame = 1024, .where = "b",
                    .begin = mb_sink_slot_begin, .data = mb_sink_slot_data, .end = mb_sink_slot_end };
    mb_recv(&r, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) {
    if (n < 1 + sizeof(mb_image_hdr_t)) return 0;
    static bool once;
    if (!once) { sim_reset(); once = true; }
    bool raw_crc = d[0] & 1;
    sim_port.require_signature = (d[0] & 2) != 0;
    mb_image_hdr_t h;
    memcpy(&h, d + 1, sizeof(h));
    h.magic = MB_IMG_MAGIC;
    h.hdr_version = MB_IMG_HDR_VERSION;
    h.hdr_size = MB_IMG_HDR_SIZE;
    h.payload_offset = MB_IMG_PAYLOAD_OFF;
    h.payload_size %= 0x50000;                          // inside slot b
    memcpy(h.target, "sim", 4);
    mb_image_seal(&h);
    sn = 0;
    put('H');
    for (size_t i = 0; i < sizeof(h); i++) put(((const uint8_t*)&h)[i]);
    size_t i = 1 + sizeof(h);
    while (i + 6 <= n) {
        uint32_t off = (uint32_t)d[i] | (uint32_t)d[i + 1] << 8 | (uint32_t)d[i + 2] << 16 | (uint32_t)d[i + 3] << 24;
        size_t len = (size_t)(d[i + 4] | d[i + 5] << 8);
        i += 6;
        if (len > n - i) len = n - i;
        put('D');
        put32(off % (h.payload_size + 1));
        put((uint8_t)len);
        put((uint8_t)(len >> 8));
        for (size_t k = 0; k < len; k++) put(d[i + k]);
        put32(raw_crc ? 0 : mb_crc32(0, d + i, len));
        i += len;
    }
    put('E');
    sim_input(script, sn);
    mb_slot_sink_t sink = { .p = &sim_port, .slot = MB_SLOT_B };
    sim_guard(run, &sink);
    sim_port.require_signature = false;
    return 0;
}
