/*
 * MimiBoot host tests: the console lock (built with MB_FEAT_CONSOLE_AUTH=1).
 * What a locked console refuses and allows, bad unlock answers, the lockout.
 * A good answer needs a signature over a fresh nonce: the QEMU test does that
 * end to end with mbtool's own signing code.
 */
#include "tests/sim_port.h"
#include <stdio.h>
#include <string.h>

#if !MB_FEAT_CONSOLE_AUTH
#error "build with -DMB_FEAT_CONSOLE_AUTH=1"
#endif

static int fails, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static const mb_keyring_t unlock_ring = { 1, (const uint8_t (*)[32])sim_test_public };

static sim_outcome_t console(const char* script) {
    sim.console = true;
    sim.button = true;
    sim_input(script, strlen(script));
    sim_outcome_t o = sim_power_on();
    sim.console = false;
    sim.button = false;
    return o;
}

static void put_golden(void) {
    // a minimal golden image so the menu has something (content irrelevant here)
    static uint8_t body[4096];
    for (unsigned i = 0; i < sizeof body; i++) body[i] = (uint8_t)(i * 7);
    mb_image_hdr_t h;
    memset(&h, 0, sizeof h);
    h.magic = MB_IMG_MAGIC;
    h.hdr_version = MB_IMG_HDR_VERSION;
    h.hdr_size = MB_IMG_HDR_SIZE;
    h.flags = MB_IMG_F_GOLDEN;
    h.load_type = MB_LOAD_CHAIN;
    h.payload_offset = MB_IMG_PAYLOAD_OFF;
    h.payload_size = sizeof body;
    mb_sha256_t s;
    mb_sha256_init(&s);
    mb_sha256_update(&s, body, sizeof body);
    mb_sha256_final(&s, h.sha256);
    h.version = MB_VERSION(1, 0, 0);
    h.arch = MB_ARCH_ARM;
    strcpy(h.name, "rescue");
    strcpy(h.target, "sim");
    mb_image_seal(&h);
    uint32_t off = sim_port.layout->slot[MB_SLOT_GOLDEN].offset;
    memcpy(sim_flash + off, &h, sizeof h);
    memcpy(sim_flash + off + MB_IMG_PAYLOAD_OFF, body, sizeof body);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("console lock\n");
    sim_reset();
    sim_port.unlock_keys = &unlock_ring;
    put_golden();

    console("c\rerase g\rreject g\rcfg reset\rboot g force\rramboot\rmd 0 16\rretry g\r");
    CHECK(strstr(sim.out, "locked: 'unlock' first") != NULL, "state-changing commands refused");
    CHECK(!strstr(sim.out, "erase slot g?") && !strstr(sim.out, "g -> BAD") && !strstr(sim.out, "MB READY"),
          "none of them ran");
    mb_bcl_t log;
    mb_bcl_load(&log, &sim_port);
    CHECK(log.cur.slot[MB_SLOT_GOLDEN].state != MB_ST_BAD, "golden not rejected");

    console("c\rls\rinfo g\rverify g\rversion\rhelp\r");
    CHECK(strstr(sim.out, "rescue") && strstr(sim.out, "g: sha256 OK") && strstr(sim.out, "unlock "), "looking is allowed");
    CHECK(!strstr(sim.out, "locked:"), "nothing refused while looking");

    CHECK(console("c\rboot g\r") == SIM_BOOTED && sim.booted_slot == MB_SLOT_GOLDEN, "booting an entry as configured is allowed");

    printf("console lock: menu keys\n");
    console("e");
    CHECK(strstr(sim.out, "locked: editing args") != NULL, "menu 'e' (edit args) refused");
    CHECK(console("u") != SIM_ROM && strstr(sim.out, "locked: the ROM loader"), "menu 'u' (ROM loader) refused");

    printf("console lock: bad answers, lockout\n");
    console("c\runlock\rnot-a-signature\r");
    CHECK(strstr(sim.out, "MB CHALLENGE sim ") != NULL, "challenge names the target");
    CHECK(strstr(sim.out, "MB ERR bad response (1 of 5)") != NULL, "garbage answer refused");
    static char zero[600] = "c\runlock\r";
    for (int i = 0; i < 128; i++) strcat(zero, "0");
    strcat(zero, "\runlock\r");
    for (int i = 0; i < 128; i++) strcat(zero, "a");
    strcat(zero, "\runlock\r1\runlock\r2\runlock\rerase g\r");
    console(zero);
    CHECK(strstr(sim.out, "(2 of 5)") && strstr(sim.out, "(5 of 5)"), "well-formed wrong signatures refused");
    CHECK(strstr(sim.out, "MB ERR locked out until reset") != NULL, "sixth attempt: locked out");
    CHECK(!strstr(sim.out, "erase slot g?"), "still locked");
    console("c\runlock\r");
    CHECK(strstr(sim.out, "MB ERR locked out until reset") != NULL, "lockout holds for the session (no reset in the sim)");

    printf("\n%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
