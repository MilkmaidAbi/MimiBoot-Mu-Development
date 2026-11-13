/*
 * MimiBoot - what a port provides
 *
 * The core (image checks, boot log, config, policy, console, crypto) is
 * plain C with no SDK in it. Everything chip-specific comes in through this
 * table. Optional entries may be NULL; the core then falls back (software
 * SHA-256, no watchdog, no key, no console, no RAM images, no handoff).
 */
#ifndef MIMIBOOT_PORT_H
#define MIMIBOOT_PORT_H

#include "core/mb_features.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mimiboot/mb_layout.h"
#include "mimiboot/mb_image.h"
#include "mimiboot/mb_handoff.h"
#include "mimiboot/mb_control.h"

/* errors */
#define MB_OK           0
#define MB_E_IO         (-1)
#define MB_E_BADARG     (-2)
#define MB_E_CORRUPT    (-3)
#define MB_E_NOSPACE    (-4)
#define MB_E_UNSUPP     (-5)
#define MB_E_TIMEOUT    (-6)
#define MB_E_REFUSED    (-7)
#define MB_E_SIGNATURE  (-8)

/* Trusted Ed25519 public keys: fixed at build time. Nothing in flash (the
 * config, the log) can add a key or turn signature checks off. */
typedef struct {
    int count;
    const uint8_t (*keys)[32];
} mb_keyring_t;

/* Trusted ECDSA P-256 keys (MB_FEAT_ECDSA): the raw point X || Y */
typedef struct {
    int count;
    const uint8_t (*keys)[64];
} mb_keyring_p256_t;

/* Protected rollback floors (core/mb_floor.c): one erase unit the running
 * image can't write (the port locks it), read and programmed through these
 * functions, which bypass the port's "never the bootloader region" check.
 * program is NULL on the app side: apps may read the floors, not raise them. */
#define MB_FLOOR_SECURITY   0       /* anti-rollback floor for A/B images */
#define MB_FLOOR_GOLDEN     1       /* newest golden version accepted */
#define MB_FLOOR_CONFIG     2       /* newest signed config version accepted (MB_FEAT_CFG_SIGNED) */
#define MB_FLOOR_COUNT      3
typedef struct mb_floor_store {
    uint32_t off, size;         /* flash offset and size of the store (one erase unit) */
    uint32_t entry;             /* bytes per entry: 16, or the chip's program unit if larger */
    int (*read)(uint32_t off, void* buf, size_t len);
    int (*program)(uint32_t off, const void* buf, size_t len);
} mb_floor_store_t;

typedef struct mb_port {
    const char* name;           /* "rp2350", "sim" */
    const char* target;         /* images must carry this in hdr.target */
    const mb_layout_t* layout;
    uint8_t arch;               /* the architecture the bootloader itself is running on */

    /* security policy: build-time constants */
    const mb_keyring_t* keys;   /* NULL: no keys, signatures can't be checked */
    const mb_keyring_p256_t* p256_keys;     /* MB_FEAT_ECDSA: P-256 keys (NULL: none) */
    bool require_signature;     /* refuse unsigned images */
    const mb_keyring_t* unlock_keys;    /* MB_FEAT_CONSOLE_AUTH: who may unlock the console */

    /* flash: offsets from the start of flash. erase/program take whole
     * sectors / pages (the core aligns); read takes anything. */
    int (*flash_read)(uint32_t off, void* buf, size_t len);
    int (*flash_erase)(uint32_t off, size_t len);
    int (*flash_program)(uint32_t off, const void* buf, size_t len);

    /* optional: hash a flash range / memory fast (hardware SHA-256) */
    int (*hash_flash)(uint32_t off, uint32_t len, uint8_t out[32]);
    int (*hash_mem)(const void* p, uint32_t len, uint8_t out[32]);

    /* can this image be started at all? (arch, load type) */
    bool (*can_start)(const mb_image_hdr_t* hdr);

    /* start an image in place (MB_LOAD_CHAIN); returns only on failure */
    int (*launch)(const mb_image_hdr_t* hdr, uint32_t slot_off, uint32_t slot_size);

    /* RAM images: ram_ptr says where [addr, addr+len) is, or NULL if an image
     * (or the handoff) may not use it (the bootloader's own RAM, not RAM at
     * all). launch_ram starts a payload already copied and checked there. */
    void* (*ram_ptr)(uint32_t addr, uint32_t len);
    int (*launch_ram)(const mb_image_hdr_t* hdr);

    /* optional: reboot the chip into the other architecture, where the other
     * half of a universal bootloader runs (and finds the request left for it
     * in the log). Doesn't return on success. With it, can_start may accept
     * XIP images for either architecture. */
    void (*switch_arch)(uint8_t arch);

    /* optional: hardware random bytes (MB_OK), for console unlock challenges */
    int (*random)(void* buf, size_t len);

    /* optional */
    uint32_t (*time_ms)(void);
    void (*watchdog_arm)(uint32_t ms);      /* for trial boots */
    void (*watchdog_disarm)(void);
    bool (*button)(void);                   /* the "open the menu" key */
    bool (*console_open)(uint32_t wait_ms); /* bring the console up; true once someone is there */
    int  (*getc)(uint32_t timeout_ms);      /* -1: nothing */
    void (*write)(const char* s, size_t n);
    void (*console_close)(void);
    void (*reboot)(void);
    void (*reboot_rom)(void);               /* the chip's own USB/UART loader */
    uint32_t (*reset_cause)(void);          /* MB_RESET_* */
    const char* (*reset_reason)(void);      /* for people */

    /* client side (apps): which slot is this image running from? */
    int (*self_slot)(void);

    /* optional: protected copies of the rollback floors (NULL: the log only) */
    const mb_floor_store_t* floor;

    /* optional: what the port does to protect itself, for the console's
     * security line, e.g. "flash locked at handoff, debug forced shut".
     * A text containing "NOT" is shown as a warning. */
    const char* lockdown;

    /* optional: the slot whose check was running when the CPU faulted before
     * the last reset (the fault handler leaves a note and resets), or -1.
     * Reading it clears it. The core marks that slot bad. */
    int (*fault_slot)(void);

    /* Optional Night services; runtime capability checks include silicon policy. */
    uint32_t (*capabilities)(void);
    int (*prepare_topology)(mb_topology_t profile);
} mb_port_t;

#endif
