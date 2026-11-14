/*
 * MimiBoot client - what a booted image uses to talk to the bootloader
 *
 * State goes through the boot log and config in flash, so it works the same
 * whether the bootloader is running or not (and survives resets). The boot
 * handoff (args, how we were booted) comes in RAM when the image asked for
 * one, with the flash as the fallback.
 *
 *   mb_client_init(port)             once, with the app-side port (flash ops)
 *   mb_client_set_handoff(&mb_handoff)   if the image declares MB_HANDOFF_BUFFER
 *   mb_client_status(&st)            which slot am I, am I on trial?
 *   mb_client_args()                 my command line
 *   mb_client_confirm()              "this image works": GOOD, active, raise the rollback floor
 *   mb_client_request(...)           menu / another slot or entry once / ROM loader, next reset
 *   mb_client_install_*()            write a new image into the other slot (A/B update)
 *   mb_client_recv(...)              ... or receive one over a byte stream (OTA)
 *
 * Two ways to ask for a boot mode:
 *   mb_client_request()   writes the request into the boot log. Always works,
 *                         with any MimiBoot build and without a handoff.
 *   mb_client_control()   the control service: more (boot profiles, config
 *                         mode, reboot at once). Only when this boot's
 *                         handoff says the bootloader has it: check
 *                         mb_client_capabilities() & MB_CAP_CONTROL first;
 *                         without it the call returns MB_E_UNSUPP and
 *                         mb_client_request() is the fallback.
 */
#ifndef MIMIBOOT_CLIENT_H
#define MIMIBOOT_CLIENT_H

#include "core/mimiboot.h"

typedef struct {
    int slot;  /* the slot this image runs from (MB_SLOT_NONE: not booted by MimiBoot) */
    int state; /* its log state: MB_ST_TRIAL means "confirm me" */
    int tries_left;
    int active;    /* the preferred GOOD A/B slot */
    int last_kind; /* how this boot was chosen (MB_KIND_*) */
    int strikes;   /* watchdog resets in a row (crash-loop guard) */
    uint32_t version, security_version, min_security;
    bool handoff; /* a valid handoff was received this boot */
    char name[32];
    char entry[16]; /* config entry we were booted as ("" if unknown) */
} mb_client_status_t;

int mb_client_init(const mb_port_t *port);
void mb_client_set_handoff(volatile mb_handoff_t *h);
const mb_handoff_t *mb_client_handoff(void); /* NULL: none this boot */
const char *mb_client_args(void);            /* never NULL */
int mb_client_status(mb_client_status_t *st);
int mb_client_confirm(void);
int mb_client_reject(int slot);              /* mark another slot BAD (until its image changes) */
int mb_client_vacate(int slot);              /* empty another slot: its header erased, its log record cleared */
int mb_client_request(int request, int arg); /* MB_REQ_MENU / _BOOT_ONCE(slot) / _BOOTSEL / _FLASH */
int mb_client_request_entry(const char *entry, const char *args); /* MB_REQ_ENTRY_ONCE by name */

/* A/B update into `slot` (normally the one we are *not* running from;
 * writing your own slot or golden is refused). The header is written last,
 * after the payload hashed correctly, so a half-written image is never
 * seen as one. The bootloader boots it as a trial on the next reset.
 * Writes are in order (offset = what has been written so far; a chunk sent
 * again is accepted and ignored) and of any size: the library gathers whole
 * flash pages and programs each once, so flash with write-once units (STM32
 * L4/G0/G4 ECC, SAM D21 rows) needs nothing from the caller.
 * install_abort() gives up: the slot is left empty (its header was erased at
 * begin), the library ready for a new begin.
 * Encrypted images (MB_IMG_F_ENCRYPTED) are refused with MB_E_UNSUPP, here
 * and in mb_client_recv(): only the bootloader holds the decryption key, so
 * they go to MimiBoot's console (mbtool install) or its SMP. */
int mb_client_install_begin(int slot, const mb_image_hdr_t *hdr);
int mb_client_install_write(uint32_t offset, const void *data, size_t len);
int mb_client_install_end(void);
int mb_client_install_abort(void);

/* OTA: run the mb_recv protocol on a byte stream (a console, a socket...)
 * straight into `slot` through the install functions above. */
int mb_client_recv(int slot, void *io, int (*getc)(void *io, uint32_t ms), void (*puts)(void *io, const char *s),
                   uint16_t max_frame);

uint32_t mb_client_capabilities(void);
int mb_client_control(const mb_control_request_t *request, bool reboot_now);
int mb_client_reboot_menu(void);
int mb_client_reboot_config(void);
int mb_client_reboot_profile(const char *entry, mb_topology_t profile, const char *args);
int mb_client_get_config(char *, size_t);
int mb_client_set_config(const char *, size_t, char *, size_t);
int mb_client_set_default(const char *);
int mb_client_other_slot(void); /* the A/B slot we don't run from */

#endif
