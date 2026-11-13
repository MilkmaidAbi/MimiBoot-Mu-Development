# Security

What MimiBoot-Mu protects, against whom, how, and where it stops. Read this
before you rely on it in a product. Everything below says which chips it holds
for; [HARDWARE-STATUS.md](HARDWARE-STATUS.md) says what has actually run.

## Who it defends against

| Attacker | Can | MimiBoot-Mu's answer |
|---|---|---|
| Code running in the app (a bug in your firmware, exploited) | Write the slots, the boot log and the config; call the flash controller directly | Signed images only, hash every boot; rollback floors kept in flash the app can't write; the bootloader region locked before the app starts (nRF) |
| Someone on the console UART | Type commands, upload images | Console lock: changes need a signed challenge (CONSOLE_AUTH) |
| Someone with a debug probe | Read and write everything, halt the CPU | Not the bootloader's job alone: lock the debug port (DEBUG_LOCK on nRF, `mbtool provision` for the persistent steps) |
| Someone with a glitcher (voltage, clock, EM) | Skip an instruction or two | Not defended yet (see "Known gaps") |

Out of scope: secrets in the app (MimiBoot holds none), side channels on the
signing machine, a compromised build machine or signing key.

## Who decides what runs

The code execution authority is whoever holds a private key whose public half
is in the build's `KEYS` file.

- With `REQUIRE_SIGNATURE` (the `secure` preset) only images signed by one of
  those keys start: MimiBoot images (Ed25519 over the whole header, which
  holds the payload's SHA-256, versions, target and handoff address) and
  Zephyr/MCUboot images (Ed25519 TLV over imgtool's digest).
- Without it, signed images are checked when they carry a signature, and
  unsigned images boot. The console's security line says so in yellow.
- The keys are compiled into the bootloader. Nothing in flash (config, log)
  can add a key or turn checks off. Changing the authority means building and
  flashing a new bootloader, which needs a debug probe or the chip's ROM
  loader (and neither, once the board is locked).
- There is no way to hand authority to someone else at run time.

To check whether a given image may run on a board:

    python tools/mbtool.py info app.mimg --pub keys/mimiboot.pub

It prints the signature check, the security version and the target. Compare
the security version with the board's floor (`log` on the console, or
`mb_client_status()` in the app).

## What is checked before an image starts

1. The header: magic, version, CRC, sizes inside the slot.
2. Built for this chip (`target`), startable here (architecture, load type).
3. A/B images: `security_version` not below the rollback floor. Golden: not
   older than the golden version already accepted.
4. The signature (every boot when signatures are required).
5. The SHA-256 of the whole payload (`BOOT_VERIFY=every-boot`; `once` and
   `never` trade this for speed and are refused together with required
   signatures).

A failure marks the slot bad with the reason and the next candidate is tried
(the other A/B slot, then golden).

## Rollback floors

An image's `security_version` (`mbtool pack --secver N`) is a promise: once a
version-N image is confirmed, nothing below N boots again. The floor and the
newest golden version live in two places:

- **The boot log.** Ordinary flash. The app library raises the floor when the
  app confirms itself. A compromised app could also lower it here.
- **The protected store** (`PROTECTED_FLOOR`, nRF): an append-only list in the
  last 4 KB of the bootloader region, which `BOOT_LOCK` write-protects before
  the app runs. The bootloader raises it only to the security version of a
  confirmed image it is about to start, so a hostile log can't push it to some
  silly value either.

The floor that counts is the higher of the two. `boot <slot> force` on the
console doesn't get past it, and neither does `ramboot` when signatures are
required. The store has room for 256 raises; when it is full the floors stay
where they are and the log copy carries on.

## Protection per chip

| Chip | Bootloader region vs the app | Debug port | Persistent steps (`mbtool provision`) |
|---|---|---|---|
| nRF51 | `BOOT_LOCK`: MPU PROTENSET until reset | UICR readback protection | `nrfjprog --rbp ALL` |
| nRF52805/810/811/832 | `BOOT_LOCK`: BPROT until reset, also in debug mode | `DEBUG_LOCK` (newer silicon), UICR.APPROTECT | `nrfjprog --rbp ALL` |
| nRF52820/833/840 | `BOOT_LOCK`: an ACL region until reset | as above | as above |
| STM32 | option bytes: WRP on the bootloader's sectors | RDP level 1 (reversible), level 2 (forever) | prints the CubeProgrammer commands |
| SAM D21/D51 | BOOTPROT fuse | Security Bit | prints the OpenOCD commands; refuses when BOOTPROT can't cover the region exactly |
| AVR (Lite) | lock bits BLB1 (SPM can't write the boot section) | lock bits LB | prints the avrdude command |
| RP2040 | nothing on the chip can do it | can't be disabled | none |
| RP2350 | secure boot needs OTP (irreversible): not automated | OTP | see the RP2350 datasheet |

Notes:

- The nRF locks are written from Nordic's register descriptions and the nRF
  Connect SDK's own flash-protection drivers. They compile for every nRF
  board; they haven't run on silicon yet.
- STM32 write protection also stops the bootloader writing its own region.
  MimiBoot never needs to, which is why the protected floor store exists only
  where the lock can be applied after the bootloader's own writes (nRF).
- SAM D21's BOOTPROT covers at most 32 KB. A bootloader region larger than
  that (the default 48 KB with signatures and the console) can't be protected
  exactly; build a smaller one (`BOOT_SIZE`) first. Software can rewrite the
  user row that holds BOOTPROT; a change only takes effect after a reset, but
  MimiBoot doesn't yet check and restore it at boot.
- The fuse and option-byte steps are printed, never run. Several can't be
  undone without erasing the chip; RDP level 2 and RP2350 OTP can't be undone
  at all.

## The console

The console is powerful by design: it uploads images, edits the config and
marks images good or bad. On a product:

- Turn it off (`CONSOLE`, `SHELL`), or
- Lock it (`CONSOLE_AUTH`, on in the `secure` preset). Until `unlock` is
  answered, it only lets you look (`ls`, `info`, `verify`, `log`...) and boot an
  entry as configured. Everything that changes state, edits boot arguments or
  enters the ROM loader needs the unlock.

`unlock` prints a 32-byte challenge; mbtool signs
`"MimiBoot console unlock v1\0" || target || challenge` with the key given by
`--unlock-key` (or `MB_UNLOCK_KEY`) and sends the signature back. The keys
come from `UNLOCK_KEYS` (one per line, `mbtool keygen`), or the image keys if
that is empty; a separate key is better, so the image signing key never has
to be on the bench. The domain prefix means an unlock signature can never be
mistaken for an image signature, or the other way round. Each wrong answer
costs a growing delay; after five the console stays locked until a reset.

The challenge comes from the hardware RNG on nRF. Other chips don't have one
wired up yet: there it is a hash of the boot count, a session counter and the
clock, which is unique but predictable to someone who can also reset the boot
log. Treat CONSOLE_AUTH on those chips as a guard against casual access, not
against an attacker who already controls the flash.

## Faults

A HardFault or NMI in the bootloader (a flash ECC error, a bus error reading a
damaged slot, a bug) resets the chip instead of hanging. If the fault happened
while an image was being checked, a note in RAM that survives the reset names
the slot, and the next boot marks it bad (`CPU fault while checking`) and
falls back.

## Cryptography

| Mechanism | Used for |
|---|---|
| Ed25519 (RFC 8032) | image signatures, console unlock |
| SHA-256 | payload hashes; Ed25519 uses SHA-512 internally |
| CRC-32 | corruption checks only (headers, log, config, upload frames, the Lite core): not a security mechanism |

Ed25519 isn't on the EU's ECCG agreed-mechanisms list (ECDSA P-256 and LMS
are); ETSI TS 119 312 recommends it. The verifier is tested against RFC 8032's
vectors and all 210 of Project Wycheproof's: every valid signature verifies,
every invalid one (malleable S, non-canonical encodings, truncated or padded
signatures, wrong keys) is refused. Of the 29 cases Wycheproof leaves to the
implementation (small-order and mixed-order public keys), all are accepted:
the check is cofactorless. That matters only when an attacker picks the
public key, and here the keys are compiled in. ECDSA P-256 and LMS support are
planned.

The AVR Lite core does no cryptography at all.

## Known gaps

- **Fault injection.** The boot decision comes down to single branches. A
  glitch at the right moment could skip a check.
- **No self-update.** The bootloader can't replace itself in the field: a bug
  in it is fixed only with a debug probe. (A two-stage design is planned.)
- **Untested on hardware.** The nRF locks, the debug lock and the RNG have run
  only in the emulator (RNG, flash) or not at all (BPROT, ACL, APPROTECT).
- **The boot config** (boot order, arguments) is protected by a CRC, not a
  signature. Keep `CFG_FILE` off on a locked product, or lock the console.
- **No encryption.** Images are stored in the clear.
- **No measured boot or attestation.**

## Reporting a problem

Open an issue on the repository. For something you'd rather not post in
public, say so in a short issue without the details and ask for a private
channel.
