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

## Revoking a signing key

Keys are compiled in, so that nothing in flash can add one. The other side of
that: a key that leaks would stay trusted until every board got a new
bootloader. With `REVOKE_KEYS` a board can drop one of its keys in the field:

- The statement is an Ed25519 signature by a revocation key over
  `"MimiBoot revoke v1\0" || target || key_id`. `mbtool revoke --key
  <revocation key> --keyid <id> --target <chip>` makes it and sends it (the
  board's `keys` command lists the ids); `--print` only prints it.
- Revocation keys are their own set. Keep them offline: an image key, leaked
  or not, can't revoke anything.
- The revocation goes into the protected store (append-only, next to the
  rollback floors), so it needs one: nRF with `PROTECTED_FLOOR`, or a
  two-stage build. From then on every signature check (images, and stage-1
  copies in two-stage builds) skips that key.
- A board never revokes the last trusted key of a kind (image keys, stage-1
  keys): nothing could be signed for it again.
- Images signed only by the revoked key stop booting when signatures are
  required. Re-sign and install them with another key first. Without
  required signatures a revocation protects nothing (an unsigned image boots
  anyway); the configurator warns.
- It holds against the app where the store is locked (nRF). On chips without
  a runtime lock a compromised app could erase the store and with it the
  revocation; there it is an operator's tool, not a defence against the app.
  A board built without `REVOKE_KEYS` ignores revocation entries altogether,
  so an app can't plant one.

## Encrypted images

With `ENCRYPTED_IMAGES` an update file can be kept private on its way to the
board. The scheme is MCUboot's, so imgtool and MimiBoot agree on it:

- The payload is encrypted with AES-128 or AES-256 in counter mode, under a
  fresh random key for each image. The counter block is 12 zero bytes and
  the big-endian block number, counted from the start of the payload.
- That key travels in an envelope for the board (ECIES-X25519, MCUboot's TLV
  0x33). The envelope holds an ephemeral X25519 public key, an HMAC-SHA256
  tag, and the AES key encrypted with a zero counter. Both keys come from
  HKDF-SHA256 with no salt and the info string `MCUBoot_ECIES_v1`.
- In a MimiBoot image file the envelope sits right after the 256-byte header,
  in the header sector. The header's `MB_IMG_F_ENCRYPTED` flag says it is
  there.
- The hash and the signature cover the plaintext, so a signed and encrypted
  image is checked exactly like a signed one.

`mbtool keygen --type x25519` makes a board key: `board.key` goes into the
build as `ENC_KEY`, and `mbtool pack --encrypt board.pub` encrypts for it.

MimiBoot decrypts while the image comes in, over the console (`mbtool
install`) or SMP:

- The envelope is opened and its tag checked before the slot is erased. An
  image made for another board, or a damaged envelope, is refused with the
  old image still in place.
- Tampered ciphertext decrypts to the wrong payload. It fails the hash at the
  end and leaves the slot empty, as any bad upload does.
- Slots hold plaintext, as MCUboot's primary slot does.

**What this protects:** update files, the link they travel over, and anywhere
the files sit before they reach the board.

**What it doesn't protect:**

- **The chip's flash.** The decryption key is compiled into the bootloader, so:
  - every board built from the same binary shares it;
  - whoever has `mimiboot.bin`, or the build folder with its generated
    config header, has the key;
  - on a chip whose debug port is open, a probe reads the key and the
    decrypted images.

  Lock the debug port (`DEBUG_LOCK` on nRF; read protection from `mbtool
  provision` on the others). The configurator warns when you haven't.
- **The app.** On chips without a runtime read lock, a running app can read the
  key from the bootloader's flash.
- **Anyone at the console.** The `md` memory dump would hand out a decrypted
  image, so the configurator refuses `SHELL_DIAG` without `CONSOLE_AUTH`.

**Limits:**

- Only MimiBoot's console and SMP decrypt. The client library refuses
  encrypted images, because an app would need the key.
- An imgtool-encrypted Zephyr image isn't taken into a slot either: its
  envelope comes after the payload, so it can't be opened before the slot is
  written. The envelope format is the same, though, and the tests check
  MimiBoot's decryption against envelopes imgtool made.
- Stage-1 images can't be encrypted, because stage 0 has no key.
- `ramboot` takes encrypted RAM images and decrypts them into RAM.

On the device, AES is BearSSL's constant-time bitsliced code (MIT, adapted to
encryption only). X25519 is a Montgomery ladder on the same field arithmetic
as Ed25519: branch-free, a fixed 255 steps, conditional swaps by mask. An
all-zero shared secret (a low-order point) is refused. The tag is compared in
constant time.

Being branch-free isn't the same as taking constant time. It also depends on
the multiply instructions:

- **Cortex-M0/M0+:** the 64-bit multiplies are libgcc calls built from `MULS`,
  with no data-dependent branches.
- **Cortex-M4/M7/M33:** `UMULL` and `UMLAL` take a fixed number of cycles.
- **Cortex-M3 (STM32F1, F2):** `UMULL` and `UMLAL` finish early when the
  operands are small (Arm's Cortex-M3 Technical Reference Manual, instruction
  timing). The field multiply's 16-bit limbs sit right at that edge, so how
  long a key check takes depends on the board's key.

So on a Cortex-M3 the configurator requires `CONSOLE_AUTH` with encrypted
images: only someone who has unlocked the console can send envelopes to time.

## Updating the bootloader itself (two-stage)

A one-stage MimiBoot can't replace itself: a bug in it is fixed with a debug
probe. With `TWO_STAGE` it is split in two:

- **Stage 0**, at the start of flash: about 10 KB, never updated in the field.
  It reads the two stage-1 copies, checks them, keeps a few records in the
  store at the end of its region, and starts one. No console, no uploads.
- **Stage 1**, the whole bootloader you know (console, uploads, A/B, configs),
  in two copies, `s1a` and `s1b`. Each copy is a MimiBoot image linked for its
  own slot and flagged as a stage 1 (`MB_IMG_F_STAGE1`, inside the signed
  bytes).

A new stage 1 goes into the copy that isn't running (`mbtool loader <build
dir>`, which asks the board which one runs). On the next boot, stage 0 starts
a copy only if all of this holds:

- the header is sound, it is a stage 1 for this chip, and it is linked for that
  slot (the header says so, and the payload's reset vector agrees);
- its security version is at or above the stage-1 floor;
- it is signed by one of `S1_KEYS` (required when signatures are required).
  These are separate from the app keys: an app signing key that leaks can't
  replace the bootloader;
- its hash matches.

Then, between two usable copies: one that hasn't failed, then the higher
version, then one known to work. A copy is known to work once it has got as
far as starting an image (it writes that into the store just before the
launch). A copy that hasn't yet is on trial: every boot of it is recorded
before it runs, and after 3 boots without getting that far it is passed over
and the other copy starts. Once a copy with security version N has worked, no
copy below N starts again.

Stage 0 is built so its own records can't brick the board:

- with one usable copy it starts it, trial or not, and records nothing (a board
  left at the menu with no app doesn't fill the store);
- if every usable copy has failed, the best of them starts anyway;
- if a trial boot can't be recorded (store full, write failed), the trial
  doesn't start: the copy known to work does.

What it doesn't do:

- **No watchdog in stage 0.** On most of these chips a watchdog can't be stopped
  or slowed once it runs, so it would follow stage 1 into the app. A stage 1
  that faults resets itself (the fault handler); one that hangs is counted by
  power cycles.
- **The store is finite.** It is append-only, one erase unit (4 KB: 256 entries
  of 16 bytes). A stage-1 update costs at most 5 entries (3 boots, "it works",
  a floor). Boot counting stops 8 entries short of full so floors still fit.
  Nothing erases the store in the field yet, so after about 50 stage-1 updates
  new copies start without trials.
- **A stage-1 copy that is damaged, unsigned or below the floor is skipped, not
  repaired.** If both are unusable, stage 0 has nothing to start: STM32 parts
  fall into their ROM loader, others wait for a debug probe.
- **Without a runtime lock the copies are the app's to erase.** On nRF,
  `BOOT_LOCK` write-protects stage 0, the store and both copies before the app
  starts. On STM32 and SAM D, `mbtool provision` locks stage 0's code for good
  but has to leave the store and the copies writable, because the bootloader
  writes them. A compromised app there can erase both copies (the board then
  needs the ROM loader or a probe) or add records to the store (it can make
  stage 0 skip an update, or use up the store); it can't make stage 0 start
  anything that isn't signed and above the floor.

Two-stage builds need about 100 KB for stage 0 and the two copies, so parts
with 192 KB of flash or more. On STM32 F4/F7, whose sectors grow to 128 or
256 KB, every region takes whole sectors: there it fits A/B but not A/B plus
golden.

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

- On nRF the lock also covers the golden (recovery) slot (`LOCK_GOLDEN`, on by
  default with `BOOT_LOCK` and an A/B + golden layout), so a compromised app
  can't erase what the board falls back to. New golden images go in through
  MimiBoot's own upload, which runs before the lock.
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

### mcumgr (SMP)

With `SMP` on, the same UART also speaks the Simple Management Protocol, so
Zephyr's tools (mcumgr, smpmgr, smpclient) can list, upload, test, confirm and
erase images. It is the console by another route, and held to the same rules:

- Uploads are checked exactly as `recv` checks them (target, signature,
  stage-1 rules, the hash), and the image's header is written last, so an
  upload that stops halfway leaves an empty slot.
- It never writes golden (mcumgr has no `force`), never the stage 1 that is
  running, and never erases the active, confirmed A/B image.
- With `CONSOLE_AUTH` and the console locked, every write is refused (access
  denied). Unlock first with `mbtool --unlock-key`; reading, echo, the
  parameters and reset still work while locked.
- SMP itself has no authentication. A board that accepts unsigned images
  accepts them over SMP too: require signatures on anything that ships.

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
| Ed25519 (RFC 8032) | image signatures, console unlock, signed config |
| ECDSA P-256 (FIPS 186, `ECDSA`) | image signatures: MimiBoot images and imgtool `ecdsa-p256` Zephyr images |
| SHA-256 | payload hashes, the digest ECDSA signs; Ed25519 uses SHA-512 internally |
| X25519 (RFC 7748), HKDF / HMAC-SHA256 (RFC 5869 / 4231), AES-128/256-CTR (FIPS 197, SP 800-38A) | encrypted images (`ENCRYPTED_IMAGES`): MCUboot's ECIES-X25519 envelope |
| CRC-32 | corruption checks only (headers, log, config, upload frames, the Lite core): not a security mechanism |

Ed25519 isn't on the EU's ECCG agreed-mechanisms list (ECDSA P-256 and LMS
are); ETSI TS 119 312 recommends it. The verifier is tested against RFC 8032's
vectors and all 210 of Project Wycheproof's: every valid signature verifies,
every invalid one (malleable S, non-canonical encodings, truncated or padded
signatures, wrong keys) is refused. Of the 29 cases Wycheproof leaves to the
implementation (small-order and mixed-order public keys), all are accepted:
the check is cofactorless. That matters only when an attacker picks the
public key, and here the keys are compiled in.

ECDSA P-256 is on the ECCG list. The arithmetic is micro-ecc v1.2 (BSD 2-clause,
`third_party/micro-ecc`, unmodified, portable C). Against Wycheproof's 262 P-256
vectors every invalid signature is refused and every valid one accepted except
two: signatures built so that micro-ecc's combined multiplication passes through
the point at infinity (tcId 60) or an extreme intermediate value (tcId 210).
Those are false rejects, never false accepts, and an honest signer hits them
with probability about 2^-256; the test pins them so any change shows. mbtool's
own P-256 signer (`tools/mb_p256.py`, RFC 6979 deterministic nonces) gets all
262 right and matches RFC 6979's published test vector. LMS support is planned.

The encryption primitives are checked against their published vectors:
- FIPS-197 for AES-128 and AES-256;
- SP 800-38A for CTR, both key sizes, also fed in odd-sized pieces;
- RFC 4231 for HMAC, including a key longer than the block;
- RFC 5869 for HKDF;
- RFC 7748 for X25519: both function vectors, the Diffie-Hellman example, and
  1 and 1000 iterations.

Each vector was also run through pyca/cryptography before it went into the
tests. Envelopes made by imgtool (AES-128 and AES-256) and by mbtool open on
the device code, and every flipped envelope byte is refused. mbtool's own
implementation (`tools/mb_enc.py`, plain Python) is checked against
pyca/cryptography and imgtool.

The AVR Lite core does no cryptography at all.

## Glitches (fault injection)

With `FAULT_HARDENING` (on by default):

- The payload hash and the last step of the signature check are compared in
  constant time, twice, the second time with the arguments swapped.
- Each check that passes leaves a token in the slot's state: a fixed 32-bit
  value for "signature verified", another for "unsigned and allowed", another
  for "hash matched". A skipped branch leaves no token; a flipped bit leaves a
  wrong one.
- Right before the jump, `mb_boot()` looks at the tokens again (required
  signatures need the "verified" token, every-boot hashing needs the hash
  token) and re-checks the rollback floor, each condition twice. Console RAM
  uploads get the same treatment.

So skipping one check is no longer enough: the glitch has to land twice, at
two places in the code. That raises the bar; it isn't glitch-proof. Real
resistance needs the chip's own countermeasures (and a random delay, which
needs a hardware RNG: not yet).

## Known gaps

- **Fault injection.** See above: hardened, not immune.
- **Self-update needs `TWO_STAGE`.** A one-stage build can't replace itself in
  the field. With two stages, stage 0 itself still can't be: keep it small and
  get it right before the boards ship.
- **Untested on hardware.** The nRF locks, the debug lock and the RNG have run
  only in the emulator (RNG, flash) or not at all (BPROT, ACL, APPROTECT).
- **The boot config** (boot order, arguments) is protected by a CRC only,
  unless `CFG_SIGNED` is on (it is in the `secure` preset): then a config counts
  only with an Ed25519 signature from one of `KEYS` over its text, the target
  and a version, and anything else is ignored in favour of the built-in
  entries. An older signed config can't come back where the protected floor
  store exists (nRF); elsewhere a replayed older signed config would still be
  accepted.
- **Key revocation needs a protected store.** `REVOKE_KEYS` works on nRF
  (`PROTECTED_FLOOR`) and in two-stage builds; elsewhere a leaked key is
  dealt with by building and installing a bootloader without it.
- **RP2350 secure boot isn't automated.** It means burning OTP, which can't be
  undone; `mbtool provision` points at the datasheet instead of printing
  steps.
- **Encryption covers the way in, not the flash.** With `ENCRYPTED_IMAGES`,
  update files and links are private. Slots hold plaintext, and the key is only
  as safe as the bootloader's flash (see above).
- **No measured boot or attestation.**

## Reporting a problem

Open an issue on the repository. For something you'd rather not post in
public, say so in a short issue without the details and ask for a private
channel.
