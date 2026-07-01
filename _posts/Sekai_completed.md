---
title: "Chibile - SEKAI CTF 2026 Write-up"
date: 2026-07-1 6:00:00 +0200
categories: [CTF Writups]
tags: [reverse engineering, game hacking, kernel]
description: "Write-up for Chibile challenge SEKAI CTF 2026 "
image:
  path: /assets/img/sekai/cover.jpg
  alt: cover image
---

# Greetings

Hello everyone! Hope you are doing great.

Recently, I participated with **0xL4ugh - Free Palestine** in **SEKAI CTF
2026**, and I wanted to share my solution to the **Chibile** challenge, which
I found fun to solve.

My intent while solving the challenge was to solve it and bypass the
anti-cheat without debugging it, so this write-up isn't a full reversing
session for all the challenge binaries. It's more like a solution that allowed
me to cheat in the game with minimal reversing.

## Overview

The handout includes six files:

1. The game PE file
2. A launcher that launches both the anti-cheat and the game
3. A DLL file related to the anti-cheat
4. A kernel driver file for the anti-cheat
5. A Markdown file
6. `raylib.dll`, which is related to the game handlers


![](</assets/img/sekai/files.png>)

## Launcher Analysis

I started by analyzing the launcher binary since it has some strings that
indicate initial checks on the environment, such as checking for debuggers,
packet-capturing tools, etc.


![](</assets/img/sekai/Debugger_check.png>)



The main function first decrypts two strings, which are the anti-cheat file
names (`eac_shield.sys` and `eac_nocrt.dll`), checks its privileges, and
elevates if it is not running as administrator.

Then it starts the GUI window creation by loading the icon and creating the
splash window.

The more important part is the following: the launcher takes a snapshot of all
running processes and, for each running process, compares the executable name
against a global list containing the names of debuggers and packet-capture
tools.

If a process matches one of the listed names, the launcher raises an error
string in the window and exits.

After that, it calls a function that enumerates active kernel and file-system
driver services and checks them against hardcoded strings like `npf`,
`npf_wifi`, `Pcap`, and other blacklisted services. If one matches, it also
raises an error and exits.

If no debugger or packet-capture tool is present, the launcher checks the files
needed to launch the game, starting with the game file itself, `chibile.exe`,
then the anti-cheat DLL, `eac_nocrt.dll`, the kernel driver,
`eac_shield.sys`, and finally `raylib.dll`.


![](<assets/img/sekai/Files_check.png>)

It then verifies that the anti-cheat DLL can load, installs the kernel driver,
and starts it with the service name `EacShield`.


After starting the driver, it performs a communication/health check by sending
 16-byte input through IOCTL `0x22E008`:

The input consists of 64-bit value
`0xDEADBEEF12345678` followed by a zero 64-bit value. The launcher checks that
the IOCTL succeeds and that the returned value is nonzero.

Then it enforces a single instance by trying to create a mutex with the name
`Global\CHIBILE_SINGLE_INSTANCE`. If the mutex already exists, it exits with
an error.

Before launching the game, it checks the integrity of the files by computing
the **SHA-256** hashes of `chibile.exe`, `eac_nocrt.dll`, `eac_shield.sys`,
and `raylib.dll`, and comparing them against hardcoded hashes.


![](<assets/img/sekai/Hashes.png>)

It then calls a routine that uses the `BCryptGenRandom` API to generate a
32-byte random value. It sends the raw value to the kernel driver through
IOCTL `0x22E018`, converts the same value to 64 lowercase hexadecimal
characters, and passes it as an argument to the game executable. This
indicates that the value acts like a launch token shared between the launcher,
kernel driver, and game.

After the game is launched, the launcher stores the game process handle and
enters a wait loop until the game terminates.

## Game Logic

Executing the game gives you an image of an anime character and asks you to
enter its name within a period of time. The further you get in the rounds, the
less time you get to answer.


![](<assets/img/sekai/Game1.png>)

So, the first problem I faced was the allowed time provided to answer the
quiz.

Inspecting the game loop, we can find that one function is a wrapper for
`sprintf`. One of its calls has a float format string, which indicates that
the next argument is the remaining time being printed in the game. That
argument is the maximum value between zero and a structure field containing
the remaining time.


![](<assets/img/sekai/time.png>)

Tracing this structure field, the game also draws the time bar by clamping a
value between zero and one. It takes the minimum between one and the remaining
time divided by another structure field, so that other field must be the
starting time, which is the time limit.


![](<assets/img/sekai/Time_2.png>)

Showing global XRefs of the time-limit field, it is initialized from a global
array with the values:

```text
10.0, 5.0, 3.0, 2.0, 1.0, 0.7, 0.5, 0.3, 0.2, 0.1
```

These are impossible to solve the quizzes in.


![](<assets/img/sekai/Xref_time.png>)

From the previous analysis, the launcher only validates the hash of the game
executable against a hardcoded value, which is easy to bypass. I couldn't find
any obvious static check in the kernel driver that validates the
launcher hash, although I didn't dig deeply into the kernel driver.

So, I patched all the float values of the time limit to `100.0` and then
patched the hash of the game executable in the launcher with the new hash.

I tried to execute the launcher, and the game worked, which is a good sign that
the patched launcher was not checked by the AC.

The second problem I faced was my anime knowledge (harder than reversing).

Solving this problem was easier, as the strings revealed the offset of the
character table, which includes the characters' names and images.

So, I patched them all to **K1R1TOO**, making the quizzes much easier to
solve.


![](<assets/img/sekai/K1r1too.PNG>)

After solving the ten rounds, the game asks for a secret phrase (cheat code).


![](<assets/img/sekai/Secret.png>)

Finding the function that produces the secret phrase wasn't that hard either.

Using the string **SECRET ROOM UNLOCKED**, I found the validator that validates
the input against a decoded string.


![](<assets/img/sekai/Validation_secret.png>)

It decrypts the secret phrase using a small VM that has only three relevant
opcodes:

| Opcode | Function |
| --- | --- |
| `0x31` | Update a rolling state |
| `0x52` | Write one byte into the output buffer |
| `0x7F` | Return |


![](<assets/img/sekai/VM_from inside.png>)

The bytecode is decrypted through a rolling state machine that depends on the
seed derived from the fifth argument passed to the function.

The logic of the VM can be emulated, but we first need to get the seed used to
decrypt the bytecode. Since the fifth argument points to material made from
three fields of the game structure, we can follow their XRefs to find where
they are initialized.

Doing so led to the initialization function, which generates the seed material
based on:

1. The string `"CHIBILE-GATE-V1"`
2. A SHA-256 hash of the executable's first code section
3. The constant `"GenuntelineI"`

`GenuntelineI` is the exact byte sequence used by the game; it is not a typo
for `GenuineIntel`.

More precisely:

```text
seed_material = HMAC-SHA256(
    key = "CHIBILE-GATE-V1",
    message = SHA256(first code section) || "GenuntelineI"
)

seed = LE32(seed_material[0:4])
```

The selected section is the first PE section whose characteristics contain
`IMAGE_SCN_CNT_CODE` (`0x20`). It is hashed as `VirtualSize` bytes, with
zero-padding if `VirtualSize` is larger than `SizeOfRawData`.

Now we have the seed, so we can decrypt the VM bytecode and emulate it to get
the secret phrase.

I used this script to derive the seed:

```python
import sys, struct, hashlib, hmac

path = sys.argv[1]

with open(path, "rb") as f:
    pe = f.read()

e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
num_sections = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size

code = None

for i in range(num_sections):
    off = sec_off + i * 40

    virtual_size = struct.unpack_from("<I", pe, off + 8)[0]
    raw_size     = struct.unpack_from("<I", pe, off + 16)[0]
    raw_ptr      = struct.unpack_from("<I", pe, off + 20)[0]
    chars        = struct.unpack_from("<I", pe, off + 36)[0]

    if chars & 0x20:
        code = pe[raw_ptr : raw_ptr + min(virtual_size, raw_size)]
        code += b"\x00" * max(0, virtual_size - raw_size)
        break

if code is None:
    code_hash = b"\x00" * 32
else:
    code_hash = hashlib.sha256(code).digest()

msg = code_hash + b"GenuntelineI"

seed_material = hmac.new(
    b"CHIBILE-GATE-V1",
    msg,
    hashlib.sha256
).digest()

seed = struct.unpack("<I", seed_material[:4])[0]

print("code_hash     =", code_hash.hex())
print("seed_material =", seed_material.hex())
print("decode_seed   = 0x%08X" % seed)
print("decimal       =", seed)
```

Now we have the seed, so we can emulate the VM logic to get the secret phrase:

```python
def rol32(x, r):
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


BLOB_HEX = """
35d8b7224ddb0821dda2c7bb8b8054fb2c3e02a6c192276d9c3a340392a32aa8
841cc39cf2ecee02206b5260e69418c2fb2a16c399812d85112ab905e0145855
da24e4658178c480372e53f9266136596370fe29a7861ed6ea8fbf7e175edfd1
44eb65a19b805be9753ed7a66c4098ef88303d44c8f397ec45f9d708e9fbe9dc
4f6cc396d1d68e1ba7ac59c5a448cf3062a121c2f9b95e90c0d15d0f4aa501f1
4c8f6b6257f81d8cf361d847c6d211303124298e7c8798c09565a7d8facf1780
8e3579abebcbcc80348c20a0c434b33ed140612274df4ce50db5d21b7f3e3900
d5d05d7df789c54d6c6ce7449b335f5cc8b89d824b549ea0466c3857a45115b2
6b07089ff5902e3185e7dbeb92b21869ce9fefa78f87a191fab949dafa7528f9
7d92eefb7c1476f648a226f6e3d46fd6c46debfa2f04932674db3baeb523a435
298852526914401a047800000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
"""

blob = bytes.fromhex(BLOB_HEX)

seed32 = 0x938D9281

OUT_LEN = 73


def next_vm_byte(pc, state_a, state_b):
    tmp = (
        (state_a ^ (state_a >> 16))
        + 12345
        + 1103515245 * state_b
    ) & 0xFFFFFFFF

    decoded = (
        blob[pc]
        ^ ((state_a >> 8) & 0xFF)
        ^ ((tmp >> 24) & 0xFF)
        ^ ((61 * pc) & 0xFF)
    ) & 0xFF

    state_a = rol32(tmp + state_a + decoded, (decoded & 7) + 1)
    state_b = tmp

    return decoded, state_a, state_b, tmp


def decode_vm():
    out = bytearray(OUT_LEN)

    acc = 0x85EBCA6B
    state_a = (seed32 - 0x61C88647) & 0xFFFFFFFF
    state_b = seed32 ^ 0x7F4A7C15

    pc = 0

    while pc < len(blob):
        op, state_a, state_b, _ = next_vm_byte(pc, state_a, state_b)
        pc += 1

        if op == 0x7F:
            break

        elif op == 0x31:
            b0, state_a, state_b, _ = next_vm_byte(pc, state_a, state_b)
            pc += 1
            b1, state_a, state_b, _ = next_vm_byte(pc, state_a, state_b)
            pc += 1
            b2, state_a, state_b, _ = next_vm_byte(pc, state_a, state_b)
            pc += 1
            b3, state_a, state_b, _ = next_vm_byte(pc, state_a, state_b)
            pc += 1

            imm = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

            acc = rol32(
                ((acc ^ imm) + 0x045D9F3B) & 0xFFFFFFFF,
                ((imm >> 27) & 7) + 3
            )

        elif op == 0x52:
            index, state_a, state_b, tmp_index = next_vm_byte(
                pc, state_a, state_b
            )
            pc += 1

            encoded_value, state_a, state_b, _ = next_vm_byte(
                pc, state_a, state_b
            )
            pc += 1

            if index < OUT_LEN:
                out[index] = (
                    encoded_value
                    ^ ((17 * index) & 0xFF)
                    ^ ((tmp_index >> 16) & 0xFF)
                    ^ ((acc >> (8 * (index & 3))) & 0xFF)
                ) & 0xFF

        else:
            raise RuntimeError(f"Invalid VM opcode {op:#x} at pc={pc - 1:#x}")

    return bytes(out)


decoded = decode_vm()

phrase = bytes(
    (0xD7 ^ decoded[i] ^ ((23 * i - 93) & 0xFF)) & 0xFF
    for i in range(len(decoded))
)

print("VM output:", decoded.hex())
print("Phrase:   ", phrase.decode())
```

So, the phrase is:

```text
CONGRATS, YOU FOUND SOMETHING! TWEET AT @0XN*** AND MENTION THIS MESSAGE.
```


![](<assets/img/sekai/Secret_room_phrase.png>)

After the game successfully gets to the secret room, it connects to a server
and sends an encrypted JSON message with this format:

```json
{
  "phase": 1,
  "nonce": "...",
  "um_attest": "...",
  "km_attest": "...",
  "pid": 1234,
  "ts": 0,
  "client_build": "CHIBILE-R3-20260615"
}
```


![](<assets/img/sekai/write_instruction.png>)

It waits for the server to respond and then decrypts the response.

My target was to get the server response for the first phase so I could obtain
the kernel-mode and user-mode values.

The problem was that I couldn't capture the packet using the usual tools or
debug the game in user mode.

## Phase 1 Solution

My aim was to dump the decrypted server response without using debuggers or
any kind of packet capture. My first thought was that solving this challenge
would require kernel debugging or a kernel-based cheat.

But I had an idea: if the packet, after being decrypted, is passed as an
argument to an API function, I can use a proxy DLL with a wrapped API to dump
the argument being passed to it, which is the decrypted packet.

Searching for the API, I found two APIs that I could use. The first one is
`memcpy`, which is used after checking and skipping the `CBM1` response
header, and the second one is `free`.


![](<assets/img/sekai/MEMCPY.png>)

So, all I had to do was make a DLL whose `memcpy` export dumps the data pointed
to by the second argument, using the length, and writes it to a file.

To avoid dumping data every time `memcpy` is called, which could result in a
huge amount of data, I added a check for whether the top of the stack holds the
return address of the targeted `memcpy` call. If it matches, the wrapper dumps
the data; otherwise, it calls the original `memcpy` function normally.

So, I made a `VCRUNTIME140.dll` proxy that forwards its exports to a renamed
copy of the original `VCRUNTIME140.dll`. Whenever any export other than
`memcpy` is called, it is forwarded to the original DLL. The `memcpy` wrapper
checks the RVA of the return address, and if it matches `0xA233`, it dumps the
memory pointed to by the second argument using the copy length, then calls the
original `memcpy`.


![](<assets/img/sekai/Memcpy_hook.png>)

At this call site, the source points to the plaintext JSON immediately after
the four-byte `CBM1` header.

The dumped response was a normal JSON object containing the session id and two
encrypted secret blobs:

```json
{
  "sid": "...",
  "c_um": "...",
  "lh_um": "...",
  "c_km": "...",
  "lh_km": "..."
}
```


![](<assets/img/sekai/Dump.PNG>)

The `sid` value is used later in phase 2. The other four fields are used to
recover the two values that the game asks for in the secret room.

## Secret Delivery

Now the game asks for two values:

1. USER MODE variable value
2. KERNEL MODE variable value



After entering both values, the game builds another encrypted JSON request:

```json
{
  "phase": 2,
  "nonce": "...",
  "sid": "...",
  "typed_um": "...",
  "typed_km": "...",
  "ts": 0,
  "client_build": "CHIBILE-R3-20260615"
}
```

So, the final missing part is deriving `typed_um` and `typed_km` from the
phase 1 response.

For each secret, the response gives two values:

- `LH`: the `lh_*` value
- `C`: the `c_*` value

The binary also has a baked half-key for user mode, while the kernel side uses
the baked kernel half-key. I used the following values:

The user mode dll is encrypted/packed so you'd need to unpack it and decrypt
it in the runtime

![](<assets/img/sekai/first_block_decrypt.png>)


![](<assets/img/sekai/Anti_emulation.png>)

After that you can dump the decrypted dll. 

![](<assets/img/sekai/Dump_dll.png>)
 

```python
BK_USER = bytes.fromhex(
    "9a47d31eb8056cf283217eca4d901b66"
    "5fe80ab377c429d13ca6528b14ff9d70"
)

BK_KERNEL = bytes.fromhex(
    "4e912cd763ba18ef057ac3398651fd20"
    "a8146dbf429ed037cb60851cf32974ae"
)
```


![](<assets/img/sekai/Usermode_bk.png>)


![](<assets/img/sekai/KERNEL_BK.png>)

Here, `BK_KERNEL` is the baked key used by the secret-delivery logic. It should
not be confused with the runtime `bk` intermediate used while generating the
`km_attest` field.

The secret derivation is:

```text
DK    = HMAC-SHA256(BK, LH)
KS(b) = HMAC-SHA256(DK, tag || u32le(b))
```

For user mode, the tag is `UM-KS`:

```text
S[i] = rotl8(C[i] ^ KS(i // 32)[i % 32], 3) ^ BK[i % 32]
```

For kernel mode, the tag is `KM-KS`:

```text
S[i] = rotr8(C[i] ^ DK[(i * 7) % 32], 3) ^ KS(i // 32)[i % 32]
```

Each result is a 12-character string using this alphabet:

```text
ABCDEFGHJKLMNPQRSTUVWXYZ23456789
```

I used this script to recover both values from the dumped phase 1 response:

```python
import sys
import json
import hmac
import hashlib
import struct

BK_USER = bytes.fromhex(
    "9a47d31eb8056cf283217eca4d901b66"
    "5fe80ab377c429d13ca6528b14ff9d70"
)

BK_KERNEL = bytes.fromhex(
    "4e912cd763ba18ef057ac3398651fd20"
    "a8146dbf429ed037cb60851cf32974ae"
)


def hx(s):
    return bytes.fromhex(s)


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def rotr8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xFF


def h(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def ks(dk, tag, block):
    return h(dk, tag + struct.pack("<I", block))


def dec_user(bk, lh, c):
    dk = h(bk, lh)
    out = []

    for i, x in enumerate(c):
        stream = ks(dk, b"UM-KS", i // 32)
        out.append(rotl8(x ^ stream[i % 32], 3) ^ bk[i % 32])

    return bytes(out).decode()


def dec_kernel(bk, lh, c):
    dk = h(bk, lh)
    out = []

    for i, x in enumerate(c):
        stream = ks(dk, b"KM-KS", i // 32)
        out.append(rotr8(x ^ dk[(i * 7) % 32], 3) ^ stream[i % 32])

    return bytes(out).decode()


p = json.load(sys.stdin)

typed_um = dec_user(BK_USER, hx(p["lh_um"]), hx(p["c_um"]))
typed_km = dec_kernel(BK_KERNEL, hx(p["lh_km"]), hx(p["c_km"]))

print("sid      =", p["sid"])
print("typed_um =", typed_um)
print("typed_km =", typed_km)
```

Usage:

```bash
python solve_phase1.py < phase1_dump.json
```

![](<assets/img/sekai/runn.PNG>)

After getting the two strings, I pasted the first one into the USER MODE input
and the second one into the KERNEL MODE input.

The game then sent the phase 2 request by itself, using the same encrypted
transport layer. If the values are correct, the server response is decrypted
and passed to `LoadImageFromMemory` as a PNG image. That image is what gets
shown in the final `ACCESS GRANTED` screen.


![](<assets/img/sekai/winner.PNG>)

So the final flow was:

1. Patch the game time limits.
2. Patch all character answers to `K1R1TOO`.
3. Recover the secret-room phrase from the VM.
4. Use a proxy `VCRUNTIME140.dll` to dump the decrypted phase 1 response.
5. Derive `typed_um` and `typed_km` from `c_um`, `lh_um`, `c_km`, and `lh_km`.
6. Enter both values in the game.
7. Let the game send phase 2 and receive the final flag image.

## Conclusion

As I said at the start, this was my solution with intent to avoid any kernel debugging or writing kernel driver to bypass the anti-cheat. 
I was reversing only the parts which I needed to solve the challenge, not the whole process. 

And finally, Thank you for reading and I hope you found it helpful.

If you have any questions or comments, feel free to contact me on [linkedin][linkedin] or [discord][discord]

[linkedin]: https://www.linkedin.com/in/karim-esam-527121358/
[discord]: https://discord.com/users/688927082960650297
