"""
Finder.py - Redragon K582 Surara LED Address Calibration Tool
=============================================================
Author: Alastar
Project: K582 Open Source RGB Controller
License: Open Source

Protocol (reverse engineered via Wireshark):
  VID: 0x320F  PID: 0x5000  Interface: 1 (col04 path)
  Packet (64 bytes, no report ID byte):
    START:  04 01 00 01 00 00 ... (64 bytes)
    DATA:   04 <csum_lo> <csum_hi> 11 03 <key_id> 00 00 <R> <G> <B> 00...
    COMMIT: 04 02 00 02 00 00 ... (64 bytes)
  Checksum: sum(data[3:]) & 0xFFFF, split lo/hi into bytes 1/2

  key_id: single byte (0x00-0xFF) identifying the LED address
  Known mappings: ESC=0x00, W=0x84, A=0xC0, H=0xCF

Calibration Passes:
  Pass 1 - Discovery : Scan all 256 key IDs. Light white, user confirms.
                       Blue = single key mapped. Red = conflict (multiple keys).
                       Red resolution sub-phase clears conflicts.
  Pass 2 - Verification : Batches of 5 keys lit white. User presses Y/N.
                           Y key = bright green. Confirmed batch = dark green.
"""

import hid
import json
import time
import os
import sys
import ctypes
import ctypes.wintypes
import keyboard

# ─────────────────────────────────────────────
# Device constants
# ─────────────────────────────────────────────
VID            = 0x320F
PID            = 0x5000
IFACE_INPUT    = 0

GENERIC_WRITE  = 0x40000000
OPEN_EXISTING  = 0x3
FILE_SHARE_READ  = 0x1
FILE_SHARE_WRITE = 0x2

# ─────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────
WHITE      = (255, 255, 255)
BLUE       = (0,   0,   255)
RED        = (255, 0,   0  )
GREEN_YES  = (0,   255, 0  )   # Y key during Pass 2
GREEN_CONF = (0,   90,  0  )   # Confirmed key in Pass 2
OFF        = (0,   0,   0  )

# ─────────────────────────────────────────────
# HID usage code -> key name (keyboard library compatible)
# ─────────────────────────────────────────────
HID_KEY_MAP = {
    0x04: "a",        0x05: "b",        0x06: "c",        0x07: "d",
    0x08: "e",        0x09: "f",        0x0A: "g",        0x0B: "h",
    0x0C: "i",        0x0D: "j",        0x0E: "k",        0x0F: "l",
    0x10: "m",        0x11: "n",        0x12: "o",        0x13: "p",
    0x14: "q",        0x15: "r",        0x16: "s",        0x17: "t",
    0x18: "u",        0x19: "v",        0x1A: "w",        0x1B: "x",
    0x1C: "y",        0x1D: "z",
    0x1E: "1",        0x1F: "2",        0x20: "3",        0x21: "4",
    0x22: "5",        0x23: "6",        0x24: "7",        0x25: "8",
    0x26: "9",        0x27: "0",
    0x28: "enter",    0x29: "esc",      0x2A: "backspace", 0x2B: "tab",
    0x2C: "space",    0x2D: "-",        0x2E: "=",
    0x2F: "[",        0x30: "]",        0x31: "\\",
    0x33: ";",        0x34: "'",        0x35: "`",
    0x36: ",",        0x37: ".",        0x38: "/",
    0x39: "caps lock",
    0x3A: "f1",       0x3B: "f2",       0x3C: "f3",       0x3D: "f4",
    0x3E: "f5",       0x3F: "f6",       0x40: "f7",       0x41: "f8",
    0x42: "f9",       0x43: "f10",      0x44: "f11",      0x45: "f12",
    0x46: "print screen", 0x47: "scroll lock", 0x48: "pause",
    0x49: "insert",   0x4A: "home",     0x4B: "page up",
    0x4C: "delete",   0x4D: "end",      0x4E: "page down",
    0x4F: "right",    0x50: "left",     0x51: "down",     0x52: "up",
    0x53: "num lock", 0x54: "num /",    0x55: "num *",    0x56: "num -",
    0x57: "num +",    0x58: "num enter",
    0x59: "num 1",    0x5A: "num 2",    0x5B: "num 3",    0x5C: "num 4",
    0x5D: "num 5",    0x5E: "num 6",    0x5F: "num 7",    0x60: "num 8",
    0x61: "num 9",    0x62: "num 0",    0x63: "num .",
    0x65: "menu",
    0xE0: "left ctrl",  0xE1: "left shift", 0xE2: "left alt",  0xE3: "left windows",
    0xE4: "right ctrl", 0xE5: "right shift",0xE6: "right alt", 0xE7: "right windows",
}

# Display names for CLI output (uppercase friendly)
HID_DISPLAY_MAP = {k: v.upper() for k, v in HID_KEY_MAP.items()}

CONTROL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Control.json")


# ═════════════════════════════════════════════
# Device helpers
# ═════════════════════════════════════════════

def open_lighting_device():
    for dev in hid.enumerate(VID, PID):
        if b"col04" in dev.get("path", b"").lower():
            path = dev["path"]
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.CreateFileA(
                path,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            if handle == -1:
                raise RuntimeError(f"CreateFileA failed: {ctypes.get_last_error()}")
            return handle
    raise RuntimeError("K582 lighting interface (col04) not found.")


def open_input_device():
    for dev in hid.enumerate(VID, PID):
        if dev.get("interface_number") == IFACE_INPUT and dev.get("usage") == 6:
            d = hid.device()
            d.open_path(dev["path"])
            d.set_nonblocking(1)
            return d
    raise RuntimeError("K582 input interface not found.")


# ═════════════════════════════════════════════
# Packet helpers
# ═════════════════════════════════════════════

def build_packet(key_id, r, g, b):
    """Build a 64-byte DATA packet for a single key colour command."""
    data = [0x04, 0x00, 0x00, 0x11, 0x03, key_id, 0x00, 0x00, r, g, b] + [0x00] * 53
    csum = sum(data[3:]) & 0xFFFF
    data[1] = csum & 0xFF
    data[2] = (csum >> 8) & 0xFF
    return data


def send_colour(handle, key_id, r, g, b):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    written  = ctypes.c_ulong(0)
    start    = (ctypes.c_ubyte * 64)(0x04, 0x01, 0x00, 0x01, *([0]*60))
    data     = (ctypes.c_ubyte * 64)(*build_packet(key_id, r, g, b))
    commit   = (ctypes.c_ubyte * 64)(0x04, 0x02, 0x00, 0x02, *([0]*60))
    for pkt in [start, data, commit]:
        kernel32.WriteFile(handle, pkt, 64, ctypes.byref(written), None)
        time.sleep(0.02)


def send_batch(handle, colour_list):
    """Send multiple key colours atomically: one START, N DATA packets, one COMMIT."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    written  = ctypes.c_ulong(0)

    def write_pkt(pkt_bytes):
        pkt = (ctypes.c_ubyte * 64)(*pkt_bytes[:64])
        kernel32.WriteFile(handle, pkt, 64, ctypes.byref(written), None)

    write_pkt([0x04, 0x01, 0x00, 0x01] + [0x00] * 60)
    for key_id, r, g, b in colour_list:
        write_pkt(build_packet(key_id, r, g, b))
    write_pkt([0x04, 0x02, 0x00, 0x02] + [0x00] * 60)
    time.sleep(0.05)


def init_keyboard(handle):
    """
    Send the full initialisation sequence:
      1. Mode switch to custom lighting (06 01 command)
      2. Double START
      3. Clear all LEDs to black (11 36 packets)
      4. COMMIT
    Must be called before any per-key colour commands will take effect.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def send_raw(pkt_bytes):
        written = ctypes.c_ulong(0)
        pkt = (ctypes.c_ubyte * 64)(*pkt_bytes[:64])
        kernel32.WriteFile(handle, pkt, 64, ctypes.byref(written), None)
        time.sleep(0.02)

    # 1. Mode switch to custom lighting
    send_raw([0x04, 0x01, 0x00, 0x01] + [0x00] * 60)
    send_raw([0x04, 0x1b, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x14] + [0x00] * 55)
    send_raw([0x04, 0x02, 0x00, 0x02] + [0x00] * 60)

    # 2. Double START
    send_raw([0x04, 0x01, 0x00, 0x01] + [0x00] * 60)
    send_raw([0x04, 0x01, 0x00, 0x01] + [0x00] * 60)

    # 3. Clear all LEDs to black (8 packets covering all LED addresses)
    offsets   = [0x00, 0x36, 0x6c, 0xa2, 0xd8, 0x0e, 0x44, 0x7a]
    csum_vals = [0x47, 0x7d, 0xb2, 0xe8, 0x1f, 0x56, 0x8c, 0xc2]
    for offset, csum in zip(offsets, csum_vals):
        hi = 0x01 if csum >= 0x100 else 0x00
        send_raw([0x04, csum & 0xFF, hi, 0x11, 0x36, offset, 0x00, 0x00] + [0x00] * 56)

    # 4. COMMIT
    send_raw([0x04, 0x02, 0x00, 0x02] + [0x00] * 60)


def paint_keyboard(handle, ctrl):
    """Repaint all known keys from Control.json (blue=mapped, red=conflict)."""
    colours = (
        [(int(k, 16), *BLUE) for k in ctrl.get("blue_keys", {})] +
        [(int(k, 16), *RED)  for k in ctrl.get("red_keys",  {})]
    )
    if colours:
        send_batch(handle, colours)


# ═════════════════════════════════════════════
# Control.json helpers
# ═════════════════════════════════════════════

def load_control():
    if os.path.exists(CONTROL_PATH):
        with open(CONTROL_PATH, "r") as f:
            return json.load(f)
    return {
        "calibration_state": "pass1",
        "confirm_key": None,
        "blue_keys": {},
        "red_keys": {},
        "final_map": {},
        "last_addr": -1
    }


def save_control(data):
    with open(CONTROL_PATH, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  [Saved -> {CONTROL_PATH}]")


# ═════════════════════════════════════════════
# Input helpers
# ═════════════════════════════════════════════

MODIFIERS = {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7}


def wait_for_lalt_numenter():
    print("  >> Press lit key(s), then L-ALT + NUM ENTER to confirm...")
    collected = set()
    EXCLUDE = {0xE2, 0x28, 0x58}  # L-ALT, ENTER, NUM ENTER
    time.sleep(0.3)  # debounce before listening
    while True:
        time.sleep(0.02)
        for hid_code, key_name in HID_KEY_MAP.items():
            if hid_code in MODIFIERS or hid_code in EXCLUDE:
                continue
            try:
                if keyboard.is_pressed(key_name):
                    if hid_code not in collected:
                        collected.add(hid_code)
                        print(f"    Detected: {HID_DISPLAY_MAP.get(hid_code, key_name)} (HID 0x{hid_code:02x})")
            except ValueError:
                continue
        if keyboard.is_pressed("left alt") and keyboard.is_pressed("num enter"):
            time.sleep(0.3)  # debounce after
            break
    return collected


def wait_for_confirm_key(confirm_hid):
    confirm_name = HID_KEY_MAP.get(confirm_hid, "")
    print(f"  >> Press lit key(s), then {HID_DISPLAY_MAP.get(confirm_hid, '?')} to confirm...")
    collected = set()
    # Wait for all keys to be released before listening
    time.sleep(0.5)
    try:
        while any(keyboard.is_pressed(name) for name in HID_KEY_MAP.values() if name):
            time.sleep(0.05)
    except ValueError:
        time.sleep(0.3)
    time.sleep(0.1)
    while True:
        time.sleep(0.02)
        for hid_code, key_name in HID_KEY_MAP.items():
            if hid_code in MODIFIERS or hid_code == confirm_hid:
                continue
            try:
                if keyboard.is_pressed(key_name):
                    if hid_code not in collected:
                        collected.add(hid_code)
                        print(f"    Detected: {HID_DISPLAY_MAP.get(hid_code, key_name)} (HID 0x{hid_code:02x})")
            except ValueError:
                continue
        try:
            if confirm_name and keyboard.is_pressed(confirm_name):
                time.sleep(0.5)
                break
        except ValueError:
            pass
    return collected


def wait_for_yn(y_hid, n_hid):
    """Wait for Y or N keypress. Returns True for Y, False for N."""
    y_name = HID_KEY_MAP.get(y_hid, "")
    n_name = HID_KEY_MAP.get(n_hid, "")
    while True:
        time.sleep(0.02)
        try:
            if y_name and keyboard.is_pressed(y_name):
                time.sleep(0.15)
                return True
        except ValueError:
            pass
        try:
            if n_name and keyboard.is_pressed(n_name):
                time.sleep(0.15)
                return False
        except ValueError:
            pass


# ═════════════════════════════════════════════
# PASS 1 — Discovery
# ═════════════════════════════════════════════

def pass1_discovery(ldev, ctrl):
    print("\n" + "="*60)
    print("PASS 1: DISCOVERY")
    print("="*60)
    print("Each key ID will light WHITE one at a time.")
    print("Press the lit key(s), then confirm.")
    print("First confirm: L-ALT + NUM ENTER")
    print("All subsequent: press the first confirmed key")
    print("L-ALT + NUM ENTER at any time to end scan early.")
    print("="*60 + "\n")

    blue_keys   = ctrl.get("blue_keys", {})
    red_keys    = ctrl.get("red_keys", {})
    confirm_key = ctrl.get("confirm_key", None)
    start       = ctrl.get("last_addr", -1) + 1

    if confirm_key is not None:
        print(f"Resuming from key ID 0x{start:02x}")
        print(f"Confirm key: {HID_DISPLAY_MAP.get(confirm_key, '?')} (HID 0x{confirm_key:02x})\n")

    # Initial keyboard setup — only once
    init_keyboard(ldev)
    time.sleep(0.2)
    paint_keyboard(ldev, ctrl)

    for key_id in range(start, 0x100):
        id_str = f"0x{key_id:02x}"

        # Skip already confirmed keys
        if id_str in blue_keys:
            continue

        print(f"Key ID {id_str}  ({key_id + 1}/256)")

        # Paint known state + current key white in one atomic transaction
        colours = (
            [(int(k, 16), *BLUE) for k in blue_keys] +
            [(int(k, 16), *RED)  for k in red_keys]  +
            [(key_id, *WHITE)]
        )
        send_batch(ldev, colours)

        # Wait for user confirmation
        if confirm_key is None:
            pressed_hids = wait_for_lalt_numenter()
        else:
            pressed_hids = wait_for_confirm_key(confirm_key)

        if not pressed_hids:
            print(f"  -> No keys pressed. Skipping.\n")
            ctrl["last_addr"] = key_id
            save_control(ctrl)
            continue

        # Remove confirm key from pressed set if accidentally included
        if confirm_key:
            pressed_hids.discard(confirm_key)

        if len(pressed_hids) == 1:
            hid_code = next(iter(pressed_hids))
            name = HID_DISPLAY_MAP.get(hid_code, f"0x{hid_code:02x}")

            # Check if this key_id was previously red — resolve it
            if id_str in red_keys:
                del red_keys[id_str]

            blue_keys[id_str] = hid_code
            print(f"  -> Mapped: {name} = {id_str} [BLUE]\n")

            # First confirmed key becomes our confirm key
            if confirm_key is None:
                confirm_key = hid_code
                print(f"  [Confirm key set to: {name}]\n")

        elif len(pressed_hids) > 1:
            names = [HID_DISPLAY_MAP.get(h, f"0x{h:02x}") for h in pressed_hids]
            print(f"  -> CONFLICT: {', '.join(names)} = {id_str} [RED]\n")
            red_keys[id_str] = list(pressed_hids)

        ctrl.update({
            "blue_keys":   blue_keys,
            "red_keys":    red_keys,
            "confirm_key": confirm_key,
            "last_addr":   key_id,
            "calibration_state": "pass1"
        })
        save_control(ctrl)

    # ── Red resolution sub-phase ──────────────────────────────
    if red_keys:
        print("\n" + "="*60)
        print("RESOLVING CONFLICTS (RED KEYS)")
        print("="*60)
        print("Watch for a red key to flash WHITE — press it!")
        print(f"Confirm with: {HID_DISPLAY_MAP.get(confirm_key, '?')}\n")

        for id_str in list(red_keys.keys()):
            key_id = int(id_str, 16)
            colours = (
                [(int(k, 16), *BLUE) for k in blue_keys] +
                [(int(k, 16), *RED)  for k in red_keys if k != id_str] +
                [(key_id, *WHITE)]
            )
            send_batch(ldev, colours)
            print(f"Key ID {id_str} — which key lit white?")

            pressed = wait_for_confirm_key(confirm_key)
            pressed.discard(confirm_key)

            if len(pressed) == 1:
                hid_code = next(iter(pressed))
                name = HID_DISPLAY_MAP.get(hid_code, f"0x{hid_code:02x}")
                blue_keys[id_str] = hid_code
                del red_keys[id_str]
                print(f"  -> Resolved: {name} = {id_str} [BLUE]\n")
            else:
                print(f"  -> Could not resolve {id_str}, leaving red.\n")

            ctrl.update({"blue_keys": blue_keys, "red_keys": red_keys})
            save_control(ctrl)

    print("\n✓ Pass 1 complete!")
    ctrl["calibration_state"] = "pass2"
    save_control(ctrl)
    return ctrl


# ═════════════════════════════════════════════
# PASS 2 — Verification
# ═════════════════════════════════════════════

def pass2_verification(ldev, ctrl):
    print("\n" + "="*60)
    print("PASS 2: VERIFICATION")
    print("="*60)
    print("5 keys at a time will light WHITE.")
    print("CLI will show what keys SHOULD be lit.")
    print("Y key = bright green (correct).")
    print("N key = red (incorrect, flagged for review).")
    print("="*60 + "\n")

    blue_keys = ctrl.get("blue_keys", {})
    final_map = ctrl.get("final_map", {})

    # Look up Y and N key IDs from blue_keys
    y_hid = None
    n_hid = None
    y_id  = None
    n_id  = None

    for id_str, hid_code in blue_keys.items():
        if HID_KEY_MAP.get(hid_code) == "y" and y_hid is None:
            y_hid = hid_code
            y_id  = int(id_str, 16)
        if HID_KEY_MAP.get(hid_code) == "n" and n_hid is None:
            n_hid = hid_code
            n_id  = int(id_str, 16)

    if y_hid is None or n_hid is None:
        print("ERROR: Y and/or N keys not found in Control.json — run Pass 1 first!")
        return ctrl

    print(f"Y key: {HID_DISPLAY_MAP.get(y_hid)} | N key: {HID_DISPLAY_MAP.get(n_hid)}\n")

    # Build list of (id_str, hid_code, display_name) to verify
    to_verify = [
        (id_str, hid_code, HID_DISPLAY_MAP.get(hid_code, f"0x{hid_code:02x}"))
        for id_str, hid_code in blue_keys.items()
        if id_str not in final_map
    ]

    # Process in batches of 5
    batch_size = 5
    for i in range(0, len(to_verify), batch_size):
        batch = to_verify[i:i + batch_size]

        init_keyboard(ldev)

        colours = (
            [(y_id, *GREEN_YES), (n_id, *RED)] +
            [(int(id_str, 16), *WHITE) for id_str, _, _ in batch]
        )
        send_batch(ldev, colours)

        # Show CLI prompt
        print(f"Batch {i // batch_size + 1}: Should be lit —")
        for id_str, hid_code, name in batch:
            print(f"  {name} (ID {id_str})")
        print(f"\nPress Y (green) if correct, N (red) if wrong.")

        confirmed = wait_for_yn(y_hid, n_hid)

        if confirmed:
            send_batch(ldev, [(int(id_str, 16), *GREEN_CONF) for id_str, _, _ in batch])
            for id_str, hid_code, name in batch:
                final_map[id_str] = {
                    "key_id": id_str,
                    "hid":    hid_code,
                    "name":   name,
                    "rgb":    [0, 0, 0]
                }
            print(f"  ✓ Batch confirmed!\n")
        else:
            print(f"  ✗ Batch flagged for review — skipping for now.\n")

        ctrl["final_map"] = final_map
        save_control(ctrl)

    print("\n✓ Pass 2 complete!")
    ctrl["calibration_state"] = "complete"
    save_control(ctrl)
    return ctrl


# ═════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════

def main():
    print("Available K582 interfaces:")
    for dev in hid.enumerate(0x320F, 0x5000):
        print(f"  Interface {dev.get('interface_number')}: usage={hex(dev.get('usage',0))} usage_page={hex(dev.get('usage_page',0))}")

    print("\n" + "="*60)
    print(" Redragon K582 Surara — Finder.py")
    print(" LED Address Calibration Tool")
    print(" Open Source RGB Controller Project")
    print("="*60)

    try:
        print("\nOpening lighting interface...")
        ldev = open_lighting_device()
        print("Opening input interface...")
        idev = open_input_device()
        print("✓ K582 connected.\n")
    except RuntimeError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    ctrl  = load_control()
    state = ctrl.get("calibration_state", "pass1")
    print(f"Calibration state: {state}\n")

    try:
        if state == "pass1":
            ctrl  = pass1_discovery(ldev, ctrl)
            state = ctrl.get("calibration_state", "pass2")
        if state == "pass2":
            ctrl  = pass2_verification(ldev, ctrl)

        if ctrl.get("calibration_state") == "complete":
            print("\n" + "="*60)
            print("CALIBRATION COMPLETE!")
            print("Control.json is fully populated.")
            print("You can now run Controller.py to set key colours.")
            print("="*60)

    except KeyboardInterrupt:
        print("\n\nInterrupted. Progress has been saved to Control.json.")
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle(ldev)
        idev.close()


if __name__ == "__main__":
    main()