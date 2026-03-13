"""
Finder.py - Redragon K582 Surara LED Address Calibration Tool
=============================================================
Author: Alastar
Project: K582 Open Source RGB Controller
License: Open Source

Protocol (reverse engineered via Wireshark):
  VID: 0x320F  PID: 0x5000  Interface: 1
  Packet (64 bytes):
    START:  04 01 00 01 00 00 ... (64 bytes)
    DATA:   04 <csum_lo> <csum_hi> <addr_lo> <addr_hi> 00 00 00 <R> <G> <B> 00...
    COMMIT: 04 02 00 02 00 00 ... (64 bytes)

Calibration Passes:
  Pass 1 - Discovery : Light one address white. User presses lit keys + L-Alt+Enter.
  Pass 2 - Identity  : Ask user to press a named key. Correct=green, wrong=red (retry).
  Pass 3 - Lock-in   : Call out keys, user presses to confirm. Confirmed = dark (locked).
"""

import hid
import json
import time
import os
import sys
import pywinusb.hid as pywinusb
import ctypes

#Lets find the break!
print("Available K582 interfaces:")
for dev in hid.enumerate(0x320F, 0x5000):
    print(f"  Interface {dev.get('interface_number')}: usage={hex(dev.get('usage',0))} usage_page={hex(dev.get('usage_page',0))}")

# ─────────────────────────────────────────────
# Device constants
# ─────────────────────────────────────────────
VID            = 0x320F
PID            = 0x5000
IFACE_LIGHTING = 1
IFACE_INPUT    = 0

# ─────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────
WHITE = (255, 255, 255)
BLUE  = (0,   0,   255)
GREEN = (0,   100, 0  )
RED   = (255, 0,   0  )
OFF   = (0,   0,   0  )

# ─────────────────────────────────────────────
# Address scan range
# ─────────────────────────────────────────────
ADDR_START = 0x0000
ADDR_END   = 0x00FF

# ─────────────────────────────────────────────
# HID usage code -> key name
# ─────────────────────────────────────────────
HID_KEY_MAP = {
    0x04: "A",        0x05: "B",        0x06: "C",        0x07: "D",
    0x08: "E",        0x09: "F",        0x0A: "G",        0x0B: "H",
    0x0C: "I",        0x0D: "J",        0x0E: "K",        0x0F: "L",
    0x10: "M",        0x11: "N",        0x12: "O",        0x13: "P",
    0x14: "Q",        0x15: "R",        0x16: "S",        0x17: "T",
    0x18: "U",        0x19: "V",        0x1A: "W",        0x1B: "X",
    0x1C: "Y",        0x1D: "Z",
    0x1E: "1",        0x1F: "2",        0x20: "3",        0x21: "4",
    0x22: "5",        0x23: "6",        0x24: "7",        0x25: "8",
    0x26: "9",        0x27: "0",
    0x28: "ENTER",    0x29: "ESC",      0x2A: "BACKSPACE", 0x2B: "TAB",
    0x2C: "SPACE",    0x2D: "-",        0x2E: "=",
    0x2F: "[",        0x30: "]",        0x31: "\\",
    0x33: ";",        0x34: "'",        0x35: "`",
    0x36: ",",        0x37: ".",        0x38: "/",
    0x39: "CAPS",
    0x3A: "F1",       0x3B: "F2",       0x3C: "F3",       0x3D: "F4",
    0x3E: "F5",       0x3F: "F6",       0x40: "F7",       0x41: "F8",
    0x42: "F9",       0x43: "F10",      0x44: "F11",      0x45: "F12",
    0x46: "PRTSC",    0x47: "SCRLK",    0x48: "PAUSE",
    0x49: "INS",      0x4A: "HOME",     0x4B: "PGUP",
    0x4C: "DEL",      0x4D: "END",      0x4E: "PGDN",
    0x4F: "RIGHT",    0x50: "LEFT",     0x51: "DOWN",     0x52: "UP",
    0x53: "NUMLK",    0x54: "NUM/",     0x55: "NUM*",     0x56: "NUM-",
    0x57: "NUM+",     0x58: "NUMENTER",
    0x59: "NUM1",     0x5A: "NUM2",     0x5B: "NUM3",     0x5C: "NUM4",
    0x5D: "NUM5",     0x5E: "NUM6",     0x5F: "NUM7",     0x60: "NUM8",
    0x61: "NUM9",     0x62: "NUM0",     0x63: "NUM.",
    0x65: "APP",
    0xE0: "L-CTRL",   0xE1: "L-SHIFT",  0xE2: "L-ALT",    0xE3: "L-WIN",
    0xE4: "R-CTRL",   0xE5: "R-SHIFT",  0xE6: "R-ALT",    0xE7: "R-WIN",
}

CONTROL_JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Control.js")


# ═════════════════════════════════════════════
# Device helpers
# ═════════════════════════════════════════════

def open_lighting_device():
    hid_filter = pywinusb.HidDeviceFilter(vendor_id=VID, product_id=PID)
    devices = hid_filter.get_devices() or []
    for d in devices:
        if "col04" in d.device_path.lower():
            d.open()
            return d
    raise RuntimeError("K582 lighting interface not found.")

def open_device(interface):
    for dev in hid.enumerate(VID, PID):
        if dev.get("interface_number") == interface and dev.get("usage") == 6:
            d = hid.device()
            d.open_path(dev["path"])
            return d
    raise RuntimeError(f"K582 input interface not found.")


def build_packet(addr_lo, addr_hi, r, g, b):
    data = [0x04, 0x00, 0x00, addr_lo, addr_hi, 0xcf, 0x00, 0x00, r, g, b] + [0x00] * 53
    csum = sum(data[3:]) & 0xFFFF
    data[1] = csum & 0xFF
    data[2] = (csum >> 8) & 0xFF
    return data


def send_colour(dev, addr_lo, addr_hi, r, g, b):
    start  = [0x04, 0x01, 0x00, 0x01] + [0x00] * 60
    commit = [0x04, 0x02, 0x00, 0x02] + [0x00] * 60
    data   = build_packet(addr_lo, addr_hi, r, g, b)
    print(f"Data packet: {data[:12]}")

    import ctypes
    for packet in [start, data, commit]:
        buf = (ctypes.c_ubyte * 65)(0, *packet[:64])
        bytes_written = ctypes.c_ulong(0)
        ctypes.windll.kernel32.WriteFile(
            int(dev.hid_handle), buf, 65,
            ctypes.byref(bytes_written), None)
        print(f"Written: {bytes_written.value}")
        time.sleep(0.02)


# ═════════════════════════════════════════════
# Control.js helpers
# ═════════════════════════════════════════════

def load_control_js():
    if os.path.exists(CONTROL_JS_PATH):
        with open(CONTROL_JS_PATH, "r") as f:
            content = f.read().strip()
        if content.startswith("export default"):
            content = content[len("export default"):].strip().rstrip(";")
        return json.loads(content)
    return {"calibration_state": "pass1", "addr_map": {}, "address_to_hid": {},
            "verified_keys": {}, "locked_keys": {}, "final_map": {}}


def save_control_js(data):
    with open(CONTROL_JS_PATH, "w") as f:
        f.write("export default ")
        json.dump(data, f, indent=2)
        f.write(";\n")
    print(f"  [Saved -> {CONTROL_JS_PATH}]")


# ═════════════════════════════════════════════
# Input helpers
# ═════════════════════════════════════════════

def read_pressed_keys(input_dev):
    pressed = set()
    try:
        report = input_dev.read(64)
        if report and len(report) >= 8:
            mod = report[0]
            if mod & 0x01: pressed.add(0xE0)
            if mod & 0x02: pressed.add(0xE1)
            if mod & 0x04: pressed.add(0xE2)
            if mod & 0x08: pressed.add(0xE3)
            if mod & 0x10: pressed.add(0xE4)
            if mod & 0x20: pressed.add(0xE5)
            if mod & 0x40: pressed.add(0xE6)
            if mod & 0x80: pressed.add(0xE7)
            for b in report[2:8]:
                if b != 0x00:
                    pressed.add(b)
    except Exception:
        pass
    return pressed


def wait_for_confirm(input_dev):
    """Wait for L-Alt + Enter. Returns all non-modifier/non-Enter keys pressed before confirm."""
    print("  >> Press lit keys, then L-ALT + ENTER to confirm...")
    collected = set()
    last = set()
    while True:
        time.sleep(0.02)
        pressed = read_pressed_keys(input_dev)
        for k in pressed - last:
            if k not in (0xE2, 0x28):
                if k not in collected:
                    collected.add(k)
                    print(f"    Key detected: {HID_KEY_MAP.get(k, f'0x{k:02x}')} (HID 0x{k:02x})")
        if 0xE2 in pressed and 0x28 in pressed:
            time.sleep(0.15)
            break
        last = pressed
    return collected


def wait_for_single_key(input_dev):
    """Wait for exactly one non-modifier keypress and return its HID code."""
    last = set()
    MODIFIERS = {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7}
    while True:
        time.sleep(0.02)
        pressed = read_pressed_keys(input_dev)
        new = (pressed - last) - MODIFIERS
        if new:
            return next(iter(new))
        last = pressed


# ═════════════════════════════════════════════
# PASS 1 — Discovery
# ═════════════════════════════════════════════

def pass1_discovery(ldev, idev, ctrl):
    print("\n" + "="*60)
    print("PASS 1: DISCOVERY")
    print("="*60)
    print("One address at a time will light WHITE.")
    print("Press every key that lights up, then L-ALT + ENTER.")
    print("Multiple keys lighting = address overlap (thats fine!).")
    print("="*60 + "\n")

    addr_map       = ctrl.get("addr_map", {})
    address_to_hid = ctrl.get("address_to_hid", {})
    start          = ctrl.get("last_addr", ADDR_START - 1) + 1

    if start > ADDR_START:
        print(f"Resuming from address 0x{start:04x}\n")

    for addr in range(start, ADDR_END + 1):
        alo, ahi = addr & 0xFF, (addr >> 8) & 0xFF
        addr_str = f"0x{addr:04x}"
        print(f"Address {addr_str}  ({addr - ADDR_START + 1}/{ADDR_END - ADDR_START + 1})")

        send_colour(ldev, alo, ahi, *WHITE)
        pressed_hids = wait_for_confirm(idev)
        send_colour(ldev, alo, ahi, *BLUE)

        if pressed_hids:
            address_to_hid[addr_str] = list(pressed_hids)
            for hid_code in pressed_hids:
                key = str(hid_code)
                if key not in addr_map:
                    addr_map[key] = []
                if addr_str not in addr_map[key]:
                    addr_map[key].append(addr_str)
            names = [HID_KEY_MAP.get(h, f"0x{h:02x}") for h in pressed_hids]
            print(f"  -> Mapped: {', '.join(names)} = {addr_str}\n")
        else:
            print(f"  -> No keys pressed. Skipping.\n")

        ctrl.update({"addr_map": addr_map, "address_to_hid": address_to_hid,
                     "last_addr": addr, "calibration_state": "pass1"})
        save_control_js(ctrl)

    print("\n✓ Pass 1 complete!")
    ctrl["calibration_state"] = "pass2"
    save_control_js(ctrl)
    return ctrl


# ═════════════════════════════════════════════
# PASS 2 — Identity
# ═════════════════════════════════════════════

def pass2_identity(ldev, idev, ctrl):
    print("\n" + "="*60)
    print("PASS 2: IDENTITY VERIFICATION")
    print("="*60)
    print("Press the named key when asked.")
    print("Correct = GREEN  |  Wrong = RED (will retry)")
    print("="*60 + "\n")

    addr_map = ctrl.get("addr_map", {})
    verified = ctrl.get("verified_keys", {})
    to_verify = [int(k) for k in addr_map if k not in verified]

    for hid_code in to_verify:
        key_name  = HID_KEY_MAP.get(hid_code, f"0x{hid_code:02x}")
        addresses = addr_map[str(hid_code)]
        print(f"\nPress: [ {key_name} ]")

        for a in addresses:
            av = int(a, 16)
            send_colour(ldev, av & 0xFF, av >> 8, *WHITE)

        confirmed = False
        while not confirmed:
            pressed = wait_for_single_key(idev)
            if pressed == hid_code:
                for a in addresses:
                    av = int(a, 16)
                    send_colour(ldev, av & 0xFF, av >> 8, *GREEN)
                print(f"  ✓ {key_name} verified!")
                verified[str(hid_code)] = {"name": key_name, "addresses": addresses}
                confirmed = True
            else:
                wrong = HID_KEY_MAP.get(pressed, f"0x{pressed:02x}")
                for a in addresses:
                    av = int(a, 16)
                    send_colour(ldev, av & 0xFF, av >> 8, *RED)
                print(f"  ✗ Got {wrong}. Try again...")
                time.sleep(0.5)
                for a in addresses:
                    av = int(a, 16)
                    send_colour(ldev, av & 0xFF, av >> 8, *WHITE)

        ctrl["verified_keys"] = verified
        save_control_js(ctrl)

    print("\n✓ Pass 2 complete!")
    ctrl["calibration_state"] = "pass3"
    save_control_js(ctrl)
    return ctrl


# ═════════════════════════════════════════════
# PASS 3 — Lock-in
# ═════════════════════════════════════════════

def pass3_lockin(ldev, idev, ctrl):
    print("\n" + "="*60)
    print("PASS 3: FINAL LOCK-IN")
    print("="*60)
    print("Press each key as called. Confirmed keys go DARK (locked).")
    print("="*60 + "\n")

    verified  = ctrl.get("verified_keys", {})
    locked    = ctrl.get("locked_keys", {})
    final_map = ctrl.get("final_map", {})
    to_lock   = [(int(k), v) for k, v in verified.items() if k not in locked]

    for hid_code, key_data in to_lock:
        key_name  = key_data["name"]
        addresses = key_data["addresses"]
        print(f"\nConfirm: [ {key_name} ]")

        for a in addresses:
            av = int(a, 16)
            send_colour(ldev, av & 0xFF, av >> 8, *WHITE)

        pressed = wait_for_single_key(idev)

        if pressed == hid_code:
            for a in addresses:
                av = int(a, 16)
                send_colour(ldev, av & 0xFF, av >> 8, *OFF)
            print(f"  ✓ {key_name} LOCKED.")
            locked[str(hid_code)] = key_data
            final_map[key_name] = {"address": addresses[0], "hid": hid_code, "rgb": [0, 0, 0]}
        else:
            wrong = HID_KEY_MAP.get(pressed, f"0x{pressed:02x}")
            print(f"  ✗ Expected {key_name}, got {wrong}. Flagged for re-check.")

        ctrl.update({"locked_keys": locked, "final_map": final_map})
        save_control_js(ctrl)

    print(f"\n✓ Pass 3 complete! {len(locked)} keys locked.")
    ctrl["calibration_state"] = "complete"
    save_control_js(ctrl)
    return ctrl


# ═════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════

def main():
    import pywinusb.hid as pywinusb
    filter = pywinusb.HidDeviceFilter(vendor_id=VID, product_id=PID)
    devices = filter.get_devices()
    devices = devices if devices is not None else []
    print(f"pywinusb found: {len(devices)} devices")
    for d in devices:
        print(f"  {d}")
    print("="*60)
    print(" Redragon K582 Surara — Finder.py")
    print(" LED Address Calibration Tool")
    print(" Open Source RGB Controller Project")
    print("="*60)

    try:
        print("\nOpening lighting interface (Interface 1)...")
        ldev = open_lighting_device()
        print("Opening input interface (Interface 0)...")
        idev = open_device(IFACE_INPUT)
        print("✓ K582 connected.\n")
    except RuntimeError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    ctrl  = load_control_js()
    state = ctrl.get("calibration_state", "pass1")
    print(f"Calibration state: {state}\n")

    try:
        if state == "pass1":
            ctrl  = pass1_discovery(ldev, idev, ctrl)
            state = ctrl.get("calibration_state", "pass2")
        if state == "pass2":
            ctrl  = pass2_identity(ldev, idev, ctrl)
            state = ctrl.get("calibration_state", "pass3")
        if state == "pass3":
            ctrl  = pass3_lockin(ldev, idev, ctrl)

        if ctrl.get("calibration_state") == "complete":
            print("\n" + "="*60)
            print("CALIBRATION COMPLETE!")
            print("Control.js is fully populated.")
            print("You can now run Controller.py to set key colours.")
            print("="*60)

    except KeyboardInterrupt:
        print("\n\nInterrupted. Progress has been saved to Control.js.")
    finally:
        ldev.close()
        idev.close()


if __name__ == "__main__":
    main()