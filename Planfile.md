# PLANFILE — Redragon K582 RGB Controller
### Open Source Per-Key RGB Controller for the Redragon K582 Surara (CH555 Controller)
---

# Part 1: The Goal
---

## What We Intend To Do
1. Reverse engineer the USB HID protocol used by the Redragon MITRA software to communicate with the K582 Surara's CH555 controller.
2. Build a fully open source, per-key static RGB lighting controller that bypasses the official MITRA software entirely.
3. Map every physical key on the 104-key layout to its corresponding hardware LED address.
4. Provide a GUI tool that allows a user to select keys and assign static RGB colours, saving and loading profiles via a `.js` config file.

---

# Part 2: The Pieces
---

## The Three Core Files

### `Keyboard.py`
- The **hardware layer**. Static file responsible for all direct USB HID communication with the CH555 controller.
- Sends correctly structured HID packets to the keyboard to set per-key RGB values.
- Does **not** handle UI or profile logic — it only speaks to the hardware.
- Relies on `hidapi` (via `hid` Python library) to interface with the keyboard over USB.

### `Control.js`
- The **keymap and profile store**. A JSON-structured `.js` file that maps each physical key name to its discovered hardware LED address and its assigned RGB colour value.
- Starts life as an **incomplete, address-unknown map** — populated incrementally during the discovery phase.
- Acts as the bridge between the GUI (`Controller.py`) and the hardware layer (`Keyboard.py`).
- Example structure (to be refined during discovery):
```json
{
  "keys": {
    "ESC":    { "address": null, "rgb": [0, 0, 0] },
    "F1":     { "address": null, "rgb": [0, 0, 0] },
    "A":      { "address": null, "rgb": [0, 0, 0] }
  }
}
```

### `Controller.py`
- The **GUI and orchestration layer**. Reads the keymap from `Control.js`, presents a GUI for per-key colour selection, and dispatches colour commands through `Keyboard.py`.
- Saves colour profiles back to `Control.js` for persistence.
- GUI framework: **TBD** — to be decided once address discovery is complete and the full key layout is confirmed.

---

# Part 3: The Discovery Phase
---

## Why We Need This First
The CH555 controller does not have a public protocol spec. Before any code can be written, we need to know:
- The USB Vendor ID and Product ID of the keyboard.
- The HID packet structure used to set key colours.
- The individual LED address for each of the 104 physical keys.

## Tools Required

| Tool | Purpose | Source |
|------|---------|--------|
| **Wireshark** + **USBPcap** | Capture raw USB HID packets sent by MITRA software | https://www.wireshark.org |
| **Ghidra** | Disassemble and decompile the MITRA `.exe` to extract protocol logic | https://ghidra-sre.org |
| **dnSpy** | If MITRA is .NET-based, decompile to near-readable C# | https://github.com/dnSpy/dnSpy |
| **Python + hid** | Send test packets directly to the keyboard for blind address matching | https://pypi.org/project/hid |

## Discovery Steps
1. Install Wireshark with USBPcap bundled.
2. Run MITRA software and set known static colours on specific keys.
3. Capture and analyse the USB HID packets in Wireshark — identify packet structure, key addresses, and RGB byte positions.
4. Cross-reference findings with Ghidra/dnSpy decompilation of the MITRA `.exe`.
5. Iteratively populate `Control.js` with confirmed key-to-address mappings.
6. Validate each mapping by sending test packets via `Keyboard.py` and visually confirming the correct key lights up.

---

# Part 4: Interoperability
---

```
[Controller.py GUI]
      |
      | reads/writes
      v
  [Control.js]
      |
      | key addresses + RGB values
      v
  [Keyboard.py]
      |
      | HID packets via hidapi
      v
[K582 CH555 Controller]
```

- `Controller.py` never talks directly to hardware — always via `Keyboard.py`.
- `Control.js` is the single source of truth for both layout and colour state.
- Each layer is independently testable.

---

# Part 5: Reliability & Redundancy
---

- **Reliability:** `Keyboard.py` will implement basic error handling for USB disconnects and failed packet sends, with a retry mechanism.
- **Redundancy:** `Control.js` profiles are saved to disk — if the tool crashes, the last saved colour state can be reloaded and re-applied on next launch.
- **Fallback:** If address discovery is incomplete, unresolved keys are silently skipped rather than crashing the tool.

---

# Part 6: How A User Uses This Tool
---

1. Plug in the K582 Surara.
2. Run `Controller.py`.
3. The GUI loads the keyboard layout from `Control.js`.
4. User clicks a key (or group of keys) and picks a colour.
5. Colour is applied live to the keyboard via `Keyboard.py`.
6. User saves the profile — written back to `Control.js`.
7. On next launch, the saved profile is auto-loaded and re-applied.

---

# Part 7: Sources & References
---

- Redragon K582 Surara product page: https://redragonzone.com
- Wireshark: https://www.wireshark.org
- Ghidra (NSA/Open Source): https://ghidra-sre.org
- dnSpy: https://github.com/dnSpy/dnSpy
- Python `hid` library (hidapi bindings): https://pypi.org/project/hid
- CH555 datasheet (WCH): http://www.wch-ic.com/products/CH555.html
- Community reverse engineering reference (OpenRGB): https://gitlab.com/CalcProgrammer1/OpenRGB

---

# NOTES: What The Hells Is Happening
---
1. started with reverse engineering the Redragon .exe file, then used wireshark to capture packets of colour change data to determine what is being sent back and forth. The wireshark files are included int he repo.
2. built the finder.py to enable keys address discovery so this program can be used for any redreagon keyboard. 
3. while testing the Finder.py during development, we are unable to send the correct colours to the keyboard itself. 

## The idea: If any
We could try to use the testfile.py to manually sequence 4 random addresses, using a pre-scripted method, this could enable the discovery of the cause of the issue ast hand. 

## The Issue. 
The currently faced issue with finder .py is the colours are not being sent properly, the keyboard is not correctly updating. the result is, it is impossible to press an appropriate key after the first key is confirmed. 

---

# AI NOTES — IPEOR Progress Log

---

## EXECUTE — What Was Done

1. **Wireshark capture** — MITRA software was run and USB HID packets were captured. The raw packet structure was extracted from the capture files included in the repo.

2. **Protocol fully reverse-engineered** — From Wireshark data:
   - VID: `0x320F`, PID: `0x5000`
   - Lighting interface: `col04` path (interface 1)
   - Input interface: interface 0, usage=6
   - Packets are **64 bytes**, no report ID byte
   - Transaction model: **START → one or more DATA → COMMIT**
   - `START:  [0x04, 0x01, 0x00, 0x01, 0x00 * 60]`
   - `DATA:   [0x04, csum_lo, csum_hi, 0x11, 0x03, key_id, 0x00, 0x00, R, G, B, 0x00 * 53]`
   - `COMMIT: [0x04, 0x02, 0x00, 0x02, 0x00 * 60]`
   - Checksum: `sum(data[3:]) & 0xFFFF`, lo byte → `[1]`, hi byte → `[2]`
   - Writing uses `kernel32.CreateFileA` + `kernel32.WriteFile` — **NOT** the `hid` library
   - Input reading uses `hid.device()` via the `hid` Python library (hidapi)

3. **testfile.py** — Proof-of-concept written. Manually hardcoded a single DATA packet for the H key (`key_id=0xCF`) at white (255,255,255). **Confirmed: the protocol works.** Key lit correctly.
   - Known confirmed key_ids: `ESC=0x00`, `F1=0x01`, `W=0x84`, `A=0xC0`, `H=0xCF`

4. **Finder.py built** — Full two-pass LED address calibration tool:
   - **Pass 1 (Discovery)**: Iterates all 256 key_ids (`0x00–0xFF`). Lights each WHITE. User presses the physical key that lit, confirms with L-ALT + NUM ENTER (first time), then with the first confirmed key thereafter. Mapped = BLUE, conflict = RED.
   - **Red resolution sub-phase**: For any conflicted address, shows it WHITE against the rest and asks user to press the correct key.
   - **Pass 2 (Verification)**: Batches of 5 keys lit WHITE. User presses Y (green=correct) or N (red=wrong). Confirmed keys written to `final_map` in Control.json.
   - State is saved to `Control.json` after every keypress — safe to interrupt and resume.

5. **Control.json format established** — differs from the original plan's hypothetical `Control.js`:
```json
{
  "calibration_state": "pass1 | pass2 | complete",
  "confirm_key": <hid_code int>,
  "blue_keys":   { "0xNN": <hid_code int> },
  "red_keys":    { "0xNN": [<hid_codes>] },
  "final_map":   { "0xNN": { "key_id": "0xNN", "hid": int, "name": "KEY", "rgb": [0,0,0] } },
  "last_addr":   <int>
}
```

6. **Batching introduced** — Each START/DATA/COMMIT transaction replaces the entire keyboard LED state. Per-key individual transactions caused the "snake effect" (each new START wipes previous keys). Fix: one START, N DATA packets, one COMMIT = atomic multi-key update. `send_batch(handle, colour_list)` added to `Finder.py`.

---

## OBSERVE — What Was Found During Testing

- **Snake effect (symptom)**: After confirming ESC (white → confirmed), keyboard should show ESC=BLUE and F1=WHITE. Instead: ESC appeared as `(128, 128, 255)` (half-blended) and F1 appeared as `(255, 0, 0)`. Error worsens with each subsequent key.

- **Root cause hypothesis A**: 20ms inter-packet sleep inside `send_batch` was causing the keyboard firmware to timeout or split the transaction, blending partial state from two updates.

- **Fix applied**: Removed all inter-packet delays from `send_batch`. Single `50ms` sleep after COMMIT. Added `200ms` settling delay after `init_keyboard`. **Status: applied, awaiting test.**

- **Diagnostic suggestion (pending)**: Manually script 4 addresses testfile.py-style (no loop, no state machine) to confirm whether multi-DATA batches work at all on this firmware, or whether only 1 DATA packet per transaction is supported.

---

## RESULTS — Current State

| Component     | Status                                               |
|---------------|------------------------------------------------------|
| Protocol      | COMPLETE — fully reverse-engineered via Wireshark    |
| testfile.py   | COMPLETE — proof of concept, protocol confirmed      |
| Finder.py     | BUILT — active bug (wrong colours / snake effect)    |
| Control.json  | FORMAT ESTABLISHED — has partial pass1 data          |
| Keyboard.py   | STUB — not yet built                                 |
| Controller.py | STUB — not yet built                                 |

**Next actions:**
1. Resolve Finder.py snake effect (test timing fix; fallback: testfile.py-style manual batch diagnostic)
2. Build `Keyboard.py` (hardware layer — wraps `send_batch` for use by `Controller.py`)
3. Build `Controller.py` (GUI — reads `final_map` from `Control.json`, dispatches colour commands)

---

*This planfile is a living document and will be updated as the discovery phase progresses.*