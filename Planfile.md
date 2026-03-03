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

*This planfile is a living document and will be updated as the discovery phase progresses.*