const HID = require('node-hid');

// Device constants from Finder.py
const VID = 0x320F;
const PID = 0x5000;
const INTERFACE = 1;

function createPacket() {
    return new Array(65).fill(0);
}

function sendColor(device, addr, r, g, b) {
    // START Packet
    let start = createPacket();
    start[0] = 0x04; start[1] = 0x01; start[3] = 0x01;
    device.write(start);

    // DATA Packet
    // Structure: 04 <csum_lo> <csum_hi> <addr_lo> <addr_hi> 00 00 00 <R> <G> <B>
    let data = createPacket();
    const addr_lo = addr & 0xFF;
    const addr_hi = (addr >> 8) & 0xFF;
    
    data[0] = 0x04;
    data[3] = addr_lo;
    data[4] = addr_hi;
    data[8] = r;
    data[9] = g;
    data[10] = b;
    // Note: Checksum logic (csum_lo/hi) may be needed if this doesn't trigger
    device.write(data);

    // COMMIT Packet
    let commit = createPacket();
    commit[0] = 0x04; commit[1] = 0x02; commit[3] = 0x02;
    device.write(commit);
}

try {
    const deviceInfo = HID.devices().find(d => d.vendorId === VID && d.productId === PID && d.interface === INTERFACE);
    if (deviceInfo) {
        const device = new HID.HID(deviceInfo.path);
        console.log("Connected to K582 Lighting Interface!");
        // Example: Turn address 0x0001 Blue
        sendColor(device, 0x0001, 0, 0, 255);
        device.close();
    } else {
        console.error("K582 Lighting Interface not found. Ensure no other RGB software is running.");
    }
} catch (err) {
    console.error("USB Error:", err.message);
}