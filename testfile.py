import ctypes
import ctypes.wintypes
import time

GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2

path = "\\\\?\\hid#vid_320f&pid_5000&mi_01&col04#7&37d128f9&0&0003#{4d1e55b2-f16f-11cf-88cb-001111000030}"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

handle = kernel32.CreateFileA(
    path.encode(),
    GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None, OPEN_EXISTING, 0, None
)

print(f"Handle: {handle}")
if handle == -1:
    print(f"Error: {ctypes.get_last_error()}")
else:
    start  = (ctypes.c_ubyte * 64)(0x04, 0x01, 0x00, 0x01, *([0]*60))
    data   = (ctypes.c_ubyte * 64)(0x04, 0xe2, 0x01, 0x11, 0x03, 0xcf, 0x00, 0x00, 0x00, 0xff, 0x00, *([0]*53))
    commit = (ctypes.c_ubyte * 64)(0x04, 0x02, 0x00, 0x02, *([0]*60))
    
    written = ctypes.c_ulong(0)
    for name, pkt in [("START", start), ("DATA", data), ("COMMIT", commit)]:
        kernel32.WriteFile(handle, pkt, 64, ctypes.byref(written), None)
        print(f"{name}: written={written.value}, error={ctypes.get_last_error()}")
        time.sleep(0.02)
    
    kernel32.CloseHandle(handle)