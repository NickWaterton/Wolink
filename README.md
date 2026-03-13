# Wolink BWRY ESL Tag - Reverse Engineered BLE Protocol

Reverse engineered BLE protocol for Wolink/Zhsunyco 2.13" BWRY epaper ESL tags,
for integration with [OpenEPaperLink](https://github.com/OpenEPaperLink/OpenEPaperLink).

**NOTE:** the BLE_Protocol.txt seems to be outdated, there is no CRC for example, so it's not totally accurate - read the code for up to date info. 

## Usage
```bash
usage: wolink_ble.py [-h] [--scan] [--scan-time SCAN_TIME] [--width WIDTH] [--height HEIGHT] [-r RETRIES] [-L [VAL ...]] [-C] [-v] [-D] [mac_address] [image]

Send an image to a Wolink ESL e-paper tag via BLE

positional arguments:
  mac_address           BLE MAC address of the ESL tag
  image                 Image file path (PNG/JPG/BMP). Omit for test pattern.

options:
  -h, --help            show this help message and exit
  --scan                Scan for nearby Wolink devices (default: False))
  --scan-time SCAN_TIME
                        Scan duration in seconds (default: 30.0))
  --width WIDTH         Display width (default: 250))
  --height HEIGHT       Display height (default: 128))
  -r RETRIES, --retries RETRIES
                        Number of connect retries (default: 3))
  -L [VAL ...], --led [VAL ...]
                        flash LED, args: R G B [on] [off] [duration] (default: 0 0 255 80 500 5000)
  -C, --clear           Clear the screen
  -v, --verbose         Verbose output
  -D, --debug           Debug output

Example: python wolink_ble.py AA:BB:CC:DD:EE:FF image.png
```

## Display
- 250×128 pixels, Black/White/Red/Yellow
- Non-compressed image format (CMD 0xA501)

## Image Format
- 8000 bytes total, 2 bits per pixel, column-major scan, y-flipped in RAM
- `0b00=BLACK, 0b01=WHITE, 0b10=YELLOW, 0b11=RED`
- 32 bytes per column × 250 columns

## BLE Protocol
| Characteristic | UUID |
|---|---|
| Auth | `33323032-4C53-4545-4C42-4B4E494C4F57` |
| Image | `31323032-4C53-4545-4C42-4B4E494C4F57` |
| Status | `34323032-4C53-4545-4C42-4B4E494C4F57` |

### Authentication
AES-128-CBC, zero IV. Read challenge from Auth characteristic, encrypt with key, write back first 16 bytes.

### Sending an Image
1. Upload in 238-byte chunks via CMD `0xA500` to Image characteristic
2. Trigger refresh via CMD `0xA501`

### Status
- Byte 0: `0xFF`=busy, `0x00`=idle
- Byte 1: `0x00`=ok, `0x02`=EPD write error, `0x03`=decompression error

### Notifications (Image characteristic)
- `0xF00B` — refresh starting
- `0xFF00000000000000` — busy
- `0x0000000000000000` — idle/complete

## Dependencies
- Python: `bleak`, `pycryptodome`, `Pillow`