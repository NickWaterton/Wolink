#!/usr/bin/env python3
r'''
Wolink (zhsunyco) ESL BLE Image Sender

CPU is probably a Telink TLSR8258 varient

Size is from PID:
data (from advertising and handle 32323032-4c53-4545-4c42-4b4e494c4f57 Handle: 25: 3000000e03300103
PID is 0x000E for 2.1" ESL
0x0008	1.54"
0x000A	2.13"
0x000E	2.13" / 250×128 (122 displayed)
0x0012	2.9"
0x0016	4.2"
0x001A	5.8"

advertising also includes big endian battery voltage at the end (in mV)

Wolink ESL BLE GATT Table
=========================

Service: Generic Access (0x1800)
--------------------------------------------------------------
Handle  UUID                                    Name                     Access
------  --------------------------------------  -----------------------  ----------------
2       00002A00-0000-1000-8000-00805F9B34FB    Device Name              Read, Notify
                                                 Value: "WOESL"

4       00002A01-0000-1000-8000-00805F9B34FB    Appearance               Read
                                                 Value: 0000 (Generic)

6       00002A04-0000-1000-8000-00805F9B34FB    Preferred Conn Params    Read
                                                 Example: 140028000000E803


Service: Generic Attribute (0x1801)
--------------------------------------------------------------
Handle  UUID                                    Name                     Access
------  --------------------------------------  -----------------------  ----------------
9       00002A05-0000-1000-8000-00805F9B34FB    Service Changed          Indicate


Service: Wolink ESL (30323032-4C53-4545-4C42-4B4E494C4F57)
ASCII: "WOLINKBLEESL2020"
--------------------------------------------------------------
Handle  UUID                                    Purpose                  Access
------  --------------------------------------  -----------------------  ----------------
13      35323032-4C53-4545-4C42-4B4E494C4F57    Status / Battery         Read, Notify
                                                 Read: battery voltage
                                                 Example: 1D0C → 0x0C1D = 3101 mV
                                                 Notify: command responses

16      34323032-4C53-4545-4C42-4B4E494C4F57    Command Status           Read, Notify
                                                 Example error: FF00000000000000

19      33323032-4C53-4545-4C42-4B4E494C4F57    Authentication           Read, Write
                                                 Read: 16-byte challenge
                                                 Write: AES-128 encrypted response

22      31323032-4C53-4545-4C42-4B4E494C4F57    Command / Image Data     Read, Write
                                                 A500 → upload block
                                                 A501 → refresh uncompressed
                                                 A502 → refresh compressed

25      32323032-4C53-4545-4C42-4B4E494C4F57    Advertising Mirror       Read, Notify
                                                 Example: 3000000E03300103


Typical Session Flow
--------------------------------------------------------------
connect
↓
enable notifications (13, 16)
↓
read auth challenge (19)
↓
AES encrypt challenge
↓
write auth response (19)
↓
upload image blocks (22)
↓
send refresh command (22)
↓
receive auth OK notification
↓
display updates

see https://github.com/roxburghm/zhsunyco-esl/issues/1

uncompressed image data format (for 250x128):
Property            Value
Total size          8000
bytesEncoding       2 bits per pixel
Scan order          Column-major (x=0 = left = bytes 0–31)
Bytes per column    32 (128 rows × 2bpp / 8)

Device Discovery:
    Scan filter: Device name prefix "WL" (Wolink)
    Scan duration: 60 seconds
    BLE library: bleak

Sends a test image to a Wolink Electronic Shelf Label (ESL-21BWRY, 2.1" BWRY)
via Bluetooth Low Energy.

Reverse-engineered by N Waterton

Requirements:
    pip install bleak pycryptodome Pillow

Usage:
    python wolink_ble.py <mac_address> [image_path]
    python wolink_ble.py AA:BB:CC:DD:EE:FF test.png
    python wolink_ble.py AA:BB:CC:DD:EE:FF              # sends test pattern

N Waterton 12/3/2026   V 1.0.0 : Initial Release
'''

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from bleak import BleakClient, BleakScanner
from bleak.backends.scanner import AdvertisementData
from bleak.backends.device import BLEDevice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

try:
    from PIL import Image
except ImportError:
    Image = None
    
__version__ = '1.0.0'

logging.basicConfig(level=logging.INFO)

# --- Constants ---

# 2.9" BWRY e-paper display resolution
#DISPLAY_WIDTH = 296 # 2.1" is 250
#DISPLAY_HEIGHT = 128 # 2.1" is 122 pixels, but image is 128

# 2.13" BWRY e-paper display resolution
DISPLAY_WIDTH =  250
DISPLAY_HEIGHT = 128

def parseargs():
    # Add command line argument parsing
    parser = argparse.ArgumentParser(
        description="Send an image to a Wolink ESL e-paper tag via BLE",
        epilog="Example: python wolink_ble.py AA:BB:CC:DD:EE:FF image.png",
    )
    parser.add_argument("mac_address", nargs="?", help="BLE MAC address of the ESL tag")
    parser.add_argument("image", nargs="?", default=None, help="Image file path (PNG/JPG/BMP). Omit for test pattern.")
    parser.add_argument("--scan", action="store_true", default=False, help="Scan for nearby Wolink devices (default: %(default)s))")
    parser.add_argument("--scan-time", type=float, default=30.0, help="Scan duration in seconds (default: %(default)s))")
    parser.add_argument("--width", type=int, default=DISPLAY_WIDTH, help=f"Display width (default: %(default)s))")
    parser.add_argument("--height", type=int, default=DISPLAY_HEIGHT, help=f"Display height (default: %(default)s))")
    parser.add_argument("-r","--retries", type=int, default=3, help=f"Number of connect retries (default: %(default)s))")
    parser.add_argument("-L", "--led", nargs="*", default=None, metavar="VAL", help="flash LED, args: R G B [on] [off] [duration] (default: 0 0 255 80 500 5000)")
    parser.add_argument("-C", "--clear", action="store_true", help="Clear the screen")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-D", "--debug", action="store_true", help="Debug output")
    return parser.parse_args()

class WOLINK:
    
    # BLE secret key (See API docs)
    BLE_SECRET_KEY = bytes([
        155, 96, 159, 40, 188, 73, 226, 87,
        41, 189, 123, 141, 242, 43, 68, 32
    ])

    # BLE secret IV (zero IV, allocated as zeroed buffer in genBleSecret)
    BLE_SECRET_IV = bytes(16)
    
    BLACK  = 0b00
    WHITE  = 0b01
    YELLOW = 0b10
    RED    = 0b11
    
    WOLINK_UUIDS = {
        "service"       : "30323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2020
        "data"          : "31323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2021
        "config"        : "32323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2022
        "authenticate"  : "33323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2023
        "status"        : "34323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2024
        "battery"       : "35323032-4c53-4545-4c42-4b4e494c4f57",  # WOLINKBLEESL2025
    }
    
    types = {
        0x0008: {'type':'1.54"',               'width': 200, 'height': 200, 'voffset': 0},
        0x000A: {'type':'2.13"',               'width': 250, 'height': 128, 'voffset': 0},
        0x000E: {'type':'2.13", (250x122)',    'width': 250, 'height': 128, 'voffset': 6},  #screen is 122 pixels high, so 6 pixels offset in data
        0x0012: {'type':'2.9", (296x128)',     'width': 296, 'height': 128, 'voffset': 0},
        0x0016: {'type':'4.2"',                'width': 400, 'height': 300, 'voffset': 0},
        0x001A: {'type':'5.8"',                'width': 648, 'height': 480, 'voffset': 0},
    }
    
    error_code = {
        0x00: 'Ok',
        0x01: 'EPD init error',  
        0x02: 'EPD write error',
        0x03: 'data decompression error (wrong format)',
        0x04: 'OTA error',
        0x05: 'Unlock Failed'
    }
    
    def __init__(self, mac_address, width, height, retries=3):
        self.log = logging.getLogger('Main'+__class__.__name__)
        self.mac_address = self.normalise_mac(mac_address) if mac_address else mac_address
        self.width = width      # these will be overwritten by the actual tag data received
        self.height = height
        self.voffset = 0
        self.retries = retries+1
        self.mtu = 247          # default mtu for wolink tags
        self.status_event = asyncio.Event()
        self.status_event.set()
        self.chars = {}
            
    def close(self):
        self.log.info('SIGINT/SIGTERM received, exiting')
        sys.exit(1)
        
    def normalise_mac(self, mac: str) -> str:
        '''
        make sure mac address is of the format: 66:66:17:10:F4:C0
        '''
        mac = mac.replace(":", "").replace("-", "")
        return ":".join(mac[i:i+2] for i in range(0, 12, 2)).upper()
        
    def to_bytes(self, val, n=4, order='little'):
        '''
        return int as n bytes with order
        '''
        return val.to_bytes(n, order)

    # --- Encryption ---
    def gen_ble_secret(self, plaintext):
        """
        Encrypt data for BLE authentication (genBleSecret from common_utils.dart).
        AES-128-CBC with hardcoded key and zero IV.
        """
        cipher = AES.new(self.BLE_SECRET_KEY, AES.MODE_CBC, iv=self.BLE_SECRET_IV)
        return cipher.encrypt(pad(plaintext, AES.block_size))[:16]

    # --- Image processing ---
    def generate_test_pattern(self):
        """
        16×16 checkerboard of BLACK and WHITE tiles, with a RED and YELLOW
        stripe across the bottom two rows of tiles to verify all four colours.
        """
        def get_color(x, y):
            if y >= 112:                          # bottom 16px → YELLOW stripe
                return self.YELLOW
            if y >= 96:                           # next 16px up → RED stripe
                return self.RED
            return self.BLACK if (x // 16 + y // 16) % 2 == 0 else self.WHITE

        return self.make_image(get_color)
        
    def from_pillow(self, img):
        """
        Convert a PIL/Pillow image to display bytes.

        The image is resized to 250×128 and each pixel is mapped to the
        nearest of the four display colours using a simple decision tree:

            white  — R>150, G>150, B>150
            yellow — R>150, G>100, B<80
            red    — R>150, G<80,  B<80
            black  — everything else

        For best results, pre-dither or posterise the image to the four
        colours before calling this function.
        applies voffset if height is larger than the screen height (2.13" tag)
        """
        img = img.convert("RGB").resize((self.width, self.height-self.voffset), Image.LANCZOS)
        bg = Image.new('RGB', (self.width, self.height))
        bg.paste(img, (0, self.voffset))
        def nearest(x, y):
            r, g, b = bg.getpixel((x, y))
            if r > 150 and g > 150 and b > 150: return self.WHITE
            if r > 150 and g > 100 and b < 80:  return self.YELLOW
            if r > 150 and g < 80  and b < 80:  return self.RED
            return self.BLACK

        return self.make_image(nearest)
        
    def make_pixel_data(self, get_pixel_fn):
        """
        get_pixel_fn(x, y) → (is_black: bool, is_colored: bool)
        """
        plane_size = self.width * self.height // 8  # 4000 bytes
        bw    = bytearray(plane_size)
        color = bytearray(plane_size)
        for y in range(self.height):
            for x in range(self.width):
                idx      = y * self.width + x
                byte_idx = idx // 8
                bit_idx  = 7 - (idx % 8)  # MSB first
                is_black, is_colored = get_pixel_fn(x, y)
                if is_black:   bw[byte_idx]    |= 1 << bit_idx
                if is_colored: color[byte_idx] |= 1 << bit_idx
        return bytes(bw + color)  # 8000 bytes total
        
    def make_image(self, get_color):
        """
        get_color(x, y) -> BLACK | WHITE | YELLOW | RED
          x: 0=left  .. 249=right
          y: 0=top   .. 127=bottom
        Returns 8000 bytes for CMD 0xA501.
        """
        plane_size  = self.width * self.height // 8
        total_bytes = plane_size * 2    # 8000 bytes
        data = bytearray(total_bytes)
        for x in range(self.width):
            for y in range(self.height):
                color     = get_color(x, y) & 0b11
                phy_y     = (self.height - 1) - y   # RAM is y-flipped
                byte_idx  = x * 32 + phy_y // 4
                bit_shift = 6 - (phy_y % 4) * 2
                data[byte_idx] |= color << bit_shift
        return bytes(data)
        
    async def send_noncompressed(self, client, pixel_data):
        '''
        Upload in self.mtu-9 byte chunks (to allow for 8 byte header) via CMD 0xA500
        '''
        chunk_size = self.mtu-9
        for offset in range(0, len(pixel_data), chunk_size):
            chunk = pixel_data[offset:offset+chunk_size]
            self.log.info(f'writing {offset}')
            await self.send_command(client, bytes([0x00, 0xA5]) + self.to_bytes(offset) + chunk, response=True)
            await asyncio.sleep(0.02)
        self.log.info(f'writing completion')
        # Trigger refresh via CMD 0xA501
        await self.send_command(client, bytes([0x01, 0xA5]) + self.to_bytes(len(pixel_data)), response=True)
        self.log.debug(f'done sending pixel data: {len(pixel_data)}')

    def image_to_bitmap(self, image_path=None) -> bytes:
        """
        Convert an image file to 2-bit packed bitmap for the e-paper display.
        """
        if Image is None:
            self.log.warning('Pillow not installed, using test pattern')
            return self.generate_test_pattern()

        path = Path(image_path) if image_path else None
        if not path or not path.is_file():
            self.log.warning(f'file not found: {path}' if path else 'no image path, using test pattern')
            return self.generate_test_pattern()

        img = Image.open(path)
        image_data = self.from_pillow(img)
        self.log.info(f"Image data: {len(image_data)} bytes ({self.width}x{self.height} 2-bits/pixel)")
        return image_data
        
    async def get_tag_data(self, client):
        '''
        read config and battery data from tag,
        update width and height if needed.
        return battery nV, tag_type
        '''
        val = await client.read_gatt_char(self.chars['config'])
        self.log.debug(f'tag_data: {val.hex()}')
        flags, pid, app_version, hw_version, tag_type = self.decode_data(val)
        if isinstance(tag_type, dict):
            if tag_type['width'] != self.width or tag_type['height'] != self.height:
                self.log.warning(f'Tag size is different from default: width:{tag_type['width']}, height:{tag_type['height']} - updating values')
            self.width = tag_type['width']
            self.height = tag_type['height']
            self.voffset = tag_type['voffset']
        bat = await client.read_gatt_char(self.chars['battery'])
        batmv = self.decode_battery(bat) 
        return batmv, tag_type
            
    def decode_data(self, data, log=True):
        if len(data) < 8:
            self.log.warning(f'Advertising data too short: {len(data)} - should be 8 bytes')
            return
        flags       = data[0:2].hex()
        pid         = int.from_bytes(data[2:4], "big")
        app_version = f'{int.from_bytes(data[4:6], "big"):04X}'
        hw_version  = f'{int.from_bytes(data[6:8], "big"):04X}'
        tag_type    = self.types.get(pid, "Unknown")
        if log:
            self.log.info(f'flags: {flags}, pid: {pid} ({pid:04X}), app_version: {app_version}, hw_version: {hw_version}, type: {tag_type}')
        return flags, pid, app_version, hw_version, tag_type

    def decode_battery(self, data, log=True, byteorder="little"):
        '''
        battery info
        min battery 2.8V
        '''
        battery_mv = int.from_bytes(data[-2:], byteorder)
        if log:
            self.log.info(f'battery: {battery_mv}mv ({battery_mv/1000.0}V)')                # 3098 mV
        return battery_mv
        
    def decode_status(self, data):
        '''
        decode status bytes
        status[0]: 0xFF = busy (refreshing), 0x00 = idle
        status[1]: 0x00 = ok
                   0x01 = EPD init error  
                   0x02 = EPD write error
                   0x03 = data decompression error (wrong format)
                   0x04 = OTA error
                   0x05 = Unlock Failed
        '''
        busy = 'Busy' if data[0] == 0xFF else 'Idle'
        error = self.error_code.get(data[1], 'unknown')
        return busy, error
        
    async def set_up_status_notification(self, client):
        '''
        enable notifications on status char, and set self.status_event
        '''
        def notification_handler(sender, data):
            '''
            handle status notification updates
            '''
            self.log.debug(f"  {sender} <- Notification: {data.hex()}")
            busy, error = self.decode_status(data)
            self.log.info(f"Status update: BUSY={busy}, ERR={error}")
            self.status_event.set()
         
        self.status_event.clear()
        self.log.info(f"setting Notifications on status {self.chars['status'].uuid} Handle: {self.chars['status'].handle}")
        await client.start_notify(self.chars['status'], notification_handler)
        self.log.debug(f"Notifications enabled on {self.chars['status'].uuid}")
        
    async def authenticate(self, client):
        '''
        authenticate with plaintext and BLE_SECRET_KEY to unlock tag for writing
        '''
        plaintext = await client.read_gatt_char(self.chars['authenticate'])
        self.log.info(f'Authenticate Key: len({len(plaintext)}): {plaintext.hex()}')
        self.log.info("Sending BLE secret...")
        secret = self.gen_ble_secret(plaintext)
        self.log.debug(f"  Secret ({len(secret)} bytes): {secret.hex()}")
        await client.write_gatt_char(self.chars['authenticate'], secret, response=False)
        
    async def clear_screen(self, rgb=[0,0,255], on=80, off=500, duration=5000):
        '''
        clears the screen
        '''
        async def send_clear_screen(client):
            '''
            Clears the Screen
            CMD 0xA504
            '''
            self.log.info("Clearing screen...")
            await self.send_command(client, bytes([0x04, 0xA5]))
        
        await self.connect_and_execute(send_clear_screen)

    async def flash_led(self, rgb=[0,0,255], on=80, off=500, duration=5000):
        '''
        connect and flash the led blue for 5 seconds
        '''
        async def send_flash_led(client, rgb=[0,0,255], on=80, off=500, duration=5000):
            '''
            flash the led rgb color with on/off duty cycle for duration in mS
            CMD 0xA508 + Red(1B) + Green(1B) + Blue(1B) + on_ms(2B) + off_ms(2B) + work_ms(4B)
            '''
            self.log.info(f"Flashing LED on {self.mac_address} color:{rgb} with {on}/{off}mS for {duration/1000}s...")
            on = self.to_bytes(on, 2)
            off = self.to_bytes(off, 2)
            duration = self.to_bytes(duration)
            led_setting = bytes([0x08, 0xA5]) + bytes(rgb) + on + off + duration
            await self.send_command(client, led_setting)
            
        await self.connect_and_execute(send_flash_led, rgb, on, off, duration)
        
    async def wait_for_status_update(self):
        '''
        wait for status update notification
        '''
        try:
            await asyncio.wait_for(self.status_event.wait(), 30)    
        except asyncio.TimeoutError:
            self.log.info("Status response timeout")
            
    async def discover_services(self, client):
        '''
        discover services, populate self.chars for characteristics, and
        read/update status values
        '''
        services = client.services
        self.log.info(f"Services found: {len(list(services))}")
        for service in services:
            self.log.info(f"  Service: {service.uuid}")
            for char in service.characteristics:
                self.log.info(f"    Char: {char.uuid} Handle: {char.handle} [{', '.join(char.properties)}]")
                self.chars.update({ch:char for ch, uuid in self.WOLINK_UUIDS.items() if char.uuid==uuid})
                
    async def get_device(self):
        '''
        find device so that we can connect to it
        '''
        device = None
        while not device:
            try:
                self.log.info(f"Scanning for device: {self.mac_address}... <cntrl C to exit>")
                device = await BleakScanner.find_device_by_address(self.mac_address, timeout=60.0)
            except asyncio.CancelledError:
                sys.exit(1)
        return device
        
    async def send_command(self, client, command, response=False):
        '''
        send command to 'data' char, response is false by default
        '''
        await client.write_gatt_char(self.chars['data'], command, response=response)
        
    async def connect_and_execute(self, coro, *args, **kwargs):
        '''
        connect to tag and execute coroutine with 3 (default) reconnect attempts - 30 seond timeout on connection
        '''
        device = await self.get_device()
        for i in range(1,self.retries):    # 3 retries by default
            self.log.info(f"Connecting to {self.mac_address} attempt {i}...")
            try:
                async with BleakClient(device, timeout=30.0) as client:
                    self.log.info(f"Connected: {client.is_connected}")
                    # Discover services
                    await self.discover_services(client)
                    if not self.chars.get('data'):
                        self.log.warning("No data write characteristic found!")
                        return
                    # Read tag data
                    await self.get_tag_data(client)
                    # authenticate for writing
                    await self.authenticate(client)
                    return await coro(client, *args, **kwargs)
            except TimeoutError as e:
                self.log.warning(f'Timeout error connecting to {self.mac_address}: {e}')
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.log.error(f'error connecting to {self.mac_address}: {e}')
                raise
                
    async def send_image(self, filename=None):
        '''
        send image filename to tag
        '''
        async def send_data(client, filename=None):
            """
            send image data to connected client
            """
            # (optional) Set up status notification
            await self.set_up_status_notification(client)
            # Send data
            data = self.image_to_bitmap(filename)
            await self.send_noncompressed(client, data)
            # (optional) wait for update notification
            await self.wait_for_status_update()
            self.log.info("Done! Check the ESL display.")
        
        await self.connect_and_execute(send_data, filename)

    async def scan_devices(self, duration: float = 10.0):
        """
        Scan for Wolink ESL devices (name prefix 'WL').
        manufacturer ID in decimal 48042 = 0xBBEA. That's the Zhsunyco/Wolink company identifier in the Bluetooth SIG manufacturer registry.
        """
        self.log.info(f"Scanning for Wolink ESL devices ({duration}s)...")
        wolink_devices = []
        try:
            discovered = {}
            def callback(device, advertisement_data):
                discovered[device.address] = (device, advertisement_data)

            async with BleakScanner(callback) as scanner:
                await asyncio.sleep(duration)

            for device, advertisement_data in discovered.values():
                if (device.name or "").startswith("WL"):
                    mfr_id, mfr_bytes = next(iter(advertisement_data.manufacturer_data.items()))
                    self.log.debug(f'  mfr_bytes:    {mfr_bytes.hex()}')
                    decoded  = self.decode_data(mfr_bytes[:8], False)
                    batt_mv  = self.decode_battery(mfr_bytes[-2:], False, 'big')

                    flags, pid, app_ver, hw_ver, tag_type = decoded or ("-", 0, "-", "-", "Unknown")
                    type_str = tag_type['type'] if isinstance(tag_type, dict) else tag_type

                    self.log.info(f"  Found:         {device.address} ({device.name})")
                    self.log.info(f"  RSSI:          {advertisement_data.rssi} dBm")
                    self.log.info(f"  Battery:       {batt_mv}mV ({batt_mv/1000:.3f}V)")
                    self.log.info(f"  Type:          {type_str}")
                    self.log.info(f"  Firmware:      app={app_ver} hw={hw_ver}")
                    self.log.info(f"  Mfr:           0x{mfr_id:04X} flags={flags} pid={pid} ({pid:04X})")
                    # these are empty
                    #self.log.info(f"  Service UUIDS: {advertisement_data.service_uuids}")
                    #self.log.info(f"  Service data:  {advertisement_data.service_data}")
                    wolink_devices.append(device)

            if wolink_devices:
                self.log.info(f"Found {len(wolink_devices)} Wolink device(s)")
            else:
                self.log.info(f"No Wolink devices found (scanned {len(discovered)} total)")

        except asyncio.CancelledError:
            pass
        return wolink_devices


async def main():
    #----------- Global Variables -----------
    global log
    #-------------- Main --------------

    args = parseargs()
    logging.basicConfig(format='%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s' if args.verbose else '%(message)s',
                        force=True,
                        level=logging.DEBUG if args.debug else logging.INFO)
        
    log = logging.getLogger('Main')

    #------------ Main ------------------
    if args.verbose:
        log.info("*******************")
        log.info("* Program Started *")
        log.info("*******************")
        
        log.info("wolink_ble.py Version: %s" % __version__)
        log.info("Python Version: %s" % sys.version.replace('\n',''))
        log.debug("DEBUG mode on")
    
    if not args.mac_address and not args.scan:
        parser.self.log.info_help()
        log("Tip: Use --scan to find nearby Wolink ESL devices")
        sys.exit(1)
        
    ble = WOLINK(args.mac_address, args.width, args.height, args.retries)

    if args.scan:
        return await ble.scan_devices(args.scan_time)
        
    if args.led is not None:
        vals = [int(v) for v in args.led]
        led_args = {
            "rgb":      vals[0:3] if len(vals) >= 3 else [0, 0, 255],
            "on":       vals[3]   if len(vals) >= 4 else 80,
            "off":      vals[4]   if len(vals) >= 5 else 500,
            "duration": vals[5]   if len(vals) >= 6 else 5000,
        }
        log.info(f'sending LED: {led_args} (mS)')
        return await ble.flash_led(**led_args)
        
    if args.clear:
        return await ble.clear_screen()

    # Send to device
    await ble.send_image(args.image)


if __name__ == "__main__":
    asyncio.run(main())