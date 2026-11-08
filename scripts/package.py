"""Create flashable merged image plus individual images and checksums."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
base = Path('.pio/build/esp32-s3')
out = Path('firmware')
out.mkdir(exist_ok=True)
parts = [(0, 'bootloader.bin'), (0x8000, 'partitions.bin'), (0xe000, 'boot_app0.bin'), (0x10000, 'firmware.bin')]
# boot_app0 is part of the pinned Arduino framework, not the build output.
boot = Path.home() / '.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin'
for offset, name in parts:
    shutil.copy2(boot if name == 'boot_app0.bin' else base / name, out / name)
args = [sys.executable, '-m', 'esptool', '--chip', 'esp32s3', 'merge_bin', '-o', str(out / 'merged.bin')]
for offset, name in parts:
    args.extend([hex(offset), str(out / name)])
subprocess.run(args, check=True)
(out / 'flash-layout.json').write_text(json.dumps({hex(o): n for o, n in parts}, indent=2))
shutil.copy2(base / 'firmware.elf', out / 'firmware.elf')
shutil.copy2('README.md', out / 'README.md')
(out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(out.iterdir()) if p.name != 'SHA256SUMS'))
