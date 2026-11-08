"""Host tests for the exact TLV parser used by firmware (no MCU needed)."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as tmp:
    binary = str(Path(tmp) / 'tlv-test')
    subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Werror', '-I', str(root / 'include'), str(root / 'tests/tlv.cpp'), '-o', binary], check=True)
    subprocess.run([binary], check=True)

with tempfile.TemporaryDirectory() as tmp:
    binary = str(Path(tmp) / 'pn532-test')
    subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Werror', '-I', str(root / 'tests/stubs'), '-I', str(root / 'include'), str(root / 'tests/pn532.cpp'), '-o', binary], check=True)
    subprocess.run([binary], check=True)
