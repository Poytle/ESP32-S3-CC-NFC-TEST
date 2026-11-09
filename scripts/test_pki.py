from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parent.parent
flags=[]
for prefix in ['/opt/homebrew/opt/openssl@3','/usr/local/opt/openssl@3']:
    if Path(prefix,'include/openssl/bn.h').exists():
        flags=['-I'+prefix+'/include','-L'+prefix+'/lib']
        break
with tempfile.TemporaryDirectory() as tmp:
    binary=str(Path(tmp)/'pki-tests')
    subprocess.run(['c++','-std=c++11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-DNFC_HOST_OPENSSL','-I'+str(root/'include'),*flags,str(root/'tests/pki.cpp'),'-lcrypto','-o',binary],check=True)
    subprocess.run([binary],check=True)
