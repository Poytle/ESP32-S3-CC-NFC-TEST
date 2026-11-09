"""Generate public-only synthetic EMV RSA fixtures; ephemeral private keys are never written."""
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
root,issuer,card = [rsa.generate_private_key(public_exponent=65537,key_size=1024) for _ in range(3)]
def modulus(key): return key.public_key().public_numbers().n.to_bytes(128,'big')
def signature(key, block):
    numbers=key.private_numbers()
    return pow(int.from_bytes(block,'big'),numbers.d,numbers.public_numbers.n).to_bytes(128,'big')
def finish(key,body,suffix=b''):
    return signature(key,body+hashlib.sha1(body[1:]+suffix).digest()+b'\xbc')
pan='4111111111111111'
static=bytes.fromhex('5A0841111111111111119F4A01822000')
issuer_body=bytes.fromhex('6A0241111111129901020301018003')+modulus(issuer)[:92]
icc_body=bytes.fromhex('6A04'+pan+'FFFF129901020301018003')+modulus(card)[:86]
issuer_rem=modulus(issuer)[92:];card_rem=modulus(card)[86:]
nonce=bytes.fromhex('01020304')
related=bytes.fromhex('01112233443800')
fdda_suffix=nonce+bytes(6)+bytes.fromhex('0356')+related
sdad_body=bytes.fromhex('6A050109081122334455667788')+b'\xbb'*(128-4-9-21)
bad_padding=sdad_body[:-1]+b'\x00'
values={'root_n':modulus(root),'issuer_n':modulus(issuer),'card_n':modulus(card),'exponent':bytes.fromhex('010001'),'issuer_cert':finish(root,issuer_body,issuer_rem+bytes.fromhex('010001')),'issuer_rem':issuer_rem,'card_cert':finish(issuer,icc_body,card_rem+bytes.fromhex('010001')+static),'card_rem':card_rem,'static_data':static,'nonce':nonce,'dda_sig':finish(card,sdad_body,nonce),'fdda_suffix':fdda_suffix,'fdda_sig':finish(card,sdad_body,fdda_suffix),'fdda_online_sig':finish(card,sdad_body[:1]+b'\x95'+sdad_body[2:],fdda_suffix),'bad_padding_sig':finish(card,bad_padding,nonce)}
lines=['#pragma once','#include "emv_pki.h"','namespace pki_vectors {']
for name,value in values.items(): lines.append('inline emvpki::Bytes '+name+'(){return {'+','.join(hex(b) for b in value)+'};}')
lines.append('}')
Path('include/pki_test_vectors.h').write_text('\n'.join(lines)+'\n')
