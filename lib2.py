import asyncio
import json
from typing import Tuple, Union
from urllib.parse import urljoin


import httpx
from google.protobuf import json_format
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2


# ============================
# Configurações obrigatórias
# ============================
MAIN_KEY = b"YOUR_MAIN_KEY_16B" # 16/24/32 bytes
MAIN_IV = b"YOUR_MAIN_IV_16B" # 16 bytes
USERAGENT = "YourUserAgentString"
RELEASEVERSION = "YourReleaseVersion"


# Contas por região (exemplo fictício)
ACCOUNTS = {
"BR": {"account_data": "data"},
"NA": {"account_data": "data"},
"EU": {"account_data": "data"},
}


SUPPORTED_REGIONS = {"BR", "NA", "EU"}


# ============================
# Utilidades criptográficas
# ============================


def _adjust_key_iv(key: bytes, iv: bytes) -> tuple[bytes, bytes]:
if len(key) not in (16, 24, 32):
key = key[:32].ljust(32, b'\0') # corta/completa até 32 bytes
if len(iv) != 16:
iv = iv[:16].ljust(16, b'\0') # corta/completa até 16 bytes
return key, iv




def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
key, iv = _adjust_key_iv(key, iv)
cipher = AES.new(key, AES.MODE_CBC, iv)
return cipher.encrypt(pad(data, AES.block_size))




def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
key, iv = _adjust_key_iv(key, iv)
# Garante múltiplo de 16 para evitar ValueError no decrypt
remainder = len(ciphertext) % 16
if remainder != 0:
ciphertext += b"\0" * (16 - remainder)
cipher = AES.new(key, AES.MODE_CBC, iv)
try:
return unpad(cipher.decrypt(ciphertext), AES.block_size)
except ValueError:
# Se o padding estiver ausente/incorreto, retorna bytes brutos de decrypt
return cipher.decrypt(ciphertext)


# ============================
# Protobuf helpers
# ============================


async def json_to_proto(json_data: Union[str, dict], proto_class) -> bytes:
"""Converte JSON/dict em bytes protobuf do tipo proto_class."""
if isinstance(json_data, dict):
json_str = json.dumps(json_data)
else:
json_str = json_data


message = proto_class()
# Parse estrito; se necessário, defina ignore_unknown_fields=True
return f"Beare
