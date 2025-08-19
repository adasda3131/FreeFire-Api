import asyncio
import json
from typing import Tuple
import httpx
from google.protobuf import json_format
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2  # ajuste conforme seus imports

MAIN_KEY = b"YOUR_MAIN_KEY_16B"
MAIN_IV = b"YOUR_MAIN_IV_16B"
USERAGENT = "YourUserAgentString"
RELEASEVERSION = "YourReleaseVersion"
ACCOUNTS = {"BR": {"account_data": "data"}}
SUPPORTED_REGIONS = ["BR", "NA", "EU"]

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # ⚡ Torna a função robusta: se não for múltiplo de 16, adiciona padding temporário
    remainder = len(ciphertext) % 16
    if remainder != 0:
        ciphertext += b"\0" * (16 - remainder)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        # fallback: retorna bytes sem unpad se estiver errado
        return cipher.decrypt(ciphertext)

async def json_to_proto(json_data: str, proto_class) -> bytes:
    message = proto_class()
    json_format.Parse(json_data, message)
    return message.SerializeToString()

async def decode_protobuf(data: bytes, proto_class):
    message = proto_class()
    try:
        message.ParseFromString(data)
        return message
    except Exception:
        return None

async def getAccess_Token(account) -> Tuple[str, str]:
    return "access_token_example", "open_id_example"

async def create_jwt(region: str) -> Tuple[str, str, str]:
    account = ACCOUNTS.get(region)
    access_token, open_id = await getAccess_Token(account)
    json_data = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    encoded_result = await json_to_proto(json_data, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=payload, headers=headers)
        if response.status_code != 200:
            return "0", "0", "0"

        decrypted_bytes = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, response.content)
        decoded = await decode_protobuf(decrypted_bytes, FreeFire_pb2.LoginRes)
        if decoded is None:
            return "0", "0", "0"

        message_dict = json.loads(json_format.MessageToJson(decoded))
        token = message_dict.get("token", "0")
        region = message_dict.get("lockRegion", "0")
        serverUrl = message_dict.get("serverUrl", "0")
        return f"Bearer {token}", region, serverUrl

async def GetAccountInformation(ID, UNKNOWN_ID, regionMain, endpoint):
    json_data = json.dumps({"a": ID, "b": UNKNOWN_ID})
    # ⚡ Passando a classe, não a instância
    encoded_result = await json_to_proto(json_data, main_pb2.GetPlayerPersonalShow)
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    regionMain = regionMain.upper()
    if regionMain in SUPPORTED_REGIONS:
        token, region, serverUrl = await create_jwt(regionMain)
    else:
        return {"error": "Invalid region", "supported": SUPPORTED_REGIONS}

    if token == "0":
        return {"error": "JWT generation failed"}

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(serverUrl + endpoint, data=payload, headers=headers)
        decrypted_bytes = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, response.content)
        decoded = await decode_protobuf(decrypted_bytes, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        if decoded is None:
            return {"error": "Decode failed", "preview": response.content[:200].hex()}

        return json.loads(json_format.MessageToJson(decoded))
