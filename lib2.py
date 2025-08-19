from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
import httpx
import asyncio
import json
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from typing import Tuple

# ---------------- Configurações ----------------
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB48"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = ["IND", "BR", "SG", "RU", "ID", "TW", "US", "VN", "TH", "ME", "PK", "CIS"]
ACCOUNTS = {
    'IND': "uid=3128851125&password=A2E0175866917124D431D93C8F0179502108F92B9E22B84F855730F2E70ABEA4",
    'SG': "uid=3158350464&password=70EA041FCF79190E3D0A8F3CA95CAAE1F39782696CE9D85C2CCD525E28D223FC",
    'RU': "uid=3301239795&password=DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475",
    'ID': "uid=3301269321&password=D11732AC9BBED0DED65D0FED7728CA8DFF408E174202ECF1939E328EA3E94356",
    'TW': "uid=3301329477&password=359FB179CD92C9C1A2A917293666B96972EF8A5FC43B5D9D61A2434DD3D7D0BC",
    'US': "uid=3301387397&password=BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128",
    'VN': "uid=3301447047&password=044714F5B9284F3661FB09E4E9833327488B45255EC9E0CCD953050E3DEF1F54",
    'TH': "uid=3301470613&password=39EFD9979BD6E9CCF6CBFF09F224C4B663E88B7093657CB3D4A6F3615DDE057A",
    'ME': "uid=3301535568&password=BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517",
    'PK': "uid=3301828218&password=3A0E972E57E9EDC39DC4830E3D486DBFB5DA7C52A4E8B0B8F3F9DC4450899571",
    'CIS': "uid=3309128798&password=412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F",
    'BR': "uid=3158668455&password=44296D19343151B25DE68286BDC565904A0DA5A5CC5E96B7A7ADBE7C11E07933"
}

# ---------------- Funções Criptográficas ----------------
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    return aes.encrypt(padded_plaintext)

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(ciphertext)
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        return decrypted  # fallback se padding estiver errado

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance

# ---------------- JWT e Login ----------------
async def getAccess_Token(account: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=payload, headers=headers)
        data = response.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

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
        decrypted_bytes = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, response.content)
        try:
            message_proto = decode_protobuf(decrypted_bytes, FreeFire_pb2.LoginRes)
            message_dict = json.loads(json_format.MessageToJson(message_proto))
            token = message_dict.get("token", "0")
            region_locked = message_dict.get("lockRegion", "0")
            serverUrl = message_dict.get("serverUrl", "0")
            return f"Bearer {token}", region_locked, serverUrl
        except Exception as e:
            print("JWT Decode Failed:", e)
            print("Preview HEX:", decrypted_bytes[:100].hex())
            return "0", "0", "0"

# ---------------- Account Info ----------------
async def GetAccountInformation(ID, UNKNOWN_ID, regionMain, endpoint):
    json_data = json.dumps({
        "a": ID,
        "b": UNKNOWN_ID
    })
    encoded_result = await json_to_proto(json_data, main_pb2.GetPlayerPersonalShow())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
    regionMain = regionMain.upper()

    if regionMain not in SUPPORTED_REGIONS:
        return {
            "error": "Invalid request",
            "message": f"Unsupported 'region' parameter. Supported regions are: {', '.join(SUPPORTED_REGIONS)}."
        }

    token, region_locked, serverUrl = await create_jwt(regionMain)
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

        try:
            message_proto = decode_protobuf(decrypted_bytes, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            message_dict = json.loads(json_format.MessageToJson(message_proto))
            return message_dict
        except Exception as e:
            return {
                "error": "Account info fetch failed",
                "exception": str(e),
                "preview_hex": decrypted_bytes[:100].hex()
            }

# ---------------- Exemplo de uso ----------------
async def main():
    result = await GetAccountInformation(ID=12345, UNKNOWN_ID=67890, regionMain="BR", endpoint="/MajorQuery/GetPlayerPersonalShow")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
