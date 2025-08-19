from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
import json
import asyncio
import re
import logging


# Importa a lib async
import lib2


# --------------------
# Config Flask
# --------------------
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)


# Cache com TTL (5 minutos por padrão)
CACHE_TTL_SECONDS = 300
cache = TTLCache(maxsize=256, ttl=CACHE_TTL_SECONDS)




def cached_endpoint(ttl=CACHE_TTL_SECONDS):
"""Decora endpoints GET com cache por caminho+querystring.
Cacheia somente respostas 200 e corpo JSON (string).
"""
def decorator(func):
@wraps(func)
def wrapper(*args, **kwargs):
# Inclui método no cache key para segurança (ainda que só GET use)
cache_key = (
request.method,
request.path,
tuple(sorted(request.args.items())),
)
if cache_key in cache:
app.logger.debug("Cache HIT: %s", cache_key)
return cache[cache_key]


app.logger.debug("Cache MISS: %s", cache_key)
result = func(*args, **kwargs)


try:
# Só cacheia respostas 200 com body JSON string
body, status, headers = result
if status == 200 and isinstance(body, str):
cache[cache_key] = (body, status, headers)
except Exception:
# Se o handler retornou Response/tuple não padrão, ignore cache
pass


return result
return wrapper
return decorator




# Helpers de validação
UID_PATTERN = re.compile(r"^\d{6,20}$") # UID numérico típico (ajuste se necessário)
app.run(port=3000, host='0.0.0.0', debug=True)
