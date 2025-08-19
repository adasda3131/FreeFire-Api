from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
import json
import asyncio
import re
import logging


import lib2



app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)



CACHE_TTL_SECONDS = 300
cache = TTLCache(maxsize=256, ttl=CACHE_TTL_SECONDS)




def cached_endpoint(ttl=CACHE_TTL_SECONDS):

def decorator(func):
  @wraps(func)
def wrapper(*args, **kwargs):

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

  body, status, headers = result
  if status == 200 and isinstance(body, str):
  cache[cache_key] = (body, status, headers)
  except Exception:

pass


  return result
  return wrapper
  return decorator





UID_PATTERN = re.compile(r"^\d{6,20}$") 
app.run(port=3000, host='0.0.0.0', debug=True)
