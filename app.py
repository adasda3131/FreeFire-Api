import asyncio
import functools
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
import lib2

# ========================
# Configuração do Flask
# ========================
app = Flask(__name__)
CORS(app)

# ========================
# Cache simples em memória
# ========================
cache_store = {}

def cache_get(ttl: int = 30):
    """Decora endpoints GET com cache por caminho+querystring."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = f"{request.path}?{request.query_string.decode()}"
            now = time.time()

            # Se existe no cache e ainda não expirou
            if cache_key in cache_store:
                value, expires_at = cache_store[cache_key]
                if now < expires_at:
                    return jsonify(value)

            # Caso contrário, gera a resposta
            result = func(*args, **kwargs)
            if isinstance(result, dict):
                cache_store[cache_key] = (result, now + ttl)
            return jsonify(result)
        return wrapper
    return decorator

# ========================
# Endpoint principal
# ========================
@app.route("/api/account", methods=["GET"])
@cache_get(ttl=30)
def get_account_info():
    """Busca informações de conta FreeFire."""
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    unknown_id = request.args.get("unknown_id", "0")
    endpoint = "/Account/GetAccountPersonalShow"

    if not uid or not region:
        return {"error": "Missing required parameters: uid, region"}

    try:
        result = asyncio.run(
            lib2.GetAccountInformation(uid, unknown_id, region, endpoint)
        )
        return result
    except Exception as e:
        return {"error": str(e)}

# ========================
# Healthcheck
# ========================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# ========================
# Main
# ========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
