# tmdb.py
import os
import requests

TMDB_BASE = "https://api.themoviedb.org/3"
IMG_BASE = "https://image.tmdb.org/t/p"
LANG = "ru-RU"

# ⚠️ сюда положи свой v4 access token (начинается с eyJhb...)
AGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONYAGONY

if not TMDB_BEARER:
    raise RuntimeError("Укажи токен TMDB_BEARER (v4) в переменных окружения!")

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TMDB_BEARER}",
    "Accept": "application/json"
})

def _get(endpoint, params=None):
    url = f"{TMDB_BASE}{endpoint}"
    resp = session.get(url, params=params or {})
    resp.raise_for_status()
    return resp.json()

def img_url(path, size="w342"):
    if not path:
        return None
    return f"{IMG_BASE}/{size}{path}"

def trending(media_type="all", time_window="week", page=1):
    return _get(f"/trending/{media_type}/{time_window}", {"language": LANG, "page": page})

def details(media_type, tmdb_id):
    return _get(f"/{media_type}/{tmdb_id}", {"language": LANG})

def search(query, scope="multi", page=1):
    return _get(f"/search/{scope}", {"query": query, "language": LANG, "page": page})

def season_details(tv_id, season_number):
    return _get(f"/tv/{tv_id}/season/{season_number}", {"language": LANG})



