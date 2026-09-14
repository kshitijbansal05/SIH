from __future__ import annotations
import asyncio
import time
from datetime import datetime, timezone
from typing import Any
import hashlib
import hmac
import secrets
import sqlite3
import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Form
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="ThermalShield Weather API",
    version="1.0.0",
    description="Location-based weather backend for the ThermalShield passive shelter dashboard.",
)

app.add_middleware(
    SessionMiddleware,
    secret_key="CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_KEY",
    max_age=60 * 60 * 24 * 7,
    same_site="lax",
    https_only=False
)

app.mount("/static", StaticFiles(directory="static"), name="static")

OPEN_METEO_URL = "https://api.open-meteo.com/v1/forecast"
NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
NOMINATIM_USER_AGENT = "ThermalShield/1.0 (weather dashboard)"

DATABASE = "thermalshield.db"


def init_db():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


init_db()

weather_cache: dict[tuple[float, float], tuple[float, dict[str, Any]]] = {}
geocode_cache: dict[tuple[float, float], tuple[float, dict[str, Any]]] = {}
nominatim_lock = asyncio.Lock()
last_nominatim_request = 0.0

WEATHER_CODES = {
    0: "Clear sky",
    1: "Mainly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Depositing rime fog",
    51: "Light drizzle",
    53: "Moderate drizzle",
    55: "Dense drizzle",
    56: "Light freezing drizzle",
    57: "Dense freezing drizzle",
    61: "Slight rain",
    63: "Moderate rain",
    65: "Heavy rain",
    66: "Light freezing rain",
    67: "Heavy freezing rain",
    71: "Slight snow fall",
    73: "Moderate snow fall",
    75: "Heavy snow fall",
    77: "Snow grains",
    80: "Slight rain showers",
    81: "Moderate rain showers",
    82: "Violent rain showers",
    85: "Slight snow showers",
    86: "Heavy snow showers",
    95: "Thunderstorm",
    96: "Thunderstorm with slight hail",
    99: "Thunderstorm with heavy hail",
}

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split(":")

        salt = bytes.fromhex(salt_hex)
        stored = bytes.fromhex(hash_hex)

        calculated = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1
        )

        return hmac.compare_digest(calculated, stored)

    except Exception:
        return False

@app.get("/login")
async def login_page():
    return FileResponse("login.html")


@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return JSONResponse(
            {"error": "Invalid email or password"},
            status_code=401
        )

    request.session["user_id"] = user["id"]
    request.session["user_name"] = user["name"]
    request.session["user_email"] = user["email"]

    return RedirectResponse("/dashboard", status_code=303)


@app.get("/signup")
async def signup_page():
    return FileResponse("signup.html")


@app.post("/signup")
async def signup(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    name = name.strip()
    email = email.strip().lower()

    if password != confirm_password:
        return JSONResponse(
            {"error": "Passwords do not match"},
            status_code=400
        )

    if len(password) < 6:
        return JSONResponse(
            {"error": "Password must be at least 6 characters"},
            status_code=400
        )

    conn = sqlite3.connect(DATABASE)

    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing_user:
        conn.close()
        return JSONResponse(
            {"error": "Email already registered"},
            status_code=400
        )

    password_hash = hash_password(password)

    conn.execute(
        """
        INSERT INTO users (name, email, password_hash)
        VALUES (?, ?, ?)
        """,
        (name, email, password_hash)
    )

    conn.commit()
    conn.close()

    return RedirectResponse("/login", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/api/me")
async def current_user(request: Request):
    if "user_id" not in request.session:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    return {
        "id": request.session["user_id"],
        "name": request.session["user_name"],
        "email": request.session["user_email"]
    }

def climate_label(temp: float | None, humidity: float | None) -> str:
    if temp is None:
        return "Unknown climate"

    humidity = humidity if humidity is not None else 50.0

    if temp <= 5:
        return "Cold climate"
    if temp <= 15 and humidity < 65:
        return "Cool / dry climate"
    if temp >= 30 and humidity >= 65:
        return "Hot / humid climate"
    if temp >= 30:
        return "Hot / dry climate"
    if humidity >= 75:
        return "Warm / humid climate"
    return "Temperate climate"


def clean(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 2)
    return value


async def reverse_geocode(lat: float, lon: float) -> dict[str, Any]:
    global last_nominatim_request

    key = (round(lat, 4), round(lon, 4))
    cached = geocode_cache.get(key)
    if cached and time.time() - cached[0] < 300:
        return cached[1]

    async with nominatim_lock:
        wait = 1.05 - (time.time() - last_nominatim_request)
        if wait > 0:
            await asyncio.sleep(wait)

        params = {
            "lat": lat,
            "lon": lon,
            "format": "jsonv2",
            "zoom": 10,
            "addressdetails": 1,
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    NOMINATIM_URL,
                    params=params,
                    headers={"User-Agent": NOMINATIM_USER_AGENT},
                )
                last_nominatim_request = time.time()
                response.raise_for_status()
                data = response.json()
        except Exception:
            return {
                "name": f"{lat:.4f}, {lon:.4f}",
                "address": {},
            }

    address = data.get("address", {})
    name = (
        address.get("city")
        or address.get("town")
        or address.get("village")
        or address.get("municipality")
        or address.get("county")
        or address.get("state")
        or data.get("display_name")
        or f"{lat:.4f}, {lon:.4f}"
    )

    result = {"name": name, "address": address}
    geocode_cache[key] = (time.time(), result)
    return result


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "ThermalShield Weather API"}


@app.get("/api/weather")
async def weather(
    lat: float = Query(..., ge=-90, le=90),
    lon: float = Query(..., ge=-180, le=180),
) -> dict[str, Any]:
    key = (round(lat, 4), round(lon, 4))
    cached = weather_cache.get(key)

    if cached and time.time() - cached[0] < 300:
        return cached[1]

    current_vars = (
        "temperature_2m,relative_humidity_2m,apparent_temperature,"
        "wind_speed_10m,wind_direction_10m,shortwave_radiation,"
        "precipitation,weather_code"
    )
    hourly_vars = (
        "temperature_2m,relative_humidity_2m,wind_speed_10m,"
        "wind_direction_10m,shortwave_radiation,"
        "precipitation_probability,weather_code"
    )

    params = {
        "latitude": lat,
        "longitude": lon,
        "current": current_vars,
        "hourly": hourly_vars,
        "forecast_hours": 24,
        "timezone": "auto",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(OPEN_METEO_URL, params=params)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Weather provider request failed: {exc}",
        ) from exc

    current = data.get("current", {})
    hourly = data.get("hourly", {})
    geo = await reverse_geocode(lat, lon)

    temp = current.get("temperature_2m")
    humidity = current.get("relative_humidity_2m")
    wind = current.get("wind_speed_10m")
    radiation = current.get("shortwave_radiation")
    code = current.get("weather_code")

    response_data = {
        "location": {
            "name": geo["name"],
            "latitude": clean(data.get("latitude", lat)),
            "longitude": clean(data.get("longitude", lon)),
            "timezone": data.get("timezone"),
            "elevation": clean(data.get("elevation")),
            "climate": climate_label(temp, humidity),
        },
        "current": {
            "temperature": clean(temp),
            "humidity": clean(humidity),
            "apparent_temperature": clean(current.get("apparent_temperature")),
            "wind_speed": clean(wind),
            "wind_direction": clean(current.get("wind_direction_10m")),
            "solar_radiation": clean(radiation),
            "precipitation": clean(current.get("precipitation")),
            "weather_code": code,
            "weather_description": WEATHER_CODES.get(code, "Unknown conditions"),
            "time": current.get("time"),
        },
        "hourly": {
            "time": hourly.get("time", []),
            "temperature": hourly.get("temperature_2m", []),
            "humidity": hourly.get("relative_humidity_2m", []),
            "wind_speed": hourly.get("wind_speed_10m", []),
            "wind_direction": hourly.get("wind_direction_10m", []),
            "solar_radiation": hourly.get("shortwave_radiation", []),
            "precipitation_probability": hourly.get("precipitation_probability", []),
            "weather_code": hourly.get("weather_code", []),
        },
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }

    weather_cache[key] = (time.time(), response_data)
    return response_data

@app.get("/")
async def home():
    return FileResponse("index.html")


@app.get("/dashboard")
async def dashboard(request: Request):
    if "user_id" not in request.session:
        return RedirectResponse("/")

    return FileResponse("dashboard.html")