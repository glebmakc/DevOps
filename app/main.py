from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import os
from fastapi.responses import FileResponse

app = FastAPI()

BLACKLIST_PATH = "blacklist.txt"
DATABASE_PATH = "logins.db"

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        time TEXT,
                        country TEXT,
                        device TEXT,
                        attempts INTEGER
                    )''')
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup_event():
    init_db()

def is_blacklisted(ip: str) -> bool:
    if not os.path.exists(BLACKLIST_PATH):
        return False
    with open(BLACKLIST_PATH, 'r') as f:
        return ip.strip() in f.read().splitlines()

def add_to_blacklist(ip: str):
    with open(BLACKLIST_PATH, "a") as f:
        f.write(ip + "\n")
    print(f"[BLACKLIST] Added IP {ip}")

def get_country(ip: str) -> str:
    return "Russia" if ip.startswith("192") else "China"

def log_attempt(ip: str, country: str, device: str):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logins WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,))
    row = cursor.fetchone()
    attempts = row[5] + 1 if row else 1
    cursor.execute("INSERT INTO logins (ip, time, country, device, attempts) VALUES (?, ?, ?, ?, ?)",
                   (ip, datetime.utcnow().isoformat(), country, device, attempts))
    conn.commit()
    conn.close()
    print(f"[LOG] IP {ip} - Attempts: {attempts}")  # отладка
    return attempts

class LoginRequest(BaseModel):
    ip: str
    device: str
    is_new_device: bool

@app.post("/login")
async def login(data: LoginRequest):
    ip = data.ip
    country = get_country(ip)

    if is_blacklisted(ip):
        raise HTTPException(status_code=403, detail="BLOCKED")

    attempts = log_attempt(ip, country, data.device)

    if attempts > 5:
        if not is_blacklisted(ip):
            add_to_blacklist(ip)
        raise HTTPException(status_code=403, detail="BLOCKED_TEMPORARY")

    if data.is_new_device:
        return {"status": "NEED_SMS"}

    return {"status": "ACCESS_OK"}

@app.get("/")
async def root():
    return FileResponse('index.html')
