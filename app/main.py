from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from databases import Database
import os
from fastapi.responses import FileResponse
import asyncio
import logging

app = FastAPI()

BLACKLIST_PATH = "blacklist.txt"
LOG_FILE_PATH = "app.log"  # файл логов

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db:5432/postgres")
database = Database(DATABASE_URL)

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Инициализация БД
async def init_db():
    query = """
    CREATE TABLE IF NOT EXISTS logins (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(50),
        time TIMESTAMP,
        country VARCHAR(50),
        device VARCHAR(50),
        attempts INTEGER
    )
    """
    await database.execute(query)
    logger.info("Таблица logins инициализирована")

@app.on_event("startup")
async def startup():
    for i in range(10):
        try:
            await database.connect()
            await init_db()
            logger.info("Успешно подключились к базе")
            break
        except Exception as e:
            logger.error(f"Ошибка подключения к базе, попытка {i+1}: {e}")
            await asyncio.sleep(2)
    else:
        logger.critical("Не удалось подключиться к базе после 10 попыток")
        raise Exception("DB connection failed")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logger.info("Отключились от базы")

def is_blacklisted(ip: str) -> bool:
    if not os.path.exists(BLACKLIST_PATH):
        return False
    with open(BLACKLIST_PATH, 'r') as f:
        blacklisted = ip.strip() in f.read().splitlines()
    logger.debug(f"Проверка IP {ip} на blacklist: {blacklisted}")
    return blacklisted

def add_to_blacklist(ip: str):
    with open(BLACKLIST_PATH, "a") as f:
        f.write(ip + "\n")
    logger.info(f"[BLACKLIST] Добавлен IP {ip}")

def get_country(ip: str) -> str:
    # Пример заглушки
    country = "Russia" if ip.startswith("192") else "China"
    logger.debug(f"Определили страну для IP {ip}: {country}")
    return country

async def log_attempt(ip: str, country: str, device: str):
    query = "SELECT attempts FROM logins WHERE ip = :ip ORDER BY id DESC LIMIT 1"
    row = await database.fetch_one(query=query, values={"ip": ip})
    attempts = row["attempts"] + 1 if row else 1

    insert_query = """
    INSERT INTO logins(ip, time, country, device, attempts)
    VALUES (:ip, :time, :country, :device, :attempts)
    """
    await database.execute(query=insert_query, values={
        "ip": ip,
        "time": datetime.utcnow(),
        "country": country,
        "device": device,
        "attempts": attempts
    })
    logger.info(f"[LOG] IP {ip} - Attempts: {attempts}")
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
        logger.warning(f"Доступ заблокирован для IP {ip} — в blacklist")
        raise HTTPException(status_code=403, detail="BLOCKED")

    attempts = await log_attempt(ip, country, data.device)

    if attempts > 5:
        if not is_blacklisted(ip):
            add_to_blacklist(ip)
        logger.warning(f"Временная блокировка IP {ip} — превышено количество попыток: {attempts}")
        raise HTTPException(status_code=403, detail="BLOCKED_TEMPORARY")

    if data.is_new_device:
        logger.info(f"IP {ip} — новый девайс, требуется SMS подтверждение")
        return {"status": "NEED_SMS"}

    logger.info(f"IP {ip} — успешный доступ")
    return {"status": "ACCESS_OK"}

@app.get("/")
async def root():
    return FileResponse('app/index.html')
