import secrets
import string
import time
import uuid
from pathlib import Path

import aiosqlite
import bcrypt
from fastapi import BackgroundTasks, Cookie, FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field, EmailStr

BASE_DIR = Path(__file__).resolve().parent

CODE_EXPIRATION_TIME_SECONDS = 30 * 60


class Register(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=32)
    email: EmailStr


class Login(BaseModel):
    username: str
    password: str


class TwoFactor(BaseModel):
    code: str


app = FastAPI()

db_connection: aiosqlite.Connection


def random_id() -> str:
    return uuid.uuid4().hex


def random_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password_hash(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), hash.encode())


def get_current_time() -> int:
    return int(time.time())


async def send_email(email: str, message: str) -> None:
    with open(str(BASE_DIR / "code.txt"), "w") as fp:
        fp.write(message)


@app.on_event("startup")
async def startup():
    global db_connection
    db_connection = await aiosqlite.connect(BASE_DIR / "db.db")
    db_connection.row_factory = aiosqlite.Row

    await db_connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS two_factors (
            id TEXT NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL UNIQUE,
            code TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    await db_connection.commit()


@app.on_event("shutdown")
async def shutdown():
    await db_connection.close()


@app.post("/register")
async def register(data: Register):
    async with db_connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,),
    ) as cursor:
        user = await cursor.fetchone()

    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    await db_connection.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (data.username, get_password_hash(data.password), data.email),
    )
    await db_connection.commit()

    return {"success": True}


@app.post("/login")
async def login(data: Login, background_tasks: BackgroundTasks, response: Response):
    async with db_connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,),
    ) as cursor:
        user = await cursor.fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username",
        )

    if not check_password_hash(data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password",
        )

    two_factor_id = random_id()
    code = random_code(6)

    await db_connection.execute(
        "REPLACE INTO two_factors (id, user_id, code, timestamp) VALUES (?, ?, ?, ?)",
        (two_factor_id, user["id"], code, get_current_time()),
    )
    await db_connection.commit()

    response.set_cookie("two_factor_id", two_factor_id)

    background_tasks.add_task(send_email, user["email"], code)

    return {"success": True}


@app.post("/2fa")
async def two_factor(
    data: TwoFactor, response: Response, two_factor_id: str = Cookie(...)
):
    async with db_connection.execute(
        "SELECT users.* FROM users INNER JOIN two_factors ON(users.id = two_factors.user_id) WHERE two_factors.id = ? AND two_factors.code = ? AND two_factors.timestamp > ?",
        (two_factor_id, data.code, get_current_time() - CODE_EXPIRATION_TIME_SECONDS),
    ) as cursor:
        user = await cursor.fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code",
        )

    session_id = random_id()

    await db_connection.execute(
        "INSERT INTO sessions (id, user_id, timestamp) VALUES (?, ?, ?)",
        (session_id, user["id"], get_current_time()),
    )
    await db_connection.commit()

    response.set_cookie("session_id", session_id)

    return {"success": True}


@app.get("/me")
async def secret(session_id: str = Cookie(...)):
    async with db_connection.execute(
        "SELECT users.* FROM users INNER JOIN sessions ON(users.id = sessions.user_id) WHERE sessions.id = ?",
        (session_id,),
    ) as cursor:
        user = await cursor.fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )

    return f"Hi {user['username']}"


@app.post("/logout")
async def logout(response: Response, session_id: str = Cookie(...)):
    await db_connection.execute(
        "DELETE FROM sessions WHERE id = ?",
        (session_id,),
    )
    await db_connection.commit()

    response.delete_cookie("session_id")

    return {"success": True}
