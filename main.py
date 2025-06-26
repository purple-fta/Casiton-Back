from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy import create_engine
from validate import validate_initData
from pydantic import BaseModel
from dotenv import load_dotenv
from jose import JWTError, jwt
from random import randint, choice``

import hashlib
import hmac
import os

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Base(DeclarativeBase):
	pass

class User(Base): 
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True) 
    balance: Mapped[float] = mapped_column()


TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN is not set in environment variables")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

need_to_create_db = False
if not os.path.exists("app.db"):
    need_to_create_db = True
engine = create_engine(
	"sqlite:///app.db", echo=False
)
if need_to_create_db:
    Base.metadata.create_all(engine)

class InitDataRequest(BaseModel):
    initData: str


def create_jwt(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256") # type: ignore
    return encoded_jwt

def verify_jwt(jwt_token: str):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"]) # type: ignore
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate JWT"
        )



@app.post("/api/auth/initData")
def auth_telegram(req: InitDataRequest):
    user_data = validate_initData(req.initData, TELEGRAM_BOT_TOKEN) # type: ignore

    if not user_data:
        raise HTTPException(status_code=403, detail="Invalid Telegram initData")
    
    with Session(engine) as session:
        user = session.query(User).where(User.id == user_data["user"]["id"]).first() # type: ignore
        if not user:
            user = User(id=user_data["user"]["id"], balance=10) # type: ignore
            session.add(user)
            session.commit()
        balance = user.balance

    jwt = create_jwt({"id": user.id}) # type: ignore

    return {"ok": True, "jwt": jwt, "balance": round(balance, 2)}

@app.get("/api/roll/{amount}")
def get_roll(amount: float, jwt_token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(jwt_token)
    
    base_items = [
        ["#FF5555", " X ", lambda _: 0],
        ["#f38ba8", "/10", lambda x: x/10],
        ["#eba0ac",  "/5", lambda x: x/5],
        ["#f5c2e7",  "/2", lambda x: x/2],
        ["#f9e2af",  "x2", lambda x: x*2],
        ["#94e2d5",  "x3", lambda x: x*3],
        ["#a6e3a1",  "x5", lambda x: x*5],
        ["#74c7ec",  "x8", lambda x: x*8],
        ["#cba6f7", "x10", lambda x: x*10],
    ];

    items = []
    i = 0
    while i < 100:
        # if (randint(0, 1) == 1 or i == 2):
        random_item = choice(base_items)
        items.append([random_item[0], random_item[1]])
        # else:
            # items.append(["#6c7086", "   "])
        i += 1

    selected_item = randint(50, 95)
    new_balance = 10
    with Session(engine) as session:
        user = session.query(User).where(User.id == payload["id"]).first() # type: ignore

        if amount > round(user.balance, 2):
            raise HTTPException(status_code=409, detail=f"Not enough funds in the balance. Balance: {user.balance} Bet: {amount}")

        new_balance = user.balance - amount
        for i in base_items:
            if i[0] == items[selected_item][0]:
                new_balance += i[2](amount) # type: ignore
                new_balance = new_balance
                break
        else:
            new_balance = user.balance
        new_balance = new_balance
        user.balance = new_balance
        session.commit()
        
    return {"items": items, "selected": selected_item, "newBalance": round(new_balance, 2)}
