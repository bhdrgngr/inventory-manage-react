from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, field_validator
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3
import re

# JWT ayarları
SECRET_KEY = "your-secret-key-change-this-in-production"  # Üretimde değiştirin!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

# Veritabanını başlat
def init_db():
    conn = sqlite3.connect('items.db')
    cursor = conn.cursor()
    
    # Items tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL
        )
    ''')
    
    # Users tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Pydantic modelleri
class User(BaseModel):
    username: str
    email: str

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, 
                         description="Kullanıcı adı 3-50 karakter arasında olmalıdır")
    email: EmailStr = Field(..., description="Geçerli bir e-posta adresi giriniz")
    password: str = Field(..., min_length=6, max_length=72,
                         description="Şifre 6-72 karakter arasında olmalıdır")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Kullanıcı adı sadece harf, rakam, tire ve alt çizgi içerebilir')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Şifre en az 6 karakter olmalıdır')
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Şifre çok uzun (maksimum 72 byte)')
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Şifre en az bir harf içermelidir')
        if not re.search(r'[0-9]', v):
            raise ValueError('Şifre en az bir rakam içermelidir')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str

class Item(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, 
                     description="Ürün adı 1-200 karakter arasında olmalıdır")
    description: str = Field(None, max_length=1000,
                            description="Açıklama en fazla 1000 karakter olabilir")
    price: float = Field(..., gt=0, description="Fiyat 0'dan büyük olmalıdır")

# Yardımcı fonksiyonlar
def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    # Bcrypt 72 byte limiti
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    # Bcrypt 72 byte limiti için şifreyi kısalt
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(username: str):
    conn = sqlite3.connect('items.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, hashed_password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return {"id": user[0], "username": user[1], "email": user[2]}

# Authentication endpoints
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    conn = sqlite3.connect('items.db')
    cursor = conn.cursor()
    
    # Kullanıcı zaten var mı kontrol et
    cursor.execute('SELECT username FROM users WHERE username = ? OR email = ?', (user.username, user.email))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Yeni kullanıcı ekle
    hashed_password = get_password_hash(user.password)
    cursor.execute(
        'INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)',
        (user.username, user.email, hashed_password)
    )
    conn.commit()
    conn.close()
    
    return {"username": user.username, "email": user.email}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user[3]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user[1]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoints
@app.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/")
async def read_root():
    return {"message": "Hello from backend!"}

@app.get("/items/{item_id}")
async def read_item(item_id: int, current_user: dict = Depends(get_current_user)):
    return {"item_id": item_id}

@app.get("/items")
async def read_items(current_user: dict = Depends(get_current_user)):
    conn = sqlite3.connect('items.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM items')
    items = cursor.fetchall()
    conn.close()
    return {"items": items}


@app.post("/add_item")
async def add_item(item: Item, current_user: dict = Depends(get_current_user)):
    conn = sqlite3.connect('items.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO items (name, description, price) VALUES (?, ?, ?)
    ''', (item.name, item.description, item.price))
    conn.commit()
    conn.close()
    return {"message": "Item added successfully"}