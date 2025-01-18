from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import databases, sqlalchemy
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from passlib.context import CryptContext
import aiofiles
import uuid

app = FastAPI()

security = HTTPBasic()

DATABASE_URL = "postgresql://mihailpiksaev:5035@localhost/postgres"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

admin = sqlalchemy.Table(
    "admin",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("admin_username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("admin_password", sqlalchemy.String),
)

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("email", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
)

bookings = sqlalchemy.Table(
    "bookings",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("movie_id", sqlalchemy.Integer),
    sqlalchemy.Column("seat_number", sqlalchemy.String),
    sqlalchemy.Column("booking_time", sqlalchemy.String),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Booking(BaseModel):
    movie_id: int
    seat_number: str
    booking_time: str

class Admin(BaseModel):
    admin_username: str
    admin_password: str

class User(BaseModel):
    username: str
    email: str
    password: str

@app.on_event("startup")
async def on_startup():
    await database.connect()

@app.on_event("shutdown")
async def on_shutdown():
    await database.disconnect()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def authenticate_user(username: str, password: str):
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    if user and verify_password(password, user['password']):
        return user
    return False

async def authenticate_admin(username: str, password: str):
    query = admin.select().where(admin.c.admin_username == username)
    admin_user = await database.fetch_one(query)
    if admin_user and verify_password(password, admin_user['admin_password']):
        return admin_user
    return False

@app.post("/admin/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    admin_user = await authenticate_admin(credentials.username, credentials.password)
    if not admin_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"message": "Authorized"}

@app.get("/admin/bookings", dependencies=[Depends(security)])
async def get_bookings(credentials: HTTPBasicCredentials = Depends(security)):
    admin_user = await authenticate_admin(credentials.username, credentials.password)
    if not admin_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    query = bookings.select()
    all_bookings = await database.fetch_all(query)
    return all_bookings

@app.get("/", response_class=HTMLResponse)
async def read_root():
    async with aiofiles.open('/Users/mihailpiksaev/Desktop/МОЙ САЙТ/Prikol/index.html', mode='r') as f:
        html_content = await f.read()
    return HTMLResponse(content=html_content)

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    async with aiofiles.open('/Users/mihailpiksaev/Desktop/МОЙ САЙТ/Prikol/register.html', mode='r') as f:
        html_content = await f.read()
    return HTMLResponse(content=html_content)

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    async with aiofiles.open('/Users/mihailpiksaev/Desktop/МОЙ САЙТ/Prikol/login.html', mode='r') as f:
        html_content = await f.read()
    return HTMLResponse(content=html_content)

def generate_session_id() -> str:
    return uuid.uuid4().hex

@app.post("/book-seat/")
async def book_seat(booking: Booking, request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    username = request.cookies.get("username")
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    query = bookings.select().where(
        (bookings.c.movie_id == booking.movie_id) &
        (bookings.c.seat_number == booking.seat_number) &
        (bookings.c.booking_time == booking.booking_time)
    )
    existing_booking = await database.fetch_one(query)
    if existing_booking:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Это место уже забронировано на это время."
        )

    query = bookings.insert().values(
        username=user["id"],
        movie_id=booking.movie_id,
        seat_number=booking.seat_number,
        booking_time=booking.booking_time,
    )
    last_record_id = await database.execute(query)
    return {"id": last_record_id}

@app.post("/register/")
async def register(user: User):
    query = users.select().where(users.c.username == user.username)
    existing_user = await database.fetch_one(query)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким ником уже существует."
        )

    hashed_password = pwd_context.hash(user.password)
    query = users.insert().values(
        username=user.username,
        email=user.email,
        password=hashed_password  
    )
    last_record_id = await database.execute(query)
    
    session_id = generate_session_id()
    response = RedirectResponse(url="/online-cinema", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    response.set_cookie(key="username", value=user.username, httponly=True)
    return response

@app.post("/login")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    user = await authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    session_id = generate_session_id()
    response = JSONResponse({"detail": "Logged in"})
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    response.set_cookie(key="username", value=credentials.username, httponly=True) 
    return response

@app.get("/online-cinema", response_class=HTMLResponse)
async def online_cinema():
    async with aiofiles.open('/Users/mihailpiksaev/Desktop/МОЙ САЙТ/Prikol/movie.html', mode='r') as f:
        html_content = await f.read()
    return HTMLResponse(content=html_content)

@app.get("/my-bookings/")
async def get_my_bookings(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    username = request.cookies.get("username")
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    
    query = bookings.select().where(bookings.c.username == user["id"])
    user_bookings = await database.fetch_all(query)
    return user_bookings

@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    async with aiofiles.open('/Users/mihailpiksaev/Desktop/МОЙ САЙТ/Prikol/admin.html', mode='r') as f:
        html_content = await f.read()
    return HTMLResponse(content=html_content)