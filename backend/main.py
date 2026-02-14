# backend/main.py
import os
import re
import shutil
import logging
from datetime import datetime, timedelta, date, time
from typing import Optional, Any, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text

from database import get_db, engine
from models import Base, User, GuideSleep, Comment, DiarySleep, Vote, Quest
from schemas import (
    UserUpdate,
    UserOut,
    LoginRequest,
    GuideSleepCreate,
    CommentCreate,
    CommentOut,
    DiarySleepCreate,
    DiarySleepStart,
    DiarySleepWake,
    DiarySleepOut,
    QuestCreate,
    QuestOut,
    QuestUpdate,
)
from passlib.context import CryptContext
from jose import jwt, JWTError

# ---------------------------
# Basic logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flashsleep.backend")

# ---------------------------
# Config
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://10.0.2.2:8000")

# create tables declared in models (dev convenience)
Base.metadata.create_all(bind=engine)

# Ensure votes table exists (simple SQL table used by vote endpoints)
try:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS votes (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  guidesleep_id INTEGER NOT NULL,
                  value INTEGER NOT NULL,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                  UNIQUE(user_id, guidesleep_id)
                )
                """
            )
        )
        logger.info("Ensured votes table exists")
except Exception as e:
    logger.exception("Failed to ensure votes table: %s", e)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ---------------------------
# Runtime DB fix helper
# ---------------------------
def ensure_diarysleeptable_columns():
    stmts = [
        ("actual_wake_hour", "INT NULL"),
        ("total_sleep_minutes", "INT NULL"),
        ("actual_sleep_start", "DATETIME NULL"),
        ("actual_wake_time", "DATETIME NULL"),
    ]

    with engine.connect() as conn:
        for col_name, col_type in stmts:
            try:
                check_sql = text(f"SELECT {col_name} FROM diarysleep LIMIT 1")
                try:
                    conn.execute(check_sql)
                    continue
                except Exception:
                    pass

                try:
                    alter_sql = text(f"ALTER TABLE diarysleep ADD COLUMN IF NOT EXISTS {col_name} {col_type}")
                    conn.execute(alter_sql)
                    continue
                except Exception:
                    try:
                        alter_sql_alt = text(f"ALTER TABLE diarysleep ADD COLUMN {col_name} {col_type}")
                        conn.execute(alter_sql_alt)
                        continue
                    except Exception as e:
                        logger.warning("Failed to add column %s via ALTER: %s", col_name, e)
                        continue
            except Exception as e:
                logger.exception("Error ensuring column %s: %s", col_name, e)


try:
    ensure_diarysleeptable_columns()
except Exception:
    logger.exception("ensure_diarysleeptable_columns failed on startup")


# ---------------------------
# Auth helpers
# ---------------------------
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise JWTError()
        user_id = int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    # simple role check; models.User.role expected to exist
    if not getattr(current_user, "role", None) or current_user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


# ---------------------------
# Small input parsers for date/time robustification
# ---------------------------
def parse_date_val(s):
    if s is None:
        return None
    if isinstance(s, date) and not isinstance(s, datetime):
        return s
    if isinstance(s, datetime):
        return s.date()
    s = str(s).strip()
    try:
        return date.fromisoformat(s)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    return None


def parse_time_val(s):
    if s is None:
        return None
    if isinstance(s, time):
        return s
    if isinstance(s, datetime):
        return s.time()
    s = str(s).strip()
    m = re.match(r"^(\d{1,2})[:\.](\d{1,2})$", s)
    if m:
        try:
            h = int(m.group(1)) % 24
            m2 = int(m.group(2)) % 60
            return time(hour=h, minute=m2)
        except Exception:
            return None
    m = re.match(r"^(\d{1,2})$", s)
    if m:
        try:
            h = int(m.group(1)) % 24
            return time(hour=h, minute=0)
        except Exception:
            return None
    try:
        return datetime.fromisoformat(s).time()
    except Exception:
        return None


# ---------------------------
# Safe serializers to avoid DB-malformed-value crashes
# ---------------------------
def safe_cast_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date) and not isinstance(value, datetime):
        return datetime.combine(value, time.min)
    s = str(value).strip()
    try:
        if s.endswith("Z"):
            s2 = s.replace("Z", "+00:00")
            return datetime.fromisoformat(s2)
        return datetime.fromisoformat(s)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def safe_cast_date(value: Any) -> Optional[date]:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return parse_date_val(value)
    except Exception:
        return None


def safe_cast_time(value: Any) -> Optional[time]:
    if value is None:
        return None
    if isinstance(value, time):
        return value
    if isinstance(value, datetime):
        return value.time()
    try:
        return parse_time_val(value)
    except Exception:
        return None


# ---------------------------
# Users
# ---------------------------
@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return current_user


@app.put("/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    for key, value in data.dict(exclude_unset=True).items():
        setattr(current_user, key, value)
    db.commit()
    db.refresh(current_user)
    return {"message": "Profile updated"}


@app.post("/users/{user_id}/upload-image")
def upload_image(
    user_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    filename = f"profile_{user_id}.jpg"
    filepath = os.path.join("static", filename)
    os.makedirs("static", exist_ok=True)
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    current_user.image_url = f"{PUBLIC_BASE_URL}/static/{filename}"
    db.commit()
    db.refresh(current_user)
    return {"image_url": current_user.image_url}


@app.post("/register")
async def register_user(
    first_name: str = Form(...),
    last_name: str = Form(...),
    gender: str = Form(None),
    birthdate: str = Form(None),
    email: str = Form(...),
    password: str = Form(...),
    image: UploadFile = File(None),
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    image_url = None
    if image:
        filename = f"profile_{email}.jpg"
        filepath = os.path.join("static", filename)
        os.makedirs("static", exist_ok=True)
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_url = f"{PUBLIC_BASE_URL}/static/{filename}"

    birthdate_value = None
    if birthdate:
        try:
            birthdate_value = date.fromisoformat(birthdate)
        except Exception:
            birthdate_value = None

    new_user = User(
        first_name=first_name,
        last_name=last_name,
        gender=gender,
        birthdate=birthdate_value,
        email=email,
        password=hashed_password,
        image_url=image_url,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully", "user_id": new_user.id}


@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token_data = {"sub": str(user.id), "email": user.email}
    access_token = create_access_token(token_data)
    return {
        "message": "Login successful",
        "token": access_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        },
    }


# ---------------------------
# GuideSleep
# ---------------------------
@app.post("/guidesleep")
def create_guidesleep(data: GuideSleepCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_entry = GuideSleep(**data.dict(), user_id=current_user.id)
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    return {"message": "GuideSleep created", "id": new_entry.id}


@app.get("/guidesleep")
def get_guidesleep(request: Request, db: Session = Depends(get_db)):
    """
    Return list of guidesleep posts. If Authorization header present and valid,
    include per-post score and user_vote for that user.
    """
    posts = db.query(GuideSleep).all()
    result = []
    # try to extract user id from Authorization header if present
    auth_header = request.headers.get("authorization")
    current_user_id = None
    if auth_header:
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload.get("sub")
            if sub is not None:
                current_user_id = int(sub)
        except Exception:
            current_user_id = None

    with engine.connect() as conn:
        for post in posts:
            user = db.query(User).filter(User.id == post.user_id).first()
            # compute score (sum of votes)
            try:
                score_row = conn.execute(
                    text("SELECT COALESCE(SUM(value),0) AS s FROM votes WHERE guidesleep_id = :gid"),
                    {"gid": post.id},
                ).mappings().first()
                score = int(score_row["s"]) if score_row and score_row["s"] is not None else 0
            except Exception:
                score = 0
            # compute user_vote if we have a current user
            user_vote = 0
            if current_user_id:
                try:
                    uv = conn.execute(
                        text("SELECT value FROM votes WHERE guidesleep_id = :gid AND user_id = :uid LIMIT 1"),
                        {"gid": post.id, "uid": current_user_id},
                    ).mappings().first()
                    user_vote = int(uv["value"]) if uv and uv["value"] is not None else 0
                except Exception:
                    user_vote = 0

            result.append(
                {
                    "id": post.id,
                    "note": post.note,
                    "start_date": post.start_date,
                    "end_date": post.end_date,
                    "sleep_time": post.sleep_time,
                    "wake_time": post.wake_time,
                    "category": post.category,
                    "user_id": post.user_id,
                    "user_name": f"{user.first_name} {user.last_name}" if user else "Unknown",
                    "image_url": user.image_url if user else None,
                    "score": score,
                    "user_vote": user_vote,
                }
            )
    return result


@app.put("/guidesleep/{post_id}")
def update_guidesleep(post_id: int, payload: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(GuideSleep).filter(GuideSleep.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="GuideSleep not found")
    if int(post.user_id) != int(current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")

    allowed_keys = ["category", "note", "start_date", "end_date", "sleep_time", "wake_time"]
    updated = False
    for k in allowed_keys:
        if k in payload:
            setattr(post, k, payload[k])
            updated = True
    if not updated:
        return {"message": "Nothing to update"}
    try:
        db.commit()
        db.refresh(post)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to update guidesleep id=%s: %s", post_id, e)
        raise HTTPException(status_code=500, detail="Failed to update guidesleep")
    return {"message": "GuideSleep updated", "id": post.id}


@app.delete("/guidesleep/{post_id}")
def delete_guidesleep(post_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(GuideSleep).filter(GuideSleep.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="GuideSleep not found")
    if int(post.user_id) != int(current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        db.delete(post)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Failed to delete guidesleep id=%s: %s", post_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete guidesleep")
    return {"message": "GuideSleep deleted", "id": post_id}


# ---------------------------
# Vote endpoints for GuideSleep
# ---------------------------
@app.post("/guidesleep/{post_id}/vote")
def vote_guidesleep(post_id: int, payload: dict, current_user: User = Depends(get_current_user)):
    """
    Upsert a vote for the current user on a guidesleep post.
    payload: { "value": int } where value in -4..-1 or 1..4 (0 to remove)
    """
    val = payload.get("value")
    try:
        val = int(val)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid vote value")
    if val == 0:
        # treat as delete
        try:
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM votes WHERE guidesleep_id = :gid AND user_id = :uid"), {"gid": post_id, "uid": current_user.id})
            return {"message": "Vote removed"}
        except Exception as e:
            logger.exception("Failed to remove vote: %s", e)
            raise HTTPException(status_code=500, detail="Failed to remove vote")
    if not (-4 <= val <= -1 or 1 <= val <= 4):
        raise HTTPException(status_code=400, detail="Vote value out of allowed range")

    try:
        with engine.begin() as conn:
            # try update first
            res = conn.execute(
                text("SELECT id FROM votes WHERE guidesleep_id = :gid AND user_id = :uid LIMIT 1"),
                {"gid": post_id, "uid": current_user.id},
            ).mappings().first()
            if res:
                conn.execute(
                    text("UPDATE votes SET value = :val, created_at = CURRENT_TIMESTAMP WHERE id = :id"),
                    {"val": val, "id": res["id"]},
                )
            else:
                conn.execute(
                    text("INSERT INTO votes (user_id, guidesleep_id, value) VALUES (:uid, :gid, :val)"),
                    {"uid": current_user.id, "gid": post_id, "val": val},
                )
    except Exception as e:
        logger.exception("Failed to upsert vote: %s", e)
        raise HTTPException(status_code=500, detail="Failed to record vote")

    return {"message": "Vote recorded", "value": val}


@app.delete("/guidesleep/{post_id}/vote")
def delete_vote_guidesleep(post_id: int, current_user: User = Depends(get_current_user)):
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM votes WHERE guidesleep_id = :gid AND user_id = :uid"), {"gid": post_id, "uid": current_user.id})
    except Exception as e:
        logger.exception("Failed to delete vote: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete vote")
    return {"message": "Vote deleted"}


# Comments endpoints (main.py)
from datetime import datetime
from typing import Dict, Any
from fastapi import HTTPException, Depends, Request
from sqlalchemy.orm import Session

# ---------------------------
# Comments endpoints
# ---------------------------
# Provide legacy endpoints used by older mobile client and newer guidesleep-scoped endpoints.

@app.get("/comments/{guidesleep_id}")
def get_comments_by_guidesleep_legacy(guidesleep_id: int, db: Session = Depends(get_db)):
    try:
        rows = (
            db.query(Comment)
            .filter(Comment.guidesleep_id == guidesleep_id)
            .order_by(Comment.created_at.asc())
            .all()
        )
        result = []
        for c in rows:
            user = db.query(User).filter(User.id == c.user_id).first()
            # ensure created_at is a datetime (avoid returning None)
            created_at = c.created_at or None
            result.append(
                {
                    "id": c.id,
                    "content": c.content,
                    "created_at": created_at,
                    "user_id": c.user_id,
                    "guidesleep_id": c.guidesleep_id,
                    "user_name": f"{user.first_name} {user.last_name}" if user else None,
                    "image_url": user.image_url if user else None,
                }
            )
        return result
    except Exception as e:
        logger.exception("Failed to fetch comments for post %s: %s", guidesleep_id, e)
        raise HTTPException(status_code=500, detail="Failed to fetch comments")


@app.post("/comments", response_model=CommentOut)
def create_comment_legacy(
    data: CommentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(GuideSleep).filter(GuideSleep.id == data.guidesleep_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="GuideSleep post not found")

    new_comment = Comment(
        content=data.content,
        user_id=current_user.id,
        guidesleep_id=data.guidesleep_id,
    )

    # Ensure created_at is set so response_model validation won't fail
    if getattr(new_comment, "created_at", None) is None:
        new_comment.created_at = datetime.utcnow()

    db.add(new_comment)
    try:
        db.commit()
        db.refresh(new_comment)
        # If DB/ORM still left created_at as None, set and persist
        if new_comment.created_at is None:
            new_comment.created_at = datetime.utcnow()
            db.add(new_comment)
            db.commit()
            db.refresh(new_comment)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create comment: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create comment")

    user = db.query(User).filter(User.id == new_comment.user_id).first()
    return {
        "id": new_comment.id,
        "content": new_comment.content,
        "created_at": new_comment.created_at,
        "user_id": new_comment.user_id,
        "guidesleep_id": new_comment.guidesleep_id,
        "user_name": f"{user.first_name} {user.last_name}" if user else None,
        "image_url": user.image_url if user else None,
    }


@app.get("/guidesleep/{post_id}/comments")
def get_comments_for_post(post_id: int, db: Session = Depends(get_db)):
    try:
        rows = (
            db.query(Comment)
            .filter(Comment.guidesleep_id == post_id)
            .order_by(Comment.created_at.asc())
            .all()
        )
        result = []
        for c in rows:
            user = db.query(User).filter(User.id == c.user_id).first()
            created_at = c.created_at or None
            result.append(
                {
                    "id": c.id,
                    "content": c.content,
                    "created_at": created_at,
                    "user_id": c.user_id,
                    "guidesleep_id": c.guidesleep_id,
                    "user_name": f"{user.first_name} {user.last_name}" if user else None,
                    "image_url": user.image_url if user else None,
                }
            )
        return result
    except Exception as e:
        logger.exception("Failed to fetch comments for post %s: %s", post_id, e)
        raise HTTPException(status_code=500, detail="Failed to fetch comments")


@app.post("/guidesleep/{post_id}/comments", response_model=CommentOut)
def create_comment_for_post(
    post_id: int,
    data: CommentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(GuideSleep).filter(GuideSleep.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="GuideSleep post not found")

    new_comment = Comment(content=data.content, user_id=current_user.id, guidesleep_id=post_id)

    # Ensure created_at is set to avoid response validation errors
    if getattr(new_comment, "created_at", None) is None:
        new_comment.created_at = datetime.utcnow()

    db.add(new_comment)
    try:
        db.commit()
        db.refresh(new_comment)
        if new_comment.created_at is None:
            new_comment.created_at = datetime.utcnow()
            db.add(new_comment)
            db.commit()
            db.refresh(new_comment)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create comment: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create comment")

    user = db.query(User).filter(User.id == new_comment.user_id).first()
    return {
        "id": new_comment.id,
        "content": new_comment.content,
        "created_at": new_comment.created_at,
        "user_id": new_comment.user_id,
        "guidesleep_id": new_comment.guidesleep_id,
        "user_name": f"{user.first_name} {user.last_name}" if user else None,
        "image_url": user.image_url if user else None,
    }


@app.put("/comments/{comment_id}", response_model=CommentOut)
def update_comment(
    comment_id: int,
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if int(comment.user_id) != int(current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")

    new_content = payload.get("content") if isinstance(payload, dict) else None
    if not new_content or not str(new_content).strip():
        raise HTTPException(status_code=400, detail="Content required")

    comment.content = str(new_content).strip()
    try:
        db.commit()
        db.refresh(comment)
        # ensure created_at exists
        if comment.created_at is None:
            comment.created_at = datetime.utcnow()
            db.add(comment)
            db.commit()
            db.refresh(comment)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to update comment id=%s: %s", comment_id, e)
        raise HTTPException(status_code=500, detail="Failed to update comment")

    user = db.query(User).filter(User.id == comment.user_id).first()
    return {
        "id": comment.id,
        "content": comment.content,
        "created_at": comment.created_at,
        "user_id": comment.user_id,
        "guidesleep_id": comment.guidesleep_id,
        "user_name": f"{user.first_name} {user.last_name}" if user else None,
        "image_url": user.image_url if user else None,
    }


@app.delete("/comments/{comment_id}")
def delete_comment(
    comment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if int(comment.user_id) != int(current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        db.delete(comment)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Failed to delete comment id=%s: %s", comment_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete comment")
    return {"message": "Comment deleted", "id": comment_id}



# ---------------------------
# Admin Quests endpoints (create/list/update/delete) - admin only
# ---------------------------
# --- Replace existing admin block with this block ---

# -------------------------
# Quests endpoints (admin + public + progress)
# -------------------------
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import Request, Depends, HTTPException
import json
import logging

logger = logging.getLogger("uvicorn.error")

# Lightweight optional_current_user helper to avoid NameError.
# If your project already defines a more complete version, you can remove this helper and import the existing one.
def optional_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """
    Return User if Authorization header contains a valid token and user exists.
    Return None if no header or token invalid. This is intentionally permissive (no raises).
    """
    try:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth:
            return None
        parts = auth.split()
        if len(parts) != 2:
            return None
        token = parts[1]
        # Prefer project-specific helper if available
        if "get_user_from_token" in globals():
            try:
                return get_user_from_token(token, db)
            except Exception:
                return None
        # Fallback: decode JWT payload and lookup user id
        if "decode_jwt_payload" in globals():
            payload = decode_jwt_payload(token)
        else:
            payload = None
        if not payload:
            return None
        user_id = payload.get("sub") or payload.get("user_id") or payload.get("id")
        if not user_id:
            return None
        return db.query(User).filter(User.id == int(user_id)).first()
    except Exception:
        return None

# -------------------------
# Admin endpoints (create/list/update/delete)
# -------------------------
@app.post("/admin/quests", response_model=QuestOut)
def admin_create_quest(data: QuestCreate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    desc_val = data.description or ""
    total_percent = 0
    total_score = 0

    # try parse description and compute totals
    try:
        parsed = None
        if isinstance(desc_val, str) and desc_val.strip():
            parsed = json.loads(desc_val)
        elif isinstance(desc_val, dict):
            parsed = desc_val

        if parsed and isinstance(parsed, dict):
            periods = parsed.get("periods", {}) or {}
            for _, arr in periods.items():
                if not isinstance(arr, list):
                    continue
                for it in arr:
                    if isinstance(it, str):
                        continue
                    try:
                        percent = int(it.get("percent", 0) or 0)
                    except Exception:
                        try:
                            percent = int(float(it.get("percent", 0) or 0))
                        except Exception:
                            percent = 0
                    try:
                        score = int(it.get("score", 0) or 0)
                    except Exception:
                        try:
                            score = int(float(it.get("score", 0) or 0))
                        except Exception:
                            score = 0
                    total_percent += percent
                    total_score += score
    except Exception:
        total_percent = 0
        total_score = 0

    default_status = getattr(data, "status", None) or "published"

    q = Quest(
        title=data.title,
        description=(desc_val if isinstance(desc_val, str) else json.dumps(desc_val)),
        created_by=admin_user.id,
        status=(default_status or "published"),
        start_date=safe_cast_date(getattr(data, "start_date", None)),
        end_date=safe_cast_date(getattr(data, "end_date", None)),
    )

    # persist totals if model has fields (try common names)
    for attr_name, val in (("total_percent", total_percent), ("total_score", total_score),
                           ("percent_total", total_percent), ("score_total", total_score)):
        if hasattr(q, attr_name):
            try:
                setattr(q, attr_name, val)
            except Exception:
                pass

    db.add(q)
    try:
        db.commit()
        db.refresh(q)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create quest: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create quest")

    return {
        "id": q.id,
        "title": q.title,
        "description": q.description,
        "created_by": q.created_by,
        "status": q.status,
        "start_date": q.start_date,
        "end_date": q.end_date,
        "created_at": q.created_at,
        "updated_at": q.updated_at,
    }


@app.get("/admin/quests", response_model=List[QuestOut])
def admin_list_quests(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        rows = db.query(Quest).order_by(Quest.created_at.desc()).all()
    except Exception as e:
        logger.exception("Failed to fetch quests: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch quests")
    result = []
    for q in rows:
        result.append(
            {
                "id": q.id,
                "title": q.title,
                "description": q.description,
                "created_by": q.created_by,
                "status": q.status,
                "start_date": q.start_date,
                "end_date": q.end_date,
                "created_at": q.created_at,
                "updated_at": q.updated_at,
            }
        )
    return result


@app.put("/admin/quests/{quest_id}", response_model=QuestOut)
def admin_update_quest(quest_id: int, payload: dict, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")

    updated = False

    for field in ("title", "status"):
        if field in payload:
            setattr(q, field, payload[field])
            updated = True

    if "start_date" in payload:
        q.start_date = safe_cast_date(payload.get("start_date"))
        updated = True
    if "end_date" in payload:
        q.end_date = safe_cast_date(payload.get("end_date"))
        updated = True

    if "description" in payload:
        desc_val = payload.get("description")
        try:
            desc_str = desc_val if isinstance(desc_val, str) else json.dumps(desc_val)
        except Exception:
            desc_str = str(desc_val) if desc_val is not None else ""
        q.description = desc_str or ""
        updated = True

        total_percent = 0
        total_score = 0
        try:
            parsed = None
            if isinstance(desc_val, str) and desc_val.strip():
                parsed = json.loads(desc_val)
            elif isinstance(desc_val, dict):
                parsed = desc_val
            elif desc_str:
                parsed = json.loads(desc_str)
            if parsed and isinstance(parsed, dict):
                periods = parsed.get("periods", {}) or {}
                for _, arr in periods.items():
                    if not isinstance(arr, list):
                        continue
                    for it in arr:
                        if isinstance(it, str):
                            continue
                        try:
                            percent = int(it.get("percent", 0) or 0)
                        except Exception:
                            try:
                                percent = int(float(it.get("percent", 0) or 0))
                            except Exception:
                                percent = 0
                        try:
                            score = int(it.get("score", 0) or 0)
                        except Exception:
                            try:
                                score = int(float(it.get("score", 0) or 0))
                            except Exception:
                                score = 0
                        total_percent += percent
                        total_score += score
        except Exception:
            total_percent = 0
            total_score = 0

        for attr_name, val in (("total_percent", total_percent), ("total_score", total_score),
                               ("percent_total", total_percent), ("score_total", total_score)):
            if hasattr(q, attr_name):
                try:
                    setattr(q, attr_name, val)
                except Exception:
                    pass

    if not updated:
        return {
            "id": q.id,
            "title": q.title,
            "description": q.description,
            "created_by": q.created_by,
            "status": q.status,
            "start_date": q.start_date,
            "end_date": q.end_date,
            "created_at": q.created_at,
            "updated_at": q.updated_at,
        }

    try:
        db.commit()
        db.refresh(q)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to update quest id=%s: %s", quest_id, e)
        raise HTTPException(status_code=500, detail="Failed to update quest")

    return {
        "id": q.id,
        "title": q.title,
        "description": q.description,
        "created_by": q.created_by,
        "status": q.status,
        "start_date": q.start_date,
        "end_date": q.end_date,
        "created_at": q.created_at,
        "updated_at": q.updated_at,
    }


@app.delete("/admin/quests/{quest_id}")
def admin_delete_quest(quest_id: int, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")
    try:
        db.delete(q)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Failed to delete quest id=%s: %s", quest_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete quest")
    return {"message": "Quest deleted", "id": quest_id}


# -------------------------
# Public endpoints for members
# -------------------------
class QuestProgressIn(BaseModel):
    user_id: Optional[int] = None
    progress: Dict[str, Any]
    totals: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None

    class Config:
        orm_mode = True


@app.get("/quests", response_model=List[QuestOut])
def list_public_quests(db: Session = Depends(get_db)):
    try:
        rows = db.query(Quest).filter(Quest.status == "published").order_by(Quest.created_at.desc()).all()
    except Exception as e:
        logger.exception("Failed to fetch public quests: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch quests")
    result = []
    for q in rows:
        result.append(
            {
                "id": q.id,
                "title": q.title,
                "description": q.description,
                "created_by": q.created_by,
                "status": q.status,
                "start_date": q.start_date,
                "end_date": q.end_date,
                "created_at": q.created_at,
                "updated_at": q.updated_at,
            }
        )
    return result


@app.get("/quests/{quest_id}", response_model=QuestOut)
def get_public_quest(quest_id: int, db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id, Quest.status == "published").first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")
    return {
        "id": q.id,
        "title": q.title,
        "description": q.description,
        "created_by": q.created_by,
        "status": q.status,
        "start_date": q.start_date,
        "end_date": q.end_date,
        "created_at": q.created_at,
        "updated_at": q.updated_at,
    }


@app.post("/quests/{quest_id}/progress", response_model=Dict[str, Any])
def submit_quest_progress(
    quest_id: int,
    payload: QuestProgressIn,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Accept progress payload for a quest. Members (authenticated) or anonymous clients can submit.
    Persist to quest_progress table if available; otherwise return acknowledgement.
    """
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")

    # Basic validation
    if payload.progress is None or not isinstance(payload.progress, dict):
        raise HTTPException(status_code=400, detail="Invalid payload: 'progress' must be an object/dict")

    try:
        # resolve optional user
        current_user = optional_current_user(request, db)
        associated_user_id = None
        if current_user:
            associated_user_id = getattr(current_user, "id", None)
        elif payload.user_id:
            associated_user_id = payload.user_id

        # If QuestProgress model exists, persist the record
        if "QuestProgress" in globals():
            try:
                data_json = json.dumps(payload.progress)
                totals_json = json.dumps(payload.totals) if payload.totals is not None else None

                qp = QuestProgress(
                    quest_id=quest_id,
                    user_id=associated_user_id,
                    data=data_json,
                    totals=totals_json,
                    updated_at=(safe_cast_datetime(payload.updated_at) if payload.updated_at else None),
                )
                db.add(qp)
                db.commit()
                db.refresh(qp)

                # Optional: update Quest aggregates if payload.totals provided and model supports it
                try:
                    if payload.totals and isinstance(payload.totals, dict):
                        tp = payload.totals.get("totalPercent") or payload.totals.get("total_percent")
                        ts = payload.totals.get("totalScore") or payload.totals.get("total_score")
                        updated = False
                        if tp is not None and hasattr(q, "total_percent"):
                            try:
                                q.total_percent = int(tp)
                                updated = True
                            except Exception:
                                pass
                        if ts is not None and hasattr(q, "total_score"):
                            try:
                                q.total_score = int(ts)
                                updated = True
                            except Exception:
                                pass
                        if updated:
                            try:
                                db.add(q)
                                db.commit()
                                db.refresh(q)
                            except Exception:
                                db.rollback()
                except Exception:
                    logger.exception("Failed to update quest aggregates after saving progress")

                return {
                    "status": "ok",
                    "quest_id": quest_id,
                    "progress_id": qp.id,
                    "user_id": associated_user_id,
                    "created_at": qp.created_at,
                    "updated_at": qp.updated_at,
                }
            except Exception as persist_err:
                db.rollback()
                logger.exception("QuestProgress persist error: %s", persist_err)
                raise HTTPException(status_code=500, detail="Failed to persist progress (see server log)")

        # fallback acknowledgement (no persistence)
        logger.info("Received quest progress (ack): quest_id=%s user_id=%s totals=%s", quest_id, associated_user_id, payload.totals)
        return {"status": "ok", "quest_id": quest_id, "received": True, "user_id": associated_user_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in submit_quest_progress: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")
# --- เพิ่มนี้ไว้ท้ายไฟล์ endpoints (แก้ไขแล้ว) ---
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import Request, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import date, datetime
import json
import logging

logger = logging.getLogger("uvicorn.error")

class ProgressItemIn(BaseModel):
    id: Optional[str] = None
    label: Optional[str] = None
    quest_id: Optional[int] = None
    period: Optional[str] = None
    status: Optional[str] = None
    score: Optional[int] = 0

class ProgressIn(BaseModel):
    quest_id: Optional[int] = None
    user_id: Optional[int] = None
    date: Optional[str] = None  # YYYY-MM-DD
    accept_start_time: Optional[str] = None  # ISO datetime
    items: Optional[Dict[str, List[ProgressItemIn]]] = None
    totals: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None

    class Config:
        orm_mode = True

def safe_cast_datetime(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

def _resolve_optional_user(request: Request, db: Session) -> Optional[object]:
    if "optional_current_user" in globals():
        try:
            return optional_current_user(request, db)
        except Exception:
            return None
    return None

@app.post("/quests/progress", response_model=Dict[str, Any])
def submit_progress_generic(payload: ProgressIn, request: Request, db: Session = Depends(get_db)):
    """
    Generic endpoint to accept progress payloads without quest_id in path.
    Persists to user_daily_quests/user_daily_quest_items when available,
    otherwise falls back to quest_progress.
    """
    try:
        current_user = _resolve_optional_user(request, db)
        user_id = getattr(current_user, "id", None) if current_user else payload.user_id

        # parse date if provided
        rec_date = None
        if payload.date:
            try:
                rec_date = date.fromisoformat(payload.date)
            except Exception:
                rec_date = None

        # prepare serializable items dict (convert Pydantic models to dicts)
        items_serializable: Optional[Dict[str, List[Dict[str, Any]]]] = None
        if payload.items:
            items_serializable = {}
            for k, arr in payload.items.items():
                items_serializable[k] = [it.dict() for it in arr]

        # Prefer normalized daily tables if present
        if "UserDailyQuest" in globals():
            if not user_id:
                raise HTTPException(status_code=400, detail="user_id required for daily quest persistence")

            d = rec_date or date.today()
            existing = db.query(UserDailyQuest).filter(UserDailyQuest.user_id == user_id, UserDailyQuest.date == d).first()
            if existing:
                existing.accept_start_time = (safe_cast_datetime(payload.accept_start_time) if payload.accept_start_time else existing.accept_start_time)
                existing.status = "confirmed" if payload.accept_start_time else (existing.status or "pending")
                existing.totals = json.dumps(payload.totals) if payload.totals is not None else existing.totals

                if "UserDailyQuestItem" in globals():
                    db.query(UserDailyQuestItem).filter(UserDailyQuestItem.daily_id == existing.id).delete()
                    db.flush()
                    if payload.items:
                        for period_key, arr in payload.items.items():
                            for it in arr:
                                item = UserDailyQuestItem(
                                    daily_id=existing.id,
                                    period=period_key,
                                    quest_item_id=str(it.id) if it.id is not None else None,
                                    label=it.label or "",
                                    status=it.status or "pending",
                                    score=int(it.score or 0),
                                )
                                db.add(item)
                db.add(existing)
                db.commit()
                db.refresh(existing)
                return {"status": "ok", "stored_in": "user_daily_quests", "id": existing.id}
            else:
                new_rec = UserDailyQuest(
                    user_id=user_id,
                    date=d,
                    accept_start_time=(safe_cast_datetime(payload.accept_start_time) if payload.accept_start_time else None),
                    status="confirmed" if payload.accept_start_time else "pending",
                    totals=json.dumps(payload.totals) if payload.totals is not None else None,
                )
                db.add(new_rec)
                db.flush()
                if "UserDailyQuestItem" in globals() and payload.items:
                    for period_key, arr in payload.items.items():
                        for it in arr:
                            item = UserDailyQuestItem(
                                daily_id=new_rec.id,
                                period=period_key,
                                quest_item_id=str(it.id) if it.id is not None else None,
                                label=it.label or "",
                                status=it.status or "pending",
                                score=int(it.score or 0),
                            )
                            db.add(item)
                db.commit()
                db.refresh(new_rec)
                return {"status": "ok", "stored_in": "user_daily_quests", "id": new_rec.id}

        # Fallback to QuestProgress if available
        if "QuestProgress" in globals():
            data_obj = {
                "quest_id": payload.quest_id,
                "items": items_serializable,
                "date": payload.date,
                "accept_start_time": payload.accept_start_time,
            }
            # IMPORTANT: set quest_id to None if not provided; ensure QuestProgress.quest_id is nullable in models
            qp = QuestProgress(
                quest_id=payload.quest_id if payload.quest_id is not None else None,
                user_id=user_id,
                data=json.dumps(data_obj),
                totals=json.dumps(payload.totals) if payload.totals is not None else None,
                updated_at=(safe_cast_datetime(payload.updated_at) if payload.updated_at else None),
            )
            db.add(qp)
            db.commit()
            db.refresh(qp)
            return {"status": "ok", "stored_in": "quest_progress", "id": qp.id}

        logger.info("Received progress but no persistence model available: payload=%s", payload.dict())
        return {"status": "ok", "stored_in": None}
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("Failed to persist generic progress: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist progress")

# ---------------------------
# DiarySleep endpoints (create/list/start/wake/update/delete)
# ---------------------------
@app.post("/diarysleep", response_model=DiarySleepOut)
def create_diarysleep(data: DiarySleepCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sd = parse_date_val(getattr(data, "start_date", None))
    ed = parse_date_val(getattr(data, "end_date", None))
    st = parse_time_val(getattr(data, "sleep_time", None))
    wk = parse_time_val(getattr(data, "wake_time", None))

    if sd is None or ed is None:
        raise HTTPException(status_code=400, detail="start_date/end_date invalid or missing")
    if st is None or wk is None:
        raise HTTPException(status_code=400, detail="sleep_time/wake_time invalid or missing")

    entry = DiarySleep(
        note=(getattr(data, "note", "") or ""),
        start_date=sd,
        end_date=ed,
        sleep_time=st,
        wake_time=wk,
        user_id=current_user.id,
    )
    db.add(entry)
    try:
        db.flush()
        entry_id = entry.id
        returned = {
            "id": entry_id,
            "note": entry.note,
            "start_date": sd,
            "end_date": ed,
            "sleep_time": st,
            "wake_time": wk,
            "actual_sleep_start": None,
            "actual_wake_time": None,
            "actual_wake_hour": None,
            "total_sleep_minutes": None,
            "user_id": current_user.id,
        }
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Failed to commit new DiarySleep: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to create diary entry: {e}")

    return returned


@app.get("/diarysleep")
def list_diarysleep(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        raw_sql = text(
            """
            SELECT
              id,
              note,
              CAST(start_date AS CHAR) AS start_date,
              CAST(end_date AS CHAR) AS end_date,
              CAST(sleep_time AS CHAR) AS sleep_time,
              CAST(wake_time AS CHAR) AS wake_time,
              CAST(actual_sleep_start AS CHAR) AS actual_sleep_start,
              CAST(actual_wake_time AS CHAR) AS actual_wake_time,
              actual_wake_hour,
              total_sleep_minutes,
              user_id
            FROM diarysleep
            WHERE user_id = :uid
            ORDER BY start_date DESC
            """
        )
        with engine.connect() as conn:
            rows = conn.execute(raw_sql, {"uid": current_user.id}).mappings().all()
    except Exception as e:
        logger.exception("DB query error in list_diarysleep: %s", e)
        raise HTTPException(status_code=500, detail="Database error when fetching diary entries")

    safe_list = []
    for r in rows:
        try:
            rowdict = dict(r)
            s = {
                "id": int(rowdict.get("id")) if rowdict.get("id") is not None else None,
                "note": rowdict.get("note") or "",
                "start_date": safe_cast_date(rowdict.get("start_date")).isoformat() if safe_cast_date(rowdict.get("start_date")) else None,
                "end_date": safe_cast_date(rowdict.get("end_date")).isoformat() if safe_cast_date(rowdict.get("end_date")) else None,
                "sleep_time": safe_cast_time(rowdict.get("sleep_time")).strftime("%H:%M") if safe_cast_time(rowdict.get("sleep_time")) else None,
                "wake_time": safe_cast_time(rowdict.get("wake_time")).strftime("%H:%M") if safe_cast_time(rowdict.get("wake_time")) else None,
                "actual_sleep_start": safe_cast_datetime(rowdict.get("actual_sleep_start")).isoformat() if safe_cast_datetime(rowdict.get("actual_sleep_start")) else None,
                "actual_wake_time": safe_cast_datetime(rowdict.get("actual_wake_time")).isoformat() if safe_cast_datetime(rowdict.get("actual_wake_time")) else None,
                "actual_wake_hour": int(rowdict.get("actual_wake_hour")) if rowdict.get("actual_wake_hour") is not None else None,
                "total_sleep_minutes": int(rowdict.get("total_sleep_minutes")) if rowdict.get("total_sleep_minutes") is not None else None,
                "user_id": int(rowdict.get("user_id")) if rowdict.get("user_id") is not None else None,
            }
            safe_list.append(s)
        except Exception:
            # skip malformed row but continue
            logger.exception("Failed to parse diary row: %s", r)
            continue

    return safe_list


@app.put("/diarysleep/{diary_id}")
def update_diarysleep(diary_id: int, payload: dict, current_user: User = Depends(get_current_user)):
    try:
        sql = text(
            """
            SELECT
              id,
              CAST(start_date AS CHAR) AS start_date,
              CAST(end_date AS CHAR) AS end_date,
              CAST(sleep_time AS CHAR) AS sleep_time,
              CAST(wake_time AS CHAR) AS wake_time,
              CAST(actual_sleep_start AS CHAR) AS actual_sleep_start,
              CAST(actual_wake_time AS CHAR) AS actual_wake_time,
              actual_wake_hour,
              total_sleep_minutes,
              user_id
            FROM diarysleep
            WHERE id = :id
            LIMIT 1
            """
        )
        with engine.connect() as conn:
            row = conn.execute(sql, {"id": diary_id}).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="DiarySleep not found")
            if int(row["user_id"]) != int(current_user.id):
                raise HTTPException(status_code=403, detail="Forbidden")

            allowed = {}
            if "note" in payload:
                allowed["note"] = payload["note"]
            if "actual_sleep_start" in payload:
                dt = safe_cast_datetime(payload["actual_sleep_start"])
                allowed["actual_sleep_start"] = dt.isoformat(sep=" ") if dt else None
            if "actual_wake_time" in payload:
                dt = safe_cast_datetime(payload["actual_wake_time"])
                allowed["actual_wake_time"] = dt.isoformat(sep=" ") if dt else None
                allowed["actual_wake_hour"] = dt.hour if dt else None
            if "total_sleep_minutes" in payload:
                try:
                    allowed["total_sleep_minutes"] = int(payload["total_sleep_minutes"]) if payload["total_sleep_minutes"] is not None else None
                except Exception:
                    allowed["total_sleep_minutes"] = None

            if not allowed:
                return {"message": "Nothing to update"}

            set_parts = []
            params = {"id": diary_id}
            idx = 0
            for k, v in allowed.items():
                idx += 1
                param_name = f"p{idx}"
                set_parts.append(f"{k} = :{param_name}")
                params[param_name] = v
            update_sql = text(f"UPDATE diarysleep SET {', '.join(set_parts)} WHERE id = :id")
            with engine.begin() as conn2:
                conn2.execute(update_sql, params)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to update diary entry id=%s: %s", diary_id, e)
        raise HTTPException(status_code=500, detail="Failed to update diary entry")

    return {"message": "DiarySleep updated", "id": diary_id}


@app.delete("/diarysleep/{diary_id}")
def delete_diarysleep(diary_id: int, current_user: User = Depends(get_current_user)):
    try:
        sel = text("SELECT id, user_id FROM diarysleep WHERE id = :id LIMIT 1")
        with engine.connect() as conn:
            row = conn.execute(sel, {"id": diary_id}).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="DiarySleep not found")
            if int(row["user_id"]) != int(current_user.id):
                raise HTTPException(status_code=403, detail="Forbidden")
            with engine.begin() as conn2:
                conn2.execute(text("DELETE FROM diarysleep WHERE id = :id"), {"id": diary_id})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to delete diary entry id=%s: %s", diary_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete diary entry")
    return {"message": "DiarySleep deleted", "id": diary_id}


@app.post("/diarysleep/{diary_id}/start", response_model=DiarySleepOut)
def record_diary_start(diary_id: int, data: DiarySleepStart, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    obj = db.query(DiarySleep).filter(DiarySleep.id == diary_id, DiarySleep.user_id == current_user.id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="DiarySleep not found")
    if not data or not data.actual_sleep_start:
        raise HTTPException(status_code=400, detail="actual_sleep_start required")
    obj.actual_sleep_start = data.actual_sleep_start
    try:
        db.commit()
        db.refresh(obj)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to record sleep start: %s", e)
        raise HTTPException(status_code=500, detail="Failed to record sleep start")
    return obj


@app.post("/diarysleep/{diary_id}/wake", response_model=DiarySleepOut)
def record_diary_wake(diary_id: int, data: DiarySleepWake, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    obj = db.query(DiarySleep).filter(DiarySleep.id == diary_id, DiarySleep.user_id == current_user.id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="DiarySleep not found")
    if not data or not data.actual_wake_time:
        raise HTTPException(status_code=400, detail="actual_wake_time required")

    obj.actual_wake_time = data.actual_wake_time
    try:
        try:
            obj.actual_wake_hour = data.actual_wake_time.hour
        except Exception:
            obj.actual_wake_hour = None

        if obj.actual_sleep_start:
            diff = data.actual_wake_time - obj.actual_sleep_start
            obj.total_sleep_minutes = max(0, int(diff.total_seconds() // 60))
        elif data.duration_minutes is not None:
            obj.total_sleep_minutes = int(data.duration_minutes)
        else:
            obj.total_sleep_minutes = None

        db.commit()
        db.refresh(obj)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to record wake: %s", e)
        raise HTTPException(status_code=500, detail="Failed to record wake")
    return obj


# ---------------------------
# guidesleep/wake compatibility endpoint (keeps existing behavior)
# ---------------------------
@app.post("/guidesleep/wake")
def guidesleep_wake(payload: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    at_iso = payload.get("at")
    sleep_start_iso = payload.get("sleep_start")
    duration = payload.get("duration_minutes")
    try:
        at_dt = datetime.fromisoformat(at_iso.replace("Z", "+00:00")) if at_iso else datetime.utcnow()
    except Exception:
        at_dt = datetime.utcnow()
    try:
        sleep_start_dt = datetime.fromisoformat(sleep_start_iso.replace("Z", "+00:00")) if sleep_start_iso else None
    except Exception:
        sleep_start_dt = None

    lookup_date = (sleep_start_dt.date() if sleep_start_dt else at_dt.date())

    try:
        diary = db.query(DiarySleep).filter(
            DiarySleep.user_id == current_user.id,
            DiarySleep.start_date == lookup_date
        ).order_by(DiarySleep.id.desc()).first()
    except Exception as e:
        logger.exception("DB query error when looking up diary: %s", e)
        raise HTTPException(status_code=500, detail="Database error during lookup")

    if not diary:
        gs = db.query(GuideSleep).filter(
            GuideSleep.user_id == current_user.id,
            GuideSleep.category == "diary",
            GuideSleep.start_date == lookup_date
        ).order_by(GuideSleep.id.desc()).first()
        if gs:
            try:
                ds = DiarySleep(
                    note=gs.note,
                    start_date=gs.start_date if isinstance(gs.start_date, date) else gs.start_date.date(),
                    end_date=gs.end_date if isinstance(gs.end_date, date) else gs.end_date.date(),
                    sleep_time=gs.sleep_time,
                    wake_time=gs.wake_time,
                    user_id=current_user.id,
                )
                db.add(ds)
                db.commit()
                db.refresh(ds)
                diary = ds
            except Exception as e:
                db.rollback()
                logger.exception("Failed to create DiarySleep from GuideSleep: %s", e)
                diary = None

    if not diary:
        try:
            ds = DiarySleep(
                note=f"Auto-created from wake event at {at_dt.isoformat()}",
                start_date=lookup_date,
                end_date=lookup_date,
                sleep_time=time(hour=0, minute=0),
                wake_time=time(hour=0, minute=0),
                user_id=current_user.id,
            )
            db.add(ds)
            db.commit()
            db.refresh(ds)
            diary = ds
        except Exception as e:
            db.rollback()
            logger.exception("Failed to auto-create diary from wake event: %s", e)
            diary = None

    if not diary:
        raise HTTPException(status_code=500, detail="Failed to find or create diary entry")

    # record wake info
    try:
        if duration is not None:
            diary.total_sleep_minutes = int(duration)
        diary.actual_wake_time = at_dt
        try:
            diary.actual_wake_hour = at_dt.hour
        except Exception:
            diary.actual_wake_hour = None
        db.commit()
        db.refresh(diary)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to record guidesleep wake: %s", e)
        raise HTTPException(status_code=500, detail="Failed to record wake")

    return diary
# -------------------------
# Report endpoints (append to the end of backend/main.py)
# -------------------------
from typing import List, Dict, Any, Optional
from fastapi import Body, Request
from sqlalchemy import func, literal_column
from models import Report  # ensure Report model is available
from schemas import ReportCreate, ReportOut, ReportUpdate, ReportSummary
from database import get_db
from sqlalchemy.orm import Session

# Lightweight optional_current_user helper (non-raising)
def optional_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """
    Return User if Authorization header contains a valid token and user exists.
    Return None if no header or token invalid. This is intentionally permissive.
    """
    try:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth:
            return None
        parts = auth.split()
        if len(parts) != 2:
            return None
        token = parts[1]
        # Try to decode token using existing get_current_user logic without raising
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = int(payload.get("sub"))
        except Exception:
            return None
        user = db.query(User).filter(User.id == user_id).first()
        return user
    except Exception:
        return None


@app.post("/reports", response_model=ReportOut)
def create_report(payload: ReportCreate, request: Request, db: Session = Depends(get_db)):
    """
    Create a report for a target (guidesleep, comment, quest).
    If Authorization header present and valid, associate the report with that user.
    """
    ttype = (payload.target_type or "").strip().lower()
    if ttype not in ("guidesleep", "comment", "quest"):
        raise HTTPException(status_code=400, detail="Unsupported target_type")

    # validate target exists
    if ttype == "guidesleep":
        tgt = db.query(GuideSleep).filter(GuideSleep.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target guidesleep not found")
    elif ttype == "comment":
        tgt = db.query(Comment).filter(Comment.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target comment not found")
    elif ttype == "quest":
        tgt = db.query(Quest).filter(Quest.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target quest not found")

    reporter = optional_current_user(request, db)
    reporter_id = getattr(reporter, "id", None) if reporter else None

    rpt = Report(
        user_id=reporter_id,
        target_type=ttype,
        target_id=payload.target_id,
        reason=payload.reason,
        status="pending",
    )
    db.add(rpt)
    try:
        db.commit()
        db.refresh(rpt)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create report: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create report")

    return {
        "id": rpt.id,
        "user_id": rpt.user_id,
        "target_type": rpt.target_type,
        "target_id": rpt.target_id,
        "reason": rpt.reason,
        "status": rpt.status,
        "created_at": rpt.created_at,
        "updated_at": rpt.updated_at,
    }


@app.get("/admin/reports", response_model=List[ReportOut])
def admin_list_reports(limit: int = 100, offset: int = 0, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    Return raw report rows for admin review (most recent first).
    """
    try:
        rows = db.query(Report).order_by(Report.created_at.desc()).limit(limit).offset(offset).all()
    except Exception as e:
        logger.exception("Failed to fetch reports: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch reports")
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "user_id": r.user_id,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "reason": r.reason,
            "status": r.status,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })
    return out


@app.get("/admin/reports/summary", response_model=ReportSummary)
def admin_reports_summary(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    Aggregated report summary grouped by target (target_type + target_id).
    Safer implementation: first aggregate counts, then fetch owner and sample reasons per group.
    """
    try:
        items = []
        total_reports = 0

        # 1) Aggregate counts per (target_type, target_id)
        agg_rows = (
            db.query(
                Report.target_type.label("target_type"),
                Report.target_id.label("target_id"),
                func.count(Report.id).label("report_count"),
            )
            .group_by(Report.target_type, Report.target_id)
            .order_by(func.count(Report.id).desc())
            .all()
        )

        # 2) For each aggregated row, fetch owner info and a sample of reasons
        for ar in agg_rows:
            ttype = (ar.target_type or "").lower()
            tid = int(ar.target_id)
            rc = int(ar.report_count or 0)
            total_reports += rc

            owner_id = None
            owner_name = None
            reasons_sample = None

            # fetch owner and sample reasons depending on target_type
            if ttype == "guidesleep":
                tgt = db.query(GuideSleep).filter(GuideSleep.id == tid).first()
                if tgt:
                    owner_id = getattr(tgt, "user_id", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{u.first_name} {u.last_name}"
                # sample reasons (limit 5 distinct)
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "guidesleep", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            elif ttype == "comment":
                c = db.query(Comment).filter(Comment.id == tid).first()
                if c:
                    owner_id = getattr(c, "user_id", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{u.first_name} {u.last_name}"
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "comment", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            elif ttype == "quest":
                q = db.query(Quest).filter(Quest.id == tid).first()
                if q:
                    owner_id = getattr(q, "created_by", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{u.first_name} {u.last_name}"
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "quest", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            else:
                # unknown target type: still collect sample reasons
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == ar.target_type, Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            items.append({
                "target_type": ar.target_type,
                "target_id": tid,
                "owner_id": int(owner_id) if owner_id is not None else None,
                "owner_name": owner_name,
                "report_count": rc,
                "reasons_sample": reasons_sample,
            })

        # sort by report_count desc (already ordered, but ensure)
        items_sorted = sorted(items, key=lambda x: x["report_count"], reverse=True)
        return {"items": items_sorted, "total_reports": total_reports}
    except Exception as e:
        logger.exception("Failed to build reports summary: %s", e)
        raise HTTPException(status_code=500, detail="Failed to build reports summary")



@app.put("/admin/reports/{report_id}", response_model=ReportOut)
def admin_update_report(report_id: int, payload: ReportUpdate = Body(...), admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    Update report status (admin only). If status == 'accepted' and target is guidesleep,
    the target guidesleep will be hidden (is_hidden = True).
    """
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")

    if payload.status:
        r.status = payload.status

        if payload.status == "accepted" and r.target_type == "guidesleep":
            try:
                tgt = db.query(GuideSleep).filter(GuideSleep.id == r.target_id).first()
                if tgt:
                    tgt.is_hidden = True
                    db.add(tgt)
            except Exception:
                logger.exception("Failed to apply accepted action to guidesleep id=%s", r.target_id)

    try:
        db.add(r)
        db.commit()
        db.refresh(r)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to update report id=%s: %s", report_id, e)
        raise HTTPException(status_code=500, detail="Failed to update report")

    return {
        "id": r.id,
        "user_id": r.user_id,
        "target_type": r.target_type,
        "target_id": r.target_id,
        "reason": r.reason,
        "status": r.status,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }
# --- Moderation & Admin endpoints (replace existing moderation/admin sections) ---
# Paste this block into backend/main.py, replacing previous admin/report/guidesleep handlers.
# Required names in module scope: app, get_db, engine, models: Report, GuideSleep, Comment, Quest, User, DiarySleep, QuestProgress, Vote
# schemas: ReportOut, ReportUpdate, ReportCreate, ReportSummary
# helpers: If you already have optional_current_user/require_admin defined elsewhere, keep those and remove the duplicates here.

from typing import List, Dict, Any, Optional
from fastapi import Body, Request, HTTPException, Depends, status
from sqlalchemy import text, func, and_, not_, literal_column
from sqlalchemy.orm import Session, Query
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Ensure these imports match your project layout
from database import get_db, engine
from models import (
    User,
    Report,
    GuideSleep,
    Comment,
    Quest,
    DiarySleep,
    QuestProgress,
    Vote,
)
from schemas import ReportOut, ReportUpdate, ReportCreate, ReportSummary

# -------------------------
# Lightweight optional_current_user (non-raising)
# -------------------------
try:
    optional_current_user  # type: ignore
except NameError:
    def optional_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
        """
        Return User if Authorization header contains a valid token and user exists.
        Return None if no header or token invalid.
        Non-raising helper used by feed/detail endpoints.
        """
        try:
            auth = None
            try:
                auth = request.headers.get("authorization") or request.headers.get("Authorization")
            except Exception:
                return None
            if not auth:
                return None
            parts = auth.split()
            if len(parts) != 2:
                return None
            token = parts[1]
            # Try to decode token using available jwt lib if present (best-effort)
            try:
                # prefer jose or pyjwt if available in globals
                jwt_lib = globals().get("jwt_decode_lib")
                if jwt_lib is None:
                    return None
                secret = globals().get("SECRET_KEY", "")
                algs = [globals().get("ALGORITHM", "HS256")]
                if globals().get("_JWT_LIB") == "jose":
                    payload = jwt_lib.decode(token, secret, algorithms=algs)
                else:
                    payload = jwt_lib.decode(token, secret, algorithms=algs)
                user_id = payload.get("sub") or payload.get("user_id") or payload.get("id")
                if user_id is None:
                    return None
                user_id = int(user_id)
            except Exception:
                return None
            try:
                return db.query(User).filter(User.id == user_id).first()
            except Exception:
                return None
        except Exception:
            return None

# -------------------------
# require_admin dependency (fallback)
# -------------------------
try:
    require_admin  # type: ignore
except NameError:
    def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
        """
        Resolve current user from Authorization header and ensure admin privileges.
        Adjust checks to match your User model (is_admin / is_superuser / role).
        """
        user = optional_current_user(request, db)
        if not user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin credentials required")
        if not getattr(user, "is_admin", False) and not getattr(user, "is_superuser", False) and getattr(user, "role", None) != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        return user

# -------------------------
# Helper: visible guidesleep query
# -------------------------
def visible_guidesleep_query(db: Session, current_user) -> Query:
    """
    Query for GuideSleep rows visible to the requester.
    Admins see everything. Non-admins see only non-hidden, non-deleted, and non-reported (non-rejected) posts.
    """
    q = db.query(GuideSleep)
    if current_user and getattr(current_user, "is_admin", False):
        return q

    if hasattr(GuideSleep, "is_hidden"):
        q = q.filter(GuideSleep.is_hidden == False)
    if hasattr(GuideSleep, "is_deleted"):
        q = q.filter(GuideSleep.is_deleted == False)

    rpt_exists = db.query(Report.id).filter(
        and_(
            Report.target_type == "guidesleep",
            Report.target_id == GuideSleep.id,
            Report.status != "rejected",
        )
    ).exists()
    q = q.filter(not_(rpt_exists))
    return q

# -------------------------
# Create report endpoint
# -------------------------
@app.post("/reports", response_model=ReportOut)
def create_report(payload: ReportCreate, request: Request, db: Session = Depends(get_db)):
    """
    Create a report for a target (guidesleep, comment, quest).
    Associates reporter if Authorization header valid.
    """
    ttype = (payload.target_type or "").strip().lower()
    if ttype not in ("guidesleep", "comment", "quest"):
        raise HTTPException(status_code=400, detail="Unsupported target_type")

    # validate target exists
    if ttype == "guidesleep":
        tgt = db.query(GuideSleep).filter(GuideSleep.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target guidesleep not found")
    elif ttype == "comment":
        tgt = db.query(Comment).filter(Comment.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target comment not found")
    elif ttype == "quest":
        tgt = db.query(Quest).filter(Quest.id == payload.target_id).first()
        if not tgt:
            raise HTTPException(status_code=404, detail="Target quest not found")

    reporter = optional_current_user(request, db)
    reporter_id = getattr(reporter, "id", None) if reporter else None

    rpt = Report(
        user_id=reporter_id,
        target_type=ttype,
        target_id=payload.target_id,
        reason=payload.reason,
        status="pending",
    )
    db.add(rpt)
    try:
        db.commit()
        db.refresh(rpt)
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create report: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create report")

    return {
        "id": rpt.id,
        "user_id": rpt.user_id,
        "target_type": rpt.target_type,
        "target_id": rpt.target_id,
        "reason": rpt.reason,
        "status": rpt.status,
        "created_at": rpt.created_at,
        "updated_at": rpt.updated_at,
    }

# -------------------------
# Admin: list reports (raw)
# -------------------------
@app.get("/admin/reports", response_model=List[ReportOut])
def admin_list_reports(limit: int = 100, offset: int = 0, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        rows = db.query(Report).order_by(Report.created_at.desc()).limit(limit).offset(offset).all()
    except Exception as e:
        logger.exception("Failed to fetch reports: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch reports")
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "user_id": r.user_id,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "reason": r.reason,
            "status": r.status,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })
    return out

# -------------------------
# Admin: aggregated reports summary
# -------------------------
@app.get("/admin/reports/summary", response_model=ReportSummary)
def admin_reports_summary(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        items = []
        total_reports = 0
        agg_rows = (
            db.query(
                Report.target_type.label("target_type"),
                Report.target_id.label("target_id"),
                func.count(Report.id).label("report_count"),
            )
            .group_by(Report.target_type, Report.target_id)
            .order_by(func.count(Report.id).desc())
            .all()
        )

        for ar in agg_rows:
            ttype = (ar.target_type or "").lower()
            try:
                tid = int(ar.target_id)
            except Exception:
                tid = None
            rc = int(ar.report_count or 0)
            total_reports += rc

            owner_id = None
            owner_name = None
            reasons_sample = None

            if ttype == "guidesleep" and tid is not None:
                tgt = db.query(GuideSleep).filter(GuideSleep.id == tid).first()
                if tgt:
                    owner_id = getattr(tgt, "user_id", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{getattr(u,'first_name', '')} {getattr(u,'last_name','')}".strip()
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "guidesleep", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            elif ttype == "comment" and tid is not None:
                c = db.query(Comment).filter(Comment.id == tid).first()
                if c:
                    owner_id = getattr(c, "user_id", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{getattr(u,'first_name','')} {getattr(u,'last_name','')}".strip()
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "comment", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            elif ttype == "quest" and tid is not None:
                q = db.query(Quest).filter(Quest.id == tid).first()
                if q:
                    owner_id = getattr(q, "created_by", None) or getattr(q, "user_id", None)
                    if owner_id:
                        u = db.query(User).filter(User.id == owner_id).first()
                        if u:
                            owner_name = f"{getattr(u,'first_name','')} {getattr(u,'last_name','')}".strip()
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == "quest", Report.target_id == tid)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            else:
                reason_rows = (
                    db.query(Report.reason)
                    .filter(Report.target_type == ar.target_type, Report.target_id == ar.target_id)
                    .distinct()
                    .limit(5)
                    .all()
                )
                reasons_sample = " || ".join([r[0] for r in reason_rows]) if reason_rows else None

            items.append({
                "target_type": ar.target_type,
                "target_id": int(ar.target_id) if ar.target_id is not None else None,
                "owner_id": int(owner_id) if owner_id is not None else None,
                "owner_name": owner_name,
                "report_count": rc,
                "reasons_sample": reasons_sample,
            })

        items_sorted = sorted(items, key=lambda x: x["report_count"], reverse=True)
        return {"items": items_sorted, "total_reports": total_reports}
    except Exception as e:
        logger.exception("Failed to build reports summary: %s", e)
        raise HTTPException(status_code=500, detail="Failed to build reports summary")

# -------------------------
# Admin: delete reports for a specific target
# -------------------------
@app.delete("/admin/reports/target/{target_type}/{target_id}", status_code=status.HTTP_200_OK)
def admin_delete_reports_for_target(
    target_type: str,
    target_id: int,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        q = db.query(Report).filter(Report.target_type == target_type, Report.target_id == target_id)
        count = q.count()
        if count == 0:
            return {"deleted": 0}
        q.delete(synchronize_session=False)
        db.commit()
        logger.info("Admin %s deleted %d reports for %s/%s", getattr(admin_user, "id", None), count, target_type, target_id)
        return {"deleted": count}
    except Exception as e:
        db.rollback()
        logger.exception("Failed to delete reports for target %s/%s: %s", target_type, target_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete reports for target")

# -------------------------
# Admin: delete a single report by id
# -------------------------
@app.delete("/admin/reports/{report_id}", status_code=200)
def admin_delete_report_by_id(report_id: int, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        rpt = db.query(Report).filter(Report.id == report_id).first()
        if not rpt:
            raise HTTPException(status_code=404, detail="Report not found")
        try:
            db.delete(rpt)
            db.commit()
            logger.info("Admin %s deleted report id=%s", getattr(admin_user, "id", None), report_id)
            return {"deleted": 1}
        except Exception:
            db.rollback()
            try:
                db.execute(text("DELETE FROM report WHERE id = :rid"), {"rid": report_id})
                db.commit()
                logger.info("Admin %s deleted report id=%s via raw SQL", getattr(admin_user, "id", None), report_id)
                return {"deleted": 1}
            except Exception as e2:
                db.rollback()
                logger.exception("Failed to delete report id=%s via raw SQL: %s", report_id, e2)
                raise HTTPException(status_code=500, detail="Failed to delete report")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception("Unexpected error deleting report id=%s: %s", report_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete report")

# -------------------------
# Admin: update a single report (accept => delete target; reject => set rejected)
# -------------------------
@app.put("/admin/reports/{report_id}", response_model=ReportOut)
def admin_update_report(
    report_id: int,
    payload: ReportUpdate = Body(...),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        if payload.status:
            new_status = (payload.status or "").strip().lower()
            r.status = new_status

            if new_status == "accepted":
                ttype = (r.target_type or "").strip().lower()
                try:
                    tid = int(r.target_id)
                except Exception:
                    tid = None

                if tid is not None:
                    try:
                        if ttype == "guidesleep":
                            gs = db.query(GuideSleep).filter(GuideSleep.id == tid).with_for_update().first()
                            if gs is not None:
                                db.delete(gs)
                                logger.info("Admin %s deleted guidesleep id=%s due to accepted report %s",
                                            getattr(admin_user, "id", None), tid, report_id)
                            else:
                                logger.warning("Guidesleep id=%s not found for deletion", tid)

                        elif ttype == "comment":
                            cm = db.query(Comment).filter(Comment.id == tid).with_for_update().first()
                            if cm is not None:
                                db.delete(cm)
                                logger.info("Admin %s deleted comment id=%s due to accepted report %s",
                                            getattr(admin_user, "id", None), tid, report_id)
                            else:
                                logger.warning("Comment id=%s not found for deletion", tid)

                        elif ttype in ("quest", "quests"):
                            qobj = db.query(Quest).filter(Quest.id == tid).with_for_update().first()
                            if qobj is not None:
                                db.delete(qobj)
                                logger.info("Admin %s deleted quest id=%s due to accepted report %s",
                                            getattr(admin_user, "id", None), tid, report_id)
                            else:
                                logger.warning("Quest id=%s not found for deletion", tid)

                        else:
                            logger.warning("Unsupported target_type '%s' for deletion (report id=%s)", ttype, report_id)

                        # mark sibling reports accepted (best-effort)
                        try:
                            db.query(Report).filter(
                                Report.target_type == r.target_type,
                                Report.target_id == r.target_id,
                                Report.status != "accepted",
                            ).update({"status": "accepted"}, synchronize_session=False)
                        except Exception:
                            logger.exception("Failed to update sibling reports for target %s/%s", r.target_type, r.target_id)

                    except Exception:
                        logger.exception("Error while attempting to delete target for accepted report id=%s", report_id)

            elif new_status == "rejected":
                logger.info("Admin %s rejected report id=%s", getattr(admin_user, "id", None), report_id)

        # commit once for report + any deletes
        db.add(r)
        db.commit()
        db.refresh(r)

    except Exception as e:
        try:
            db.rollback()
        except Exception:
            logger.exception("Rollback failed for report id=%s", report_id)
        logger.exception("Failed to update report id=%s: %s", report_id, e)
        raise HTTPException(status_code=500, detail="Failed to update report")

    return {
        "id": r.id,
        "user_id": r.user_id,
        "target_type": r.target_type,
        "target_id": r.target_id,
        "reason": r.reason,
        "status": r.status,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }

# -------------------------
# Admin: accept all reports for a target and delete the target (convenience)
# -------------------------
@app.post("/admin/reports/target/{target_type}/{target_id}/accept")
def admin_accept_reports_and_delete_target(
    target_type: str,
    target_id: int,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tt = (target_type or "").strip().lower()
    try:
        reports = db.query(Report).filter(Report.target_type == tt, Report.target_id == target_id).all()
        if not reports:
            return {"accepted_reports": 0, "deleted": False, "message": "no reports found"}

        for r in reports:
            r.status = "accepted"
            db.add(r)

        deleted_applied = False
        delete_msg = "no action"

        try:
            if tt == "guidesleep":
                gs = db.query(GuideSleep).filter(GuideSleep.id == target_id).first()
                if gs is not None:
                    db.delete(gs)
                    deleted_applied = True
                    delete_msg = "guidesleep deleted"
                else:
                    delete_msg = "guidesleep not found"

            elif tt == "comment":
                cm = db.query(Comment).filter(Comment.id == target_id).first()
                if cm is not None:
                    db.delete(cm)
                    deleted_applied = True
                    delete_msg = "comment deleted"
                else:
                    delete_msg = "comment not found"

            elif tt in ("quest", "quests"):
                qobj = db.query(Quest).filter(Quest.id == target_id).first()
                if qobj is not None:
                    db.delete(qobj)
                    deleted_applied = True
                    delete_msg = "quest deleted"
                else:
                    delete_msg = "quest not found"
            else:
                delete_msg = "unsupported target_type"
        except Exception as e:
            logger.exception("Error while deleting target %s/%s: %s", tt, target_id, e)
            delete_msg = "exception while deleting"

        try:
            db.commit()
        except Exception as commit_err:
            try:
                db.rollback()
            except Exception:
                logger.exception("Rollback failed for accept-and-delete %s/%s", tt, target_id)
            logger.exception("Commit failed when accepting reports for %s/%s: %s", tt, target_id, commit_err)
            raise HTTPException(status_code=500, detail="Failed to commit changes")

        logger.info("Admin %s accepted %d reports for %s/%s (deleted=%s) - %s",
                    getattr(admin_user, "id", None), len(reports), tt, target_id, deleted_applied, delete_msg)
        return {"accepted_reports": len(reports), "deleted": deleted_applied, "message": delete_msg}

    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("Failed to accept reports and delete target %s/%s: %s", target_type, target_id, e)
        raise HTTPException(status_code=500, detail="Failed to accept reports and delete target")

# -------------------------
# Feed: list guidesleep (use helper)
# -------------------------
@app.get("/guidesleep")
def list_guidesleep(limit: int = 50, offset: int = 0, request: Request = None, db: Session = Depends(get_db)):
    try:
        current_user = optional_current_user(request, db)
        q = visible_guidesleep_query(db, current_user)
        rows = q.order_by(GuideSleep.created_at.desc()).limit(limit).offset(offset).all()
        return rows
    except Exception as e:
        logger.exception("Failed to list guidesleep: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch guidesleep")

# -------------------------
# Detail: get single guidesleep (use helper)
# -------------------------
@app.get("/guidesleep/{guidesleep_id}")
def get_guidesleep(guidesleep_id: int, request: Request = None, db: Session = Depends(get_db)):
    try:
        current_user = optional_current_user(request, db)
        q = visible_guidesleep_query(db, current_user).filter(GuideSleep.id == guidesleep_id)
        gs = q.first()
        if not gs:
            raise HTTPException(status_code=404, detail="Not found")
        return gs
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get guidesleep id=%s: %s", guidesleep_id, e)
        raise HTTPException(status_code=500, detail="Failed to fetch guidesleep")

# -------------------------
# Admin: list users (unchanged)
# -------------------------
@app.get("/admin/users")
def admin_list_users(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).limit(100).all()
    return users

# -------------------------
# Admin: set user role (unchanged)
# -------------------------
from pydantic import BaseModel

class RoleUpdatePayload(BaseModel):
    role: str

@app.patch("/admin/users/{user_id}/role")
def admin_set_user_role(
    user_id: int,
    payload: RoleUpdatePayload = Body(...),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        u = db.query(User).filter(User.id == user_id).with_for_update().first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        new_role = (payload.role or "").strip().lower()
        if new_role == "":
            raise HTTPException(status_code=400, detail="role is required")

        changed = False
        prev_role = None
        if hasattr(u, "role"):
            prev_role = getattr(u, "role")
            if prev_role != new_role:
                setattr(u, "role", new_role)
                changed = True
        elif hasattr(u, "role_name"):
            prev_role = getattr(u, "role_name")
            if prev_role != new_role:
                setattr(u, "role_name", new_role)
                changed = True
        else:
            if new_role in ("admin", "administrator", "moderator"):
                if not getattr(u, "is_admin", False):
                    if hasattr(u, "is_admin"):
                        u.is_admin = True
                        changed = True
            else:
                if getattr(u, "is_admin", False):
                    if hasattr(u, "is_admin"):
                        u.is_admin = False
                        changed = True

        if changed:
            db.add(u)
            try:
                db.commit()
            except Exception as commit_err:
                db.rollback()
                logger.exception("Failed to commit role change for user %s: %s", user_id, commit_err)
                raise HTTPException(status_code=500, detail="Failed to update user role")
            db.refresh(u)
            logger.info("Admin %s changed role for user %s: %s -> %s", getattr(admin_user, "id", None), user_id, prev_role, new_role)
        else:
            logger.debug("Admin %s attempted to set role for user %s but no change needed", getattr(admin_user, "id", None), user_id)

        return {
            "id": u.id,
            "email": getattr(u, "email", None),
            "first_name": getattr(u, "first_name", None),
            "last_name": getattr(u, "last_name", None),
            "role": getattr(u, "role", getattr(u, "role_name", "user")),
            "is_admin": getattr(u, "is_admin", False),
            "updated_at": getattr(u, "updated_at", None),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in admin_set_user_role for user %s: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Failed to set user role")

# -------------------------
# Admin: toggle user role (unchanged)
# -------------------------
@app.post("/admin/users/{user_id}/toggle-role")
def admin_toggle_user_role(
    user_id: int,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        u = db.query(User).filter(User.id == user_id).with_for_update().first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        prev_role = None
        new_role = None
        changed = False

        if hasattr(u, "role"):
            prev_role = (getattr(u, "role") or "").strip().lower()
            new_role = "user" if prev_role == "admin" else "admin"
            if prev_role != new_role:
                setattr(u, "role", new_role)
                changed = True

        elif hasattr(u, "role_name"):
            prev_role = (getattr(u, "role_name") or "").strip().lower()
            new_role = "user" if prev_role == "admin" else "admin"
            if prev_role != new_role:
                setattr(u, "role_name", new_role)
                changed = True

        elif hasattr(u, "is_admin"):
            prev_flag = bool(getattr(u, "is_admin"))
            new_flag = not prev_flag
            u.is_admin = new_flag
            prev_role = "admin" if prev_flag else "user"
            new_role = "admin" if new_flag else "user"
            changed = True

        else:
            raise HTTPException(status_code=400, detail="User model does not support role toggling")

        if changed:
            db.add(u)
            try:
                db.commit()
            except Exception as commit_err:
                db.rollback()
                logger.exception("Failed to commit toggle role for user %s: %s", user_id, commit_err)
                raise HTTPException(status_code=500, detail="Failed to toggle user role")
            db.refresh(u)
            logger.info("Admin %s toggled role for user %s: %s -> %s", getattr(admin_user, "id", None), user_id, prev_role, new_role)

        return {
            "id": u.id,
            "email": getattr(u, "email", None),
            "first_name": getattr(u, "first_name", None),
            "last_name": getattr(u, "last_name", None),
            "role": getattr(u, "role", getattr(u, "role_name", "admin" if getattr(u, "is_admin", False) else "user")),
            "is_admin": getattr(u, "is_admin", False),
            "updated_at": getattr(u, "updated_at", None),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in admin_toggle_user_role for user %s: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Failed to toggle user role")

# -------------------------
# Admin: delete user (preserve previous behavior)
# -------------------------
def _fk_field_for_user(model):
    for candidate in ("user_id", "created_by", "creator_id", "owner_id", "author_id"):
        if hasattr(model, candidate):
            return getattr(model, candidate)
    return None

@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        try:
            u = db.query(User).filter(User.id == user_id).with_for_update().first()
        except Exception:
            u = db.query(User).filter(User.id == user_id).first()

        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        try:
            current_admin_id = getattr(admin_user, "id", None)
            if current_admin_id is not None and int(current_admin_id) == int(user_id):
                raise HTTPException(status_code=400, detail="Cannot delete your own account")
        except HTTPException:
            raise
        except Exception:
            pass

        if getattr(u, "is_system", False):
            raise HTTPException(status_code=400, detail="Cannot delete system account")

        applied_soft_delete = False
        try:
            if hasattr(u, "is_deleted"):
                setattr(u, "is_deleted", True); applied_soft_delete = True
            elif hasattr(u, "is_active"):
                setattr(u, "is_active", False); applied_soft_delete = True
            elif hasattr(u, "deleted_at"):
                setattr(u, "deleted_at", datetime.utcnow()); applied_soft_delete = True
        except Exception:
            applied_soft_delete = False

        if applied_soft_delete:
            db.add(u)
            try:
                db.commit()
            except Exception as commit_err:
                db.rollback()
                logger.exception("Failed to commit soft-delete for user %s: %s", user_id, commit_err)
                raise HTTPException(status_code=500, detail="Failed to delete user")
            logger.info("Admin %s soft-deleted user %s", getattr(admin_user, "id", None), user_id)
            return {"deleted": True, "soft_deleted": True}

        try:
            try:
                db.query(GuideSleep).filter(GuideSleep.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete guides for user %s", user_id)

            q_fk = _fk_field_for_user(Quest)
            if q_fk is not None:
                try:
                    db.query(Quest).filter(q_fk == user_id).delete(synchronize_session=False)
                except Exception:
                    logger.exception("Failed to bulk-delete quests for user %s", user_id)

            try:
                db.query(Comment).filter(Comment.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete comments for user %s", user_id)

            try:
                db.query(Report).filter(Report.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete reports for user %s", user_id)

            try:
                db.query(DiarySleep).filter(DiarySleep.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete diary entries for user %s", user_id)

            try:
                db.query(QuestProgress).filter(QuestProgress.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete quest progress for user %s", user_id)

            try:
                db.query(Vote).filter(Vote.user_id == user_id).delete(synchronize_session=False)
            except Exception:
                logger.exception("Failed to bulk-delete votes for user %s", user_id)

            try:
                db.commit()
            except IntegrityError as ie:
                db.rollback()
                logger.exception("IntegrityError when deleting related content for user %s: %s", user_id, ie)
                raise HTTPException(status_code=400, detail="Cannot delete user because related records exist")
            except Exception as commit_err:
                db.rollback()
                logger.exception("Failed to commit deletion of related content for user %s: %s", user_id, commit_err)
                raise HTTPException(status_code=500, detail="Failed to delete related content")

            try:
                db.delete(u)
                db.commit()
                logger.info("Admin %s hard-deleted user %s and removed related content", getattr(admin_user, "id", None), user_id)
                return {"deleted": True, "soft_deleted": False}
            except IntegrityError as ie:
                db.rollback()
                logger.exception("IntegrityError deleting user %s: %s", user_id, ie)
                raise HTTPException(status_code=400, detail="Cannot delete user due to remaining related records")
            except Exception as hard_err:
                db.rollback()
                logger.exception("Failed to hard-delete user %s: %s", user_id, hard_err)
                raise HTTPException(status_code=500, detail="Failed to delete user")

        except HTTPException:
            raise
        except Exception as e:
            db.rollback()
            logger.exception("Unexpected error while removing related content for user %s: %s", user_id, e)
            raise HTTPException(status_code=500, detail="Failed to delete related content and user")

    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("Unexpected error when deleting user %s: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete user")
# main.py — robust POST /guidesleep handler (replace existing)
from typing import Dict, Any, Optional
from fastapi import Request, Body, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import json
import re
from datetime import datetime

@app.post("/guidesleep")
async def create_guidesleep(
    request: Request,
    body: Optional[Dict[str, Any]] = Body(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Robust create guidesleep / share-as-new handler.
    - Accepts JSON or form payloads (flexible parsing).
    - If shared_from_id provided, copies missing fields from original post.
    - Applies safe fallbacks so "share as new post" succeeds consistently.
    """
    # 1) Read raw body and parse flexibly
    try:
        raw_bytes = await request.body()
        raw_text = raw_bytes.decode("utf-8") if raw_bytes else ""
    except Exception:
        raw_text = ""

    parsed: Dict[str, Any] = {}
    # If FastAPI already parsed body into 'body' param, use it
    if isinstance(body, dict) and body:
        parsed = dict(body)
    else:
        # Try parse JSON from raw text
        if raw_text:
            try:
                parsed = json.loads(raw_text)
                if not isinstance(parsed, dict):
                    parsed = {}
            except Exception:
                # Not JSON — try form parsing
                try:
                    form = await request.form()
                    parsed = {k: v for k, v in form.items()}
                except Exception:
                    parsed = {}
        else:
            # empty body — try request.form() anyway
            try:
                form = await request.form()
                parsed = {k: v for k, v in form.items()}
            except Exception:
                parsed = {}

    logger.info("POST /guidesleep raw_body (truncated): %s", (raw_text or "")[:300])
    logger.info("POST /guidesleep parsed payload keys: %s", list(parsed.keys()))

    # 2) Normalizers / helpers
    def _get_str(key: str) -> str:
        v = parsed.get(key)
        if v is None:
            return ""
        if isinstance(v, str):
            s = v.strip()
            if s.lower() in ("null", "none"):
                return ""
            return s
        return str(v).strip()

    def _get_any(key: str):
        return parsed.get(key)

    title = _get_str("title") or _get_str("outer_title") or _get_str("original_title")
    note = _get_str("note") or _get_str("body") or ""
    category = _get_str("category") or None
    start_date = _get_any("start_date")
    end_date = _get_any("end_date")
    sleep_time = _get_any("sleep_time")
    wake_time = _get_any("wake_time")

    # Accept multiple possible keys for shared id
    shared_from_id = (
        parsed.get("shared_from_id")
        or parsed.get("shared_from")
        or parsed.get("sharedFromId")
        or parsed.get("sharedFrom")
    )
    original_title_payload = _get_str("original_title") or _get_str("originalTitle")

    # Normalize shared_from_id to int when possible
    if isinstance(shared_from_id, str):
        s = shared_from_id.strip()
        m = re.search(r"\d+", s)
        if m:
            try:
                shared_from_id = int(m.group(0))
            except Exception:
                shared_from_id = None
        else:
            shared_from_id = None
    elif isinstance(shared_from_id, (int, float)):
        try:
            shared_from_id = int(shared_from_id)
        except Exception:
            shared_from_id = None
    else:
        shared_from_id = None

    # 3) If reposting, try to load original and copy missing fields
    original = None
    if shared_from_id:
        try:
            original = db.query(GuideSleep).filter(GuideSleep.id == int(shared_from_id)).first()
        except Exception:
            original = None

        if not original:
            logger.warning("shared_from_id provided but original not found: %s", shared_from_id)
            original = None
        else:
            if not note:
                note = getattr(original, "note", "") or ""
            if not category:
                category = getattr(original, "category", None)
            if (not start_date or start_date == "") and getattr(original, "start_date", None) is not None:
                start_date = getattr(original, "start_date")
            if (not end_date or end_date == "") and getattr(original, "end_date", None) is not None:
                end_date = getattr(original, "end_date")
            if (not sleep_time or sleep_time == "") and getattr(original, "sleep_time", None) is not None:
                sleep_time = getattr(original, "sleep_time")
            if (not wake_time or wake_time == "") and getattr(original, "wake_time", None) is not None:
                wake_time = getattr(original, "wake_time")

    # 4) Safe fallbacks so share always succeeds
    if not note:
        note = original_title_payload or title or (getattr(original, "note", "") if original else "") or "แชร์โพสต์"
    if not category:
        category = getattr(original, "category", None) or "ทั่วไป"

    # Minimal validation
    if note is None or str(note).strip() == "":
        raise HTTPException(status_code=400, detail="note is required")
    if category is None or str(category).strip() == "":
        raise HTTPException(status_code=400, detail="category is required")

    # 5) Build new GuideSleep instance and populate fields safely
    new_gs = GuideSleep()
    if hasattr(new_gs, "user_id"):
        try:
            new_gs.user_id = int(getattr(current_user, "id", None))
        except Exception:
            new_gs.user_id = getattr(current_user, "id", None)

    if title:
        if hasattr(new_gs, "title"):
            new_gs.title = title
        else:
            setattr(new_gs, "title", title)

    if shared_from_id:
        if hasattr(new_gs, "original_title"):
            new_gs.original_title = original_title_payload or getattr(original, "title", None)
        if hasattr(new_gs, "shared_from_id"):
            try:
                new_gs.shared_from_id = int(shared_from_id)
            except Exception:
                new_gs.shared_from_id = shared_from_id

    if hasattr(new_gs, "note"):
        new_gs.note = note
    else:
        setattr(new_gs, "note", note)

    if hasattr(new_gs, "category"):
        new_gs.category = category
    else:
        setattr(new_gs, "category", category)

    if start_date is not None and hasattr(new_gs, "start_date"):
        new_gs.start_date = start_date
    if end_date is not None and hasattr(new_gs, "end_date"):
        new_gs.end_date = end_date
    if sleep_time is not None and hasattr(new_gs, "sleep_time"):
        new_gs.sleep_time = sleep_time
    if wake_time is not None and hasattr(new_gs, "wake_time"):
        new_gs.wake_time = wake_time

    if original and getattr(original, "image_url", None):
        if hasattr(new_gs, "image_url"):
            if not getattr(new_gs, "image_url", None):
                new_gs.image_url = original.image_url
        else:
            setattr(new_gs, "image_url", original.image_url)

    # 6) Persist new post with robust error handling
    db.add(new_gs)
    try:
        db.commit()
    except IntegrityError as ie:
        db.rollback()
        logger.exception("IntegrityError creating guidesleep: %s", ie)
        raise HTTPException(status_code=400, detail="Failed to create guidesleep due to integrity error")
    except Exception as e:
        db.rollback()
        logger.exception("Unexpected error creating guidesleep: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create guidesleep")

    try:
        db.refresh(new_gs)
    except Exception:
        logger.debug("db.refresh(new_gs) failed, continuing")

    # 7) Safely increment share_count on original in its own transaction
    if original and hasattr(original, "share_count"):
        try:
            original.share_count = (getattr(original, "share_count", 0) or 0) + 1
            db.add(original)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning("Failed to increment share_count for original id=%s", getattr(original, "id", None))

    logger.info("Created guidesleep id=%s from shared_from=%s", getattr(new_gs, "id", None), shared_from_id)
    return new_gs
# debug handler — วางชั่วคราวใน main.py แทน POST /guidesleep
from fastapi import Request, Body, Depends
from typing import Optional, Dict, Any

@app.post("/guidesleep")
async def debug_guidesleep_inspect(
    request: Request,
    body: Optional[Dict[str, Any]] = Body(None),
    current_user: User = Depends(get_current_user),
):
    # read raw body
    try:
        raw = await request.body()
        raw_text = raw.decode("utf-8") if raw else ""
    except Exception:
        raw_text = ""

    # try parsed body from FastAPI param
    parsed = body if isinstance(body, dict) else None

    # try fallback parse
    if not parsed:
        try:
            parsed = await request.json()
        except Exception:
            try:
                form = await request.form()
                parsed = {k: v for k, v in form.items()}
            except Exception:
                parsed = {}

    headers = dict(request.headers)
    # log for server console
    logger.info("DEBUG /guidesleep raw_text: %s", raw_text[:1000])
    logger.info("DEBUG /guidesleep parsed keys: %s", list(parsed.keys()))
    logger.info("DEBUG /guidesleep headers: %s", {k: headers.get(k) for k in ['content-type','authorization']})

    # return what server saw (for debugging only)
    return {"raw_text": raw_text[:2000], "parsed": parsed, "headers": {"content-type": headers.get("content-type"), "authorization": headers.get("authorization")}}
