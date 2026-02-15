# FlashSleep/backend/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import date, datetime, time

# ---------------- User ----------------
class UserCreate(BaseModel):
    first_name: str
    last_name: str
    gender: Optional[str]
    birthdate: Optional[date]
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    first_name: Optional[str]
    last_name: Optional[str]
    gender: Optional[str]
    birthdate: Optional[date]

class UserOut(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: EmailStr
    gender: Optional[str]
    birthdate: Optional[date]
    image_url: Optional[str]
    role: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    token: str
    user: UserOut

    class Config:
        orm_mode = True

# ---------------- GuideSleep ----------------
class GuideSleepCreate(BaseModel):
    category: str
    note: Optional[str]
    # Align with models: GuideSleep.start_date/end_date are DateTime in models.py
    start_date: datetime
    end_date: datetime
    sleep_time: str
    wake_time: str

    class Config:
        orm_mode = True

class GuideSleepUpdate(BaseModel):
    category: Optional[str]
    note: Optional[str]
    # Align with models: use datetime
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    sleep_time: Optional[str]
    wake_time: Optional[str]
    is_hidden: Optional[bool]

    class Config:
        orm_mode = True

class GuideSleepOut(BaseModel):
    id: int
    category: str
    note: Optional[str]
    # Align with models: use datetime
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    sleep_time: Optional[str]
    wake_time: Optional[str]
    user_id: int
    user_name: Optional[str]
    image_url: Optional[str]
    # voting fields
    score: int
    user_vote: int
    # moderation flag
    is_hidden: Optional[bool] = False

    class Config:
        orm_mode = True

# ---------------- Vote ----------------
class VoteCreate(BaseModel):
    value: int  # allowed values: -4..-1, 1..4, 0 (0 can be used to remove vote)

class VoteOut(BaseModel):
    id: int
    user_id: int
    guidesleep_id: int
    value: int
    created_at: datetime

    class Config:
        orm_mode = True

# ---------------- Comment ----------------
class CommentCreate(BaseModel):
    content: str
    guidesleep_id: int

class CommentOut(BaseModel):
    id: int
    content: str
    created_at: datetime
    user_id: int
    guidesleep_id: int
    user_name: Optional[str]
    image_url: Optional[str]
    is_hidden: Optional[bool] = False
    is_deleted: Optional[bool] = False

    class Config:
        orm_mode = True

# ---------------- DiarySleep ----------------
class DiarySleepBase(BaseModel):
    note: Optional[str]
    start_date: date
    end_date: date
    sleep_time: time
    wake_time: time

class DiarySleepCreate(DiarySleepBase):
    pass

class DiarySleepStart(BaseModel):
    actual_sleep_start: datetime

    class Config:
        orm_mode = True

class DiarySleepWake(BaseModel):
    actual_wake_time: datetime
    duration_minutes: Optional[int]

    class Config:
        orm_mode = True

class DiarySleepOut(BaseModel):
    id: int
    note: Optional[str]
    start_date: date
    end_date: date
    sleep_time: time
    wake_time: time
    actual_sleep_start: Optional[datetime]
    actual_wake_time: Optional[datetime]
    actual_wake_hour: Optional[int]
    total_sleep_minutes: Optional[int]
    user_id: int

    class Config:
        orm_mode = True

class DiarySleepUpdate(BaseModel):
    note: Optional[str]
    start_date: Optional[date]
    end_date: Optional[date]
    sleep_time: Optional[time]
    wake_time: Optional[time]

# ---------------- Quest (AddQuest) ----------------
class QuestCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = None

    class Config:
        orm_mode = True

class QuestUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    start_date: Optional[date]
    end_date: Optional[date]
    status: Optional[str]
    is_hidden: Optional[bool]
    is_deleted: Optional[bool]

    class Config:
        orm_mode = True

class QuestOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    created_by: Optional[int]
    status: str
    start_date: Optional[date]
    end_date: Optional[date]
    total_percent: Optional[int] = 0
    total_score: Optional[int] = 0
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    is_hidden: Optional[bool] = False
    is_deleted: Optional[bool] = False

    class Config:
        orm_mode = True

# ---------------- QuestProgress ----------------
class QuestProgressCreate(BaseModel):
    user_id: Optional[int] = None
    progress: Dict[str, Any]
    totals: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None
    quest_id: Optional[int] = None

    class Config:
        orm_mode = True

class QuestProgressOut(BaseModel):
    id: int
    quest_id: Optional[int]
    user_id: Optional[int]
    data: Optional[str]
    totals: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True

# ---------------- Report ----------------
class ReportCreate(BaseModel):
    target_type: str  # e.g., 'guidesleep', 'comment', 'quest'
    target_id: int
    reason: str

    class Config:
        orm_mode = True

class ReportOut(BaseModel):
    id: int
    user_id: Optional[int]
    target_type: str
    target_id: int
    reason: str
    status: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True

class ReportUpdate(BaseModel):
    status: Optional[str]  # admin only: pending/reviewed/accepted/rejected

    class Config:
        orm_mode = True

# ---------------- Report summaries for admin UI ----------------
class ReportListItem(BaseModel):
    target_type: str
    target_id: int
    owner_id: Optional[int]
    owner_name: Optional[str]
    report_count: int
    reasons_sample: Optional[str] = None  # aggregated or concatenated reasons

    class Config:
        orm_mode = True

class ReportSummary(BaseModel):
    items: List[ReportListItem]
    total_reports: int

    class Config:
        orm_mode = True

# ---------------- Admin ----------------
class AdminStats(BaseModel):
    total_users: int
    total_guides: int
    total_comments: int
    total_votes: int

    class Config:
        orm_mode = True
