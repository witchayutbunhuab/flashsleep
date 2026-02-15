# backend/models.py
from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    Text,
    DateTime,
    Date,
    Time,
    UniqueConstraint,
    func,
    Boolean,
    text,
    Index,
)
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    gender = Column(String(50), nullable=True)
    birthdate = Column(Date, nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    image_url = Column(String(255), nullable=True)

    role = Column(String(32), nullable=False, server_default="user")
    # Use server_default=func.now() so DB stores proper DATETIME values
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    guidesleep = relationship("GuideSleep", back_populates="user", cascade="all, delete-orphan")
    comments = relationship("Comment", back_populates="user", cascade="all, delete-orphan")
    diarysleep = relationship("DiarySleep", back_populates="user", cascade="all, delete-orphan")
    votes = relationship("Vote", back_populates="user", cascade="all, delete-orphan")
    quests = relationship("Quest", back_populates="creator", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    quest_progress = relationship("QuestProgress", back_populates="user", cascade="all, delete-orphan")


class GuideSleep(Base):
    __tablename__ = "guidesleep"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(100), nullable=False)
    note = Column(Text, nullable=True)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    sleep_time = Column(String(50), nullable=False)
    wake_time = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    is_hidden = Column(Boolean, nullable=False, server_default=text("0"))

    user = relationship("User", back_populates="guidesleep")
    comments = relationship("Comment", back_populates="guidesleep", cascade="all, delete-orphan")
    votes = relationship("Vote", back_populates="guidesleep", cascade="all, delete-orphan")


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    # use server_default so DB returns DATETIME type
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    guidesleep_id = Column(Integer, ForeignKey("guidesleep.id", ondelete="CASCADE"), nullable=False)

    user = relationship("User", back_populates="comments")
    guidesleep = relationship("GuideSleep", back_populates="comments")


class DiarySleep(Base):
    __tablename__ = "diarysleep"

    id = Column(Integer, primary_key=True, index=True)
    note = Column(Text, nullable=True)

    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    sleep_time = Column(Time, nullable=False)
    wake_time = Column(Time, nullable=False)

    actual_sleep_start = Column(DateTime, nullable=True)
    actual_wake_time = Column(DateTime, nullable=True)
    actual_wake_hour = Column(Integer, nullable=True)
    total_sleep_minutes = Column(Integer, nullable=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = relationship("User", back_populates="diarysleep")


class Vote(Base):
    __tablename__ = "votes"
    __table_args__ = (UniqueConstraint("user_id", "guidesleep_id", name="uix_user_guidesleep"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    guidesleep_id = Column(Integer, ForeignKey("guidesleep.id", ondelete="CASCADE"), nullable=False)
    value = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    user = relationship("User", back_populates="votes")
    guidesleep = relationship("GuideSleep", back_populates="votes")


class Quest(Base):
    __tablename__ = "quests"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    # keep created_by name but be explicit about relationship foreign key
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(32), nullable=False, server_default="draft")
    start_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    # explicitly tell relationship which FK to use
    creator = relationship("User", back_populates="quests", foreign_keys=[created_by])
    progress_entries = relationship("QuestProgress", back_populates="quest", cascade="all, delete-orphan")


class Report(Base):
    __tablename__ = "report"
    __table_args__ = (
        Index("idx_report_target", "target_type", "target_id"),
        Index("idx_report_user", "user_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target_type = Column(String(64), nullable=False)
    target_id = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, server_default="pending")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="reports")


class QuestProgress(Base):
    __tablename__ = "quest_progress"

    id = Column(Integer, primary_key=True, index=True)
    quest_id = Column(Integer, ForeignKey("quests.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # JSON payload (string) storing periods/items/status etc.
    data = Column(Text, nullable=True)
    totals = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    quest = relationship("Quest", back_populates="progress_entries")
    user = relationship("User", back_populates="quest_progress")
