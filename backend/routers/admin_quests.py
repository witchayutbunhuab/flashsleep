# backend/routers/admin_quests.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
import json
from datetime import date

from database import get_db
from models import Quest, User
from schemas import QuestCreate, QuestOut, QuestUpdate
from main import require_admin, get_current_user  # ensure main defines these before including this router

router = APIRouter(prefix="/admin/quests", tags=["admin"])


def _calculate_age(birthdate: Optional[date]) -> Optional[int]:
    if not birthdate:
        return None
    today = date.today()
    age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
    return age


def _age_to_group(age: Optional[int]) -> str:
    if age is None:
        return "all"
    if age <= 12:
        return "child"
    if 13 <= age <= 19:
        return "teen"
    if 20 <= age <= 59:
        return "adult"
    return "senior"


@router.post("", response_model=QuestOut)
def create_quest(data: QuestCreate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    Create a new quest. `description` is expected to be a JSON string (structured tasks),
    and `age_group` can be provided inside description or as a top-level field (if schema extended).
    """
    q = Quest(
        title=data.title,
        description=data.description,
        created_by=getattr(current_user, "id", None),
        start_date=data.start_date,
        end_date=data.end_date,
    )

    # If model has age_group column and description contains age_group, set it
    try:
        # attempt to read age_group from description JSON if present
        if data.description:
            try:
                parsed = json.loads(data.description)
                ag = parsed.get("age_group")
                if ag and hasattr(Quest, "age_group"):
                    setattr(q, "age_group", ag)
            except Exception:
                # ignore parse errors
                pass
    except Exception:
        pass

    db.add(q)
    try:
        db.commit()
        db.refresh(q)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create quest: {e}")
    return q


@router.get("", response_model=List[QuestOut])
def list_quests(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    List all quests (admin view).
    """
    try:
        rows = db.query(Quest).order_by(Quest.created_at.desc()).all()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list quests: {e}")


@router.get("/{quest_id}", response_model=QuestOut)
def get_quest(quest_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")
    return q


@router.put("/{quest_id}", response_model=QuestOut)
def update_quest(quest_id: int, payload: QuestUpdate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")

    for k, v in payload.dict(exclude_unset=True).items():
        # only set attributes that exist on the model
        if hasattr(q, k):
            setattr(q, k, v)
    try:
        db.commit()
        db.refresh(q)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update quest: {e}")
    return q


@router.delete("/{quest_id}")
def delete_quest(quest_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(Quest).filter(Quest.id == quest_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Quest not found")
    try:
        db.delete(q)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete quest: {e}")
    return {"message": "Quest deleted", "id": quest_id}


# Public endpoint for users to fetch quests appropriate for their age group.
# Path: /admin/quests/for-user
@router.get("/for-user", response_model=List[QuestOut])
def quests_for_current_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Return quests filtered by the current user's age group.
    If the Quest model has an `age_group` column, filter by it (or 'all' / NULL).
    If not, return all quests (backwards compatible).
    The `description` field is returned as stored (string). Frontend can parse JSON if needed.
    """
    age = _calculate_age(getattr(current_user, "birthdate", None))
    group = _age_to_group(age)

    # If Quest has age_group attribute (column), apply filter; otherwise return all
    age_group_col = getattr(Quest, "age_group", None)
    try:
        if age_group_col is not None:
            rows = (
                db.query(Quest)
                .filter(
                    (age_group_col == group) | (age_group_col == None) | (age_group_col == "all")
                )
                .order_by(Quest.created_at.desc())
                .all()
            )
        else:
            rows = db.query(Quest).order_by(Quest.created_at.desc()).all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch quests for user: {e}")

    return rows
