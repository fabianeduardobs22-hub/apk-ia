from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import User


def get_current_user(
    db: Session = Depends(get_db),
    x_user: str | None = Header(default=None, alias="X-User"),
):
    if not x_user:
        raise HTTPException(status_code=401, detail="Missing X-User header")

    user = db.scalar(select(User).where(User.username == x_user))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid user")

    return user
