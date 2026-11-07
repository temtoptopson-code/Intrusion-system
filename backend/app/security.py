from datetime import datetime,timedelta,timezone
from jose import jwt,JWTError
from passlib.context import CryptContext
from fastapi import Depends,HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import JWT_SECRET
from .database import get_db
from .models import User
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
oauth=OAuth2PasswordBearer(tokenUrl="/api/auth/login")
def hash_password(p): return pwd.hash(p)
def verify_password(p,h): return pwd.verify(p,h)
def token_for(user):
    now=datetime.now(timezone.utc)
    return jwt.encode({"sub":str(user.id),"role":user.role,"exp":now+timedelta(hours=1)},JWT_SECRET,algorithm="HS256")
def current_user(token:str=Depends(oauth),db:Session=Depends(get_db)):
    try: uid=int(jwt.decode(token,JWT_SECRET,algorithms=["HS256"])["sub"])
    except (JWTError,ValueError,KeyError): raise HTTPException(401,"Invalid or expired token")
    user=db.get(User,uid)
    if not user: raise HTTPException(401,"User not found")
    return user
