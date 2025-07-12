# dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from .database import get_db
from . import schemas, crud, models # Importa tus esquemas, crud y modelos

# Asegúrate de que esta clave secreta sea la misma que usas para generar tus tokens
SECRET_KEY = "tu_super_secreto_jwt" # ¡Cambia esto por una clave fuerte en producción!
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Endpoint para obtener el token

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email) # Si tienes un TokenData en schemas.py
    except JWTError:
        raise credentials_exception
    
    user = crud.get_afiliado_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user