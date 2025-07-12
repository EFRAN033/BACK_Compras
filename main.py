from fastapi import FastAPI, HTTPException, status, Depends, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from typing import Optional, List, Dict, Any
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Asegúrate de que database.py y config.py estén en el mismo directorio o accesibles
from database import get_db_connection
from config import settings

# Importa la función del chatbot de proveedores
from chatbot_proveedor import responder_chatbot_proveedor # <-- Importación correcta

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# Configurar CORS
origins = [
    "http://localhost:8080", # Tu frontend Vue si lo ejecutas con Vite/Vue CLI development server
    "http://localhost:5173", # Otro puerto común para Vite/Vue CLI
    # Agrega aquí la URL de tu frontend en producción (ej. "https://tu-app-frontend.com")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Permite todos los métodos (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"], # Permite todos los headers, incluyendo Content-Type y Authorization
)

# Para hash de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- Configuración de JWT ---
SECRET_KEY = settings.JWT_SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # Token expira en 24 horas

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Dependencia para obtener el usuario actual desde el token (Afiliado) ---
async def get_current_afiliado(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales de afiliado",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token: str = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise credentials_exception

    token = token.split(" ")[1] # Extrae el token "real"

    conn = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception

        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para obtener afiliado actual.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM afiliados WHERE email_corporativo = %s;", (email,))
        afiliado_data = cursor.fetchone()
        cursor.close()

        if afiliado_data is None:
            raise credentials_exception

        if not afiliado_data.get("activo"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tu cuenta de afiliado está inactiva."
            )

        return afiliado_data # Devuelve el diccionario con los datos del afiliado
    except JWTError as e:
        logger.error(f"Error de JWT al validar token de afiliado: {e}", exc_info=True)
        raise credentials_exception
    except Exception as e:
        logger.error(f"Error inesperado al obtener afiliado actual: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor al autenticar afiliado."
        )
    finally:
        if conn:
            conn.close()

# --- Dependencia para obtener el proveedor actual desde el token ---
async def get_current_proveedor(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales del proveedor",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_header: str = request.headers.get("Authorization")
    
    # --- Depurador en el Backend: Token Inicial del Header ---
    if token_header:
        logger.info(f"DEBUG: Encabezado Authorization recibido: '{token_header}'")
        if not token_header.startswith("Bearer "):
            logger.warning("DEBUG: El encabezado Authorization no empieza con 'Bearer '.")
            raise credentials_exception
        token = token_header.split(" ")[1] # Extrae el token "real"
        logger.info(f"DEBUG: Token extraído (primeros 20 chars): '{token[:20]}...'")
        logger.info(f"DEBUG: Longitud del token extraído: {len(token)}")
    else:
        logger.warning("DEBUG: Encabezado Authorization ausente en la solicitud.")
        raise credentials_exception

    conn = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            logger.warning("DEBUG: Payload del token no contiene 'sub' (email).")
            raise credentials_exception

        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para obtener proveedor actual.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM proveedores WHERE email_contacto = %s;", (email,))
        proveedor_data = cursor.fetchone()
        cursor.close()

        if proveedor_data is None:
            logger.warning(f"DEBUG: Proveedor con email '{email}' no encontrado en la DB.")
            raise credentials_exception

        if not proveedor_data.get("activo"):
            logger.warning(f"DEBUG: Cuenta de proveedor '{email}' inactiva.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tu cuenta de proveedor está inactiva. Contacta a soporte."
            )
        # Comentado temporalmente para permitir que el chatbot funcione incluso si no está verificado.
        # Puedes descomentar esta validación si quieres restringir el acceso al chatbot solo a proveedores verificados.
        # if proveedor_data.get("estado_verificacion") != "verificado":
        #     logger.warning(f"DEBUG: Cuenta de proveedor '{email}' no verificada. Estado: {proveedor_data.get('estado_verificacion')}")
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Tu cuenta de proveedor aún no ha sido verificada. Estado actual: " + str(proveedor_data.get("estado_verificacion"))
        #     )
        
        logger.info(f"DEBUG: Autenticación de proveedor '{email}' exitosa.")
        return proveedor_data # Devuelve el diccionario con los datos del proveedor
    except JWTError as e:
        logger.error(f"ERROR: Error de JWT al validar token de proveedor: {e}", exc_info=True)
        raise credentials_exception
    except Exception as e:
        logger.error(f"ERROR: Error inesperado al obtener proveedor actual: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor al autenticar proveedor."
        )
    finally:
        if conn:
            conn.close()


## Modelos Pydantic (Afiliados)
class AfiliadoRegistro(BaseModel):
    nombres: str
    apellidos: str
    email_corporativo: EmailStr
    telefono_contacto: str
    puesto_cargo: str
    razon_social_empresa: str
    rfc_empresa: str
    industria_sector: str
    tamano_empresa: str
    contrasena: str

class AfiliadoLogin(BaseModel):
    email: EmailStr
    password: str

class AfiliadoResponse(BaseModel):
    id: int
    nombres: str
    apellidos: str
    email_corporativo: EmailStr
    telefono_contacto: Optional[str] = None
    puesto_cargo: Optional[str] = None
    razon_social_empresa: Optional[str] = None
    rfc_empresa: Optional[str] = None
    industria_sector: Optional[str] = None
    tamano_empresa: Optional[str] = None
    activo: bool
    fecha_creacion: Optional[datetime] = None
    fecha_actualizacion: Optional[datetime] = None

class AfiliadoUpdate(BaseModel):
    nombres: Optional[str] = None
    apellidos: Optional[str] = None
    email_corporativo: Optional[EmailStr] = None
    telefono_contacto: Optional[str] = None
    puesto_cargo: Optional[str] = None
    razon_social_empresa: Optional[str] = None
    rfc_empresa: Optional[str] = None
    industria_sector: Optional[str] = None
    tamano_empresa: Optional[str] = None
    activo: Optional[bool] = None


## Modelos Pydantic (Proveedores)
class ProveedorRegistro(BaseModel):
    empresa: str
    rfc: str
    anios: int
    categorias: List[str] 
    nombre: str
    puesto: str
    email: EmailStr
    telefono: str
    whatsapp: Optional[str] = None
    capacidad: str
    tiempo: str
    certificaciones: Optional[str] = None
    password: str

class ProveedorLogin(BaseModel):
    email: EmailStr
    password: str

class ProveedorResponse(BaseModel):
    id: int
    nombre_legal_empresa: str
    rfc_empresa: str
    anos_experiencia: int
    nombre_completo_contacto: str
    puesto_cargo_contacto: str
    email_contacto: EmailStr
    telefono_principal: str
    whatsapp: Optional[str] = None
    capacidad_produccion_mensual: str
    tiempo_entrega_promedio: str
    certificaciones_calidad: Optional[str] = None
    fecha_registro: Optional[datetime] = None
    ultima_sesion: Optional[datetime] = None
    estado_verificacion: str
    activo: bool

class ProveedorUpdate(BaseModel):
    nombre_legal_empresa: Optional[str] = None
    rfc_empresa: Optional[str] = None
    anos_experiencia: Optional[int] = None
    nombre_completo_contacto: Optional[str] = None
    puesto_cargo_contacto: Optional[str] = None
    email_contacto: Optional[EmailStr] = None
    telefono_principal: Optional[str] = None
    whatsapp: Optional[str] = None
    capacidad_produccion_mensual: Optional[str] = None
    tiempo_entrega_promedio: Optional[str] = None
    certificaciones_calidad: Optional[str] = None
    estado_verificacion: Optional[str] = None 
    activo: Optional[bool] = None

# --- Modelo para el mensaje del chatbot (¡CLAVE PARA EL 422!) ---
class ChatMessage(BaseModel):
    message: str # Este es el campo que tu frontend está enviando.

# --- Modelo para la respuesta de análisis de contrato (para el futuro) ---
class ClauseAnalysis(BaseModel):
    clauseType: str
    riskLevel: str
    suggestion: str

## Endpoints Generales
@app.get("/")
async def root():
    return {"message": "API de ProVeo funcionando"}


## Endpoints de Afiliados
@app.post("/afiliados/registro")
async def registrar_afiliado(afiliado: AfiliadoRegistro):
    logger.debug("Intentando registrar afiliado...")
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para registro.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        hashed_password = get_password_hash(afiliado.contrasena)
        logger.debug(f"Contraseña hasheada para {afiliado.email_corporativo}")

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO afiliados (
                nombres, apellidos, email_corporativo, telefono_contacto, puesto_cargo,
                razon_social_empresa, rfc_empresa, industria_sector, tamano_empresa,
                contrasena_hash, activo, fecha_creacion, fecha_actualizacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
            """,
            (
                afiliado.nombres, afiliado.apellidos, afiliado.email_corporativo,
                afiliado.telefono_contacto, afiliado.puesto_cargo,
                afiliado.razon_social_empresa, afiliado.rfc_empresa,
                afiliado.industria_sector, afiliado.tamano_empresa,
                hashed_password, True, datetime.utcnow(), datetime.utcnow()
            )
        )
        afiliado_id = cursor.fetchone()[0]
        conn.commit()
        logger.info(f"Afiliado registrado exitosamente con ID: {afiliado_id}")
        return {"message": "Afiliado registrado exitosamente", "id": afiliado_id}
    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        logger.error(f"Error de integridad al registrar afiliado: {e}")
        if "email_corporativo" in str(e) or "rfc_empresa" in str(e):
             raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El correo electrónico o RFC de la empresa ya están registrados."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al registrar afiliado: {e}"
        )
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error inesperado al registrar afiliado: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {e}"
        )
    finally:
        if conn:
            conn.close()
            logger.debug("Conexión de BD cerrada después del registro.")


@app.post("/afiliados/login")
async def login_afiliado(afiliado_login: AfiliadoLogin):
    logger.debug(f"Intento de login para afiliado: {afiliado_login.email}")
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para login.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        logger.debug(f"Consultando afiliado con email: {afiliado_login.email}")
        cursor.execute(
            "SELECT id, contrasena_hash, activo, nombres, apellidos, razon_social_empresa, email_corporativo FROM afiliados WHERE email_corporativo = %s;",
            (afiliado_login.email,)
        )
        afiliado_data = cursor.fetchone()
        cursor.close()
        logger.debug(f"Datos de afiliado obtenidos: {afiliado_data}")

        if not afiliado_data:
            logger.warning(f"Intento de login fallido: usuario {afiliado_login.email} no encontrado.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )

        hashed_password = afiliado_data["contrasena_hash"]
        activo = afiliado_data["activo"]

        logger.debug(f"Verificando contraseña para {afiliado_login.email}")
        if not verify_password(afiliado_login.password, hashed_password):
            logger.warning(f"Intento de login fallido: contraseña incorrecta para {afiliado_login.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )

        if not activo:
            logger.warning(f"Intento de login fallido: cuenta inactiva para {afiliado_login.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta inactiva. Por favor, contacta a soporte."
            )

        user_display_name = afiliado_data.get("razon_social_empresa") or f"{afiliado_data['nombres']} {afiliado_data['apellidos']}"
        logger.info(f"Login exitoso para afiliado: {user_display_name} (ID: {afiliado_data['id']})")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": afiliado_data["email_corporativo"]},
            expires_delta=access_token_expires
        )

        return {
            "message": "Inicio de sesión exitoso",
            "afiliado_id": afiliado_data["id"],
            "user_name": user_display_name,
            "token": access_token,
            "email": afiliado_data["email_corporativo"]
        }
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Error inesperado en /afiliados/login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {e}. Revisa logs del servidor."
        )
    finally:
        if conn:
            conn.close()
            logger.debug("Conexión de BD cerrada después del login.")

## Endpoints de Proveedores

@app.post("/proveedores/registro")
async def registrar_proveedor(proveedor: ProveedorRegistro):
    logger.debug("Intentando registrar proveedor...")
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para registro de proveedor.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        hashed_password = get_password_hash(proveedor.password)
        logger.debug(f"Contraseña hasheada para {proveedor.email}")

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO proveedores (
                nombre_legal_empresa,
                rfc_empresa,
                anos_experiencia,
                nombre_completo_contacto,
                puesto_cargo_contacto,
                email_contacto,
                telefono_principal,
                whatsapp,
                capacidad_produccion_mensual,
                tiempo_entrega_promedio,
                certificaciones_calidad,
                contrasena_hash,
                fecha_registro,
                ultima_sesion,
                estado_verificacion,
                activo
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING id;
            """,
            (
                proveedor.empresa,
                proveedor.rfc,
                proveedor.anios,
                proveedor.nombre,
                proveedor.puesto,
                proveedor.email,
                proveedor.telefono,
                proveedor.whatsapp,
                proveedor.capacidad,
                proveedor.tiempo,
                proveedor.certificaciones,
                hashed_password,
                datetime.utcnow(),          # fecha_registro
                None,                       # ultima_sesion
                'pendiente',                # estado_verificacion - Nuevo proveedor comienza como pendiente
                True                        # activo
            )
        )
        proveedor_id = cursor.fetchone()[0]

        # --- Manejo de Categorías ---
        if proveedor.categorias:
            for category_name in proveedor.categorias:
                cursor.execute("SELECT id FROM categorias_generales WHERE nombre_categoria = %s;", (category_name,))
                category_data = cursor.fetchone()
                if category_data:
                    category_id = category_data[0]
                    cursor.execute(
                        "INSERT INTO proveedores_categorias (id_proveedor, id_categoria) VALUES (%s, %s);",
                        (proveedor_id, category_id)
                    )
                else:
                    logger.warning(f"Categoría '{category_name}' no encontrada en la tabla 'categorias_generales'. No se pudo asociar.")

        conn.commit()
        logger.info(f"Proveedor registrado exitosamente con ID: {proveedor_id}")
        return {"message": "Proveedor registrado exitosamente", "id": proveedor_id}
    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        logger.error(f"Error de integridad al registrar proveedor: {e}", exc_info=True)
        if "email_contacto" in str(e):
             raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El correo electrónico de contacto ya está registrado para otro proveedor."
            )
        if "rfc_empresa" in str(e):
             raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El RFC de la empresa ya está registrado para otro proveedor."
            )
        if "nombre_legal_empresa" in str(e):
             raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El nombre legal de la empresa ya está registrado para otro proveedor."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al registrar proveedor: {e}"
        )
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error inesperado al registrar proveedor: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {e}"
        )
    finally:
        if conn:
            conn.close()
            logger.debug("Conexión de BD cerrada después del registro de proveedor.")


@app.post("/proveedores/login")
async def login_proveedor(proveedor_login: ProveedorLogin):
    logger.debug(f"Intento de login para proveedor: {proveedor_login.email}")
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para login de proveedor.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        logger.debug(f"Consultando proveedor con email: {proveedor_login.email}")
        cursor.execute(
            "SELECT id, contrasena_hash, activo, nombre_legal_empresa, email_contacto, estado_verificacion FROM proveedores WHERE email_contacto = %s;",
            (proveedor_login.email,)
        )
        proveedor_data = cursor.fetchone()
        cursor.close()
        logger.debug(f"Datos de proveedor obtenidos: {proveedor_data}")

        if not proveedor_data:
            logger.warning(f"Intento de login fallido: proveedor {proveedor_login.email} no encontrado.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )

        hashed_password = proveedor_data["contrasena_hash"]
        activo = proveedor_data["activo"]
        estado_verificacion = proveedor_data["estado_verificacion"]

        logger.debug(f"Verificando contraseña para {proveedor_login.email}")
        if not verify_password(proveedor_login.password, hashed_password):
            logger.warning(f"Intento de login fallido: contraseña incorrecta para {proveedor_login.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )

        if not activo:
            logger.warning(f"Intento de login fallido: cuenta inactiva para {proveedor_login.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta inactiva. Por favor, contacta a soporte."
            )
        
        if estado_verificacion != 'verificado':
            logger.warning(f"Intento de login fallido: cuenta de proveedor {proveedor_login.email} no verificada ({estado_verificacion}).")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Tu cuenta aún está en proceso de verificación ({estado_verificacion}). Por favor, espera la aprobación."
            )


        user_display_name = proveedor_data.get("nombre_legal_empresa")
        logger.info(f"Login exitoso para proveedor: {user_display_name} (ID: {proveedor_data['id']})")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": proveedor_data["email_contacto"]}, # 'sub' should be unique identifier like email
            expires_delta=access_token_expires
        )

        return {
            "message": "Inicio de sesión exitoso",
            "proveedor_id": proveedor_data["id"],
            "user_name": user_display_name, # Use nombre_legal_empresa for display
            "token": access_token,
            "email": proveedor_data["email_contacto"]
        }
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Error inesperado en /proveedores/login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {e}. Revisa logs del servidor."
        )
    finally:
        if conn:
            conn.close()
            logger.debug("Conexión de BD cerrada después del login de proveedor.")


## Endpoints para el Perfil del Afiliado
@app.get("/afiliados/me", response_model=AfiliadoResponse)
async def read_afiliado_me(current_afiliado: dict = Depends(get_current_afiliado)):
    """
    Recupera la información del perfil del afiliado autenticado.
    """
    return current_afiliado

@app.patch("/afiliados/me", response_model=AfiliadoResponse)
async def update_afiliado_me(
    afiliado_update: AfiliadoUpdate,
    current_afiliado: dict = Depends(get_current_afiliado)
):
    """
    Actualiza la información del perfil del afiliado autenticado.
    """
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para actualización de perfil.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        cursor = conn.cursor(cursor_factory=RealDictCursor)

        update_fields = []
        update_values = []

        for field, value in afiliado_update.model_dump(exclude_unset=True).items():
            update_fields.append(f"{field} = %s")
            update_values.append(value)

        if not update_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se proporcionaron datos para actualizar."
            )

        update_fields.append("fecha_actualizacion = %s")
        update_values.append(datetime.utcnow())

        update_values.append(current_afiliado["id"])

        query = f"""
            UPDATE afiliados
            SET {", ".join(update_fields)}
            WHERE id = %s
            RETURNING *;
        """

        logger.debug(f"Ejecutando consulta de actualización: {query} con valores: {update_values}")
        cursor.execute(query, tuple(update_values))

        updated_afiliado_data = cursor.fetchone()
        conn.commit()
        cursor.close()

        if not updated_afiliado_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Perfil no encontrado o no se pudo actualizar."
            )

        logger.info(f"Perfil de afiliado {current_afiliado['id']} actualizado exitosamente.")
        return updated_afiliado_data

    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        logger.error(f"Error de integridad al actualizar perfil: {e}", exc_info=True)
        if "email_corporativo" in str(e) or "rfc_empresa" in str(e):
             raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El correo electrónico o RFC de la empresa ya están registrados por otro usuario."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al actualizar perfil: {e}"
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error inesperado al actualizar perfil: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor al actualizar el perfil: {e}"
        )
    finally:
        if conn:
            conn.close()


## Nuevos Endpoints para el Perfil del Proveedor
@app.get("/proveedores/me", response_model=ProveedorResponse)
async def read_proveedor_me(current_proveedor: dict = Depends(get_current_proveedor)):
    """
    Recupera la información del perfil del proveedor autenticado.
    """
    return current_proveedor

@app.patch("/proveedores/me", response_model=ProveedorResponse)
async def update_proveedor_me(
    proveedor_update: ProveedorUpdate,
    current_proveedor: dict = Depends(get_current_proveedor)
):
    """
    Actualiza la información del perfil del proveedor autenticado.
    """
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("No se pudo establecer conexión con la base de datos para actualización de perfil de proveedor.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al conectar con la base de datos"
            )

        cursor = conn.cursor(cursor_factory=RealDictCursor)

        update_fields = []
        update_values = []

        for field, value in proveedor_update.model_dump(exclude_unset=True).items():
            update_fields.append(f"{field} = %s")
            update_values.append(value)

        if not update_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se proporcionaron datos para actualizar."
            )

        update_fields.append("ultima_sesion = %s")
        update_values.append(datetime.utcnow())

        update_values.append(current_proveedor["id"])

        query = f"""
            UPDATE proveedores
            SET {", ".join(update_fields)}
            WHERE id = %s
            RETURNING *;
        """

        logger.debug(f"Ejecutando consulta de actualización de proveedor: {query} con valores: {update_values}")
        cursor.execute(query, tuple(update_values))

        updated_proveedor_data = cursor.fetchone()
        conn.commit()
        cursor.close()

        if not updated_proveedor_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Perfil de proveedor no encontrado o no se pudo actualizar."
            )

        logger.info(f"Perfil de proveedor {current_proveedor['id']} actualizado exitosamente.")
        return updated_proveedor_data

    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        logger.error(f"Error de integridad al actualizar perfil de proveedor: {e}", exc_info=True)
        if "email_contacto" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El correo electrónico de contacto ya está registrado para otro proveedor."
            )
        if "rfc_empresa" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El RFC de la empresa ya está registrado para otro proveedor."
            )
        if "nombre_legal_empresa" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El nombre legal de la empresa ya está registrado para otro proveedor."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al actualizar perfil: {e}"
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error inesperado al actualizar perfil de proveedor: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor al actualizar el perfil: {e}"
        )
    finally:
        if conn:
            conn.close()


## Endpoints del Chatbot


@app.post("/chatbot/proveedor/ask")
async def ask_chatbot_proveedor(
    chat_message: ChatMessage, # <-- ¡Aquí se recibe el JSON con el campo 'message'!
    current_proveedor: Dict[str, Any] = Depends(get_current_proveedor) # El decorador ya devuelve el diccionario completo del proveedor
):
    """
    Endpoint para que los proveedores interactúen con el chatbot.
    Recibe un mensaje de texto y devuelve una respuesta generada por el chatbot.
    """
    try:
        # Extraemos el email del proveedor autenticado desde el diccionario 'current_proveedor'
        proveedor_email = current_proveedor.get("email_contacto")
        
        if not proveedor_email:
            logger.error(f"No se pudo obtener el email del proveedor desde el token para el chatbot. Proveedor_data: {current_proveedor}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se pudo identificar tu cuenta de proveedor."
            )

        # Pasamos el texto del mensaje (chat_message.message) y el email del proveedor a la función del chatbot
        response_text = responder_chatbot_proveedor(chat_message.message, proveedor_email)
        
        logger.info(f"Chatbot response for '{proveedor_email}': '{response_text}'")
        return {"response": response_text}
    except HTTPException as http_exc:
        raise http_exc # Re-lanza las HTTPException directamente
    except Exception as e:
        logger.error(f"Error en el endpoint /chatbot/proveedor/ask: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor al procesar la solicitud del chatbot: {e}"
        )

# --- Endpoint para el análisis de contratos (ejemplo, necesita implementación) ---
@app.post("/api/analyze-contract")
async def analyze_contract(
    contract_file: UploadFile = File(...),
    language: str = Form("es"), # Opcional, si quieres especificar el idioma del contrato
    current_proveedor: Dict[str, Any] = Depends(get_current_proveedor)
):
    """
    Endpoint para que los proveedores suban un contrato y el chatbot lo analice.
    """
    if not contract_file.filename.endswith(('.pdf', '.doc', '.docx', '.txt')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no soportado. Por favor, sube PDF, DOC, DOCX o TXT."
        )

    # Aquí iría la lógica para leer y analizar el archivo.
    # Por ejemplo, podrías leer el contenido:
    # content = await contract_file.read()
    # Y luego pasarlo a una función de análisis (similar a responder_chatbot_proveedor)
    # analysis_results = perform_contract_analysis(content, language, current_proveedor.get("email_contacto"))

    # Placeholder de respuesta (debes reemplazarlo con tu lógica real de análisis)
    # El frontend espera una lista de objetos con 'clauseType', 'riskLevel', 'suggestion'
    mock_analysis_results = [
        {"clauseType": "Cláusula de Pago", "riskLevel": "Medio", "suggestion": "Revisar términos de pago y plazos de facturación."},
        {"clauseType": "Cláusula de Terminación", "riskLevel": "Bajo", "suggestion": "Condiciones de terminación estándar, sin riesgos evidentes."},
        {"clauseType": "Exclusión de Responsabilidad", "riskLevel": "Alto", "suggestion": "Esta cláusula limita severamente tus derechos. Consulta con un abogado."},
        {"clauseType": "Jurisdicción y Ley Aplicable", "riskLevel": "Bajo", "suggestion": "Se establece la jurisdicción local, lo cual es favorable."},
        {"clauseType": "Confidencialidad", "riskLevel": "Medio", "suggestion": "Asegúrate de entender qué información es confidencial y por cuánto tiempo."}
    ]

    logger.info(f"Análisis de contrato simulado para {current_proveedor.get('email_contacto')} - Archivo: {contract_file.filename}")
    return mock_analysis_results