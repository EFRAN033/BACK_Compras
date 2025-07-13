# main.py

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import json

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
# Importamos enum desde Python, no desde models, para los modelos Pydantic
from enum import Enum as PyEnum 

import secrets
from dotenv import load_dotenv

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from decimal import Decimal
from datetime import date

# Importar modelos y base de datos desde tus archivos locales
import models
from database import SessionLocal, engine

# Importar los ENUMs específicos de SQLAlchemy desde models
from models import Administrador, SolicitudProveedor, Categoria, Cliente, Notificacion, ProductoProveedor, \
    EstadoSolicitudEnum, ProductStatusEnumDB, UnitOfMeasureEnumDB


from fastapi.staticfiles import StaticFiles

load_dotenv()

# --- INSTANCIA Y CONFIGURACIÓN DE FASTAPI ---
app = FastAPI(title="ProVeo API", version="1.0.0")

# MONTAR EL DIRECTORIO ESTÁTICO PARA IMÁGENES
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- CONFIGURACIÓN DE CORS ---
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://localhost:8000")

origins = [
    FRONTEND_URL,
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Asegurarse de que las tablas existan
models.Base.metadata.create_all(bind=engine)

# --- CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = os.getenv("SECRET_KEY", "tu_super_secreto_para_jwt_en_dev")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# --- CONFIGURACIÓN DE CORREO ELECTRÓNICO ---
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

# --- MODELOS DE DATOS (PYDANTIC) ---
class ClienteUpdate(BaseModel):
    nombres: Optional[str] = None
    apellidos: Optional[str] = None
    email_corporativo: Optional[EmailStr] = None
    telefono_contacto: Optional[str] = None
    puesto_cargo: Optional[str] = None
    razon_social_empresa: Optional[str] = None
    industria_sector: Optional[str] = None
    tamano_empresa: Optional[str] = None

class ClienteCreate(BaseModel):
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

class Cliente(BaseModel):
    id: int
    nombres: str
    apellidos: str
    email_corporativo: EmailStr
    telefono_contacto: str
    puesto_cargo: str
    razon_social_empresa: str
    rfc_empresa: str
    industria_sector: str
    tamano_empresa: str
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    token: str
    user_name: str
    user_role: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SolicitudProveedorCreate(BaseModel):
    empresa: str
    rfc: str
    anios: int
    categorias: List[str]
    nombre: str
    puesto: str
    email: str
    telefono: str
    whatsapp: Optional[str] = None
    capacidad: str
    tiempo: str
    certificaciones: Optional[str] = None

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str

class AdminUser(BaseModel):
    id: int
    email: EmailStr
    nombre: str
    apellido: str

    class Config:
        from_attributes = True

class SolicitudProveedorResponse(BaseModel):
    id: int
    nombre_empresa: str
    rfc: str
    anios_experiencia: int
    nombre_contacto: str
    puesto_contacto: str
    email_contacto: EmailStr
    telefono_principal: str
    whatsapp: Optional[str] = None
    capacidad_mensual: str
    tiempo_entrega: str
    certificaciones: Optional[str] = None
    estado: str
    fecha_solicitud: datetime
    categorias: List[dict]

    class Config:
        from_attributes = True

# --- Modelos Pydantic para Productos ---
# Usamos PyEnum (el Enum de Python) para los modelos Pydantic
class ProductStatusEnum(PyEnum):
    activo = "Activo"
    inactivo = "Inactivo"
    borrador = "Borrador"

class UnitOfMeasureEnum(PyEnum):
    unidad = "Unidad"
    caja = "Caja"
    paquete = "Paquete"
    kg = "Kg"
    ltr = "Ltr"
    docena = "Docena"
    bulto = "Bulto"
    palet = "Palet"
    servicio = "Servicio"
    licencia = "Licencia"
    suscripcion = "Suscripcion"

class PrecioPorVolumen(BaseModel):
    min_quantity: int
    max_quantity: Optional[int] = None
    price: Decimal

class ProductoProveedorBase(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    precio: Decimal
    stock: int
    categoria_id: str
    image_url: Optional[str] = None
    sku: Optional[str] = None
    estado: ProductStatusEnum = ProductStatusEnum.borrador
    unidad_medida: UnitOfMeasureEnum = UnitOfMeasureEnum.unidad
    cantidad_minima_pedido: int = 1
    precios_por_volumen: Optional[List[PrecioPorVolumen]] = []
    peso_kg: Optional[Decimal] = None
    dimension_largo_cm: Optional[Decimal] = None
    dimension_ancho_cm: Optional[Decimal] = None
    dimension_alto_cm: Optional[Decimal] = None
    codigo_barras: Optional[str] = None
    fecha_caducidad: Optional[date] = None
    tiempo_procesamiento_dias: Optional[int] = None

class ProductoProveedorCreate(ProductoProveedorBase):
    pass

class ProductoProveedorUpdate(ProductoProveedorBase):
    nombre: Optional[str] = None
    precio: Optional[Decimal] = None
    stock: Optional[int] = None
    categoria_id: Optional[str] = None
    estado: Optional[ProductStatusEnum] = None
    unidad_medida: Optional[UnitOfMeasureEnum] = None
    cantidad_minima_pedido: Optional[int] = None

class ProductoProveedorResponse(ProductoProveedorBase):
    id: int
    proveedor_id: int
    fecha_creacion: datetime
    fecha_actualizacion: datetime
    precios_por_volumen: List[PrecioPorVolumen] = []

    class Config:
        from_attributes = True
        json_encoders = {
            date: lambda v: v.isoformat() if v else None,
            datetime: lambda v: v.isoformat() if v else None,
            Decimal: lambda v: float(v)
        }

# Modelo Pydantic para los detalles del proveedor a incluir en la respuesta del producto
class ProveedorDetalleProducto(BaseModel):
    id: int
    nombre_empresa: str
    email_contacto: EmailStr
    telefono_principal: str

    class Config:
        from_attributes = True

# Modelo de respuesta detallada del producto que incluye los datos del proveedor
class ProductoProveedorResponseDetallada(ProductoProveedorBase):
    id: int
    proveedor_id: int
    fecha_creacion: datetime
    fecha_actualizacion: datetime
    precios_por_volumen: List[PrecioPorVolumen] = []
    proveedor: Optional[ProveedorDetalleProducto] = None

    class Config:
        from_attributes = True
        json_encoders = {
            date: lambda v: v.isoformat() if v else None,
            datetime: lambda v: v.isoformat() if v else None,
            Decimal: lambda v: float(v)
        }

# --- MODELO PYDANTIC para Categoría (Respuesta) ---
class CategoriaResponse(BaseModel):
    id: str
    nombre: str

    class Config:
        from_attributes = True

# --- NUEVOS MODELOS PYDANTIC PARA NOTIFICACIONES ---
class NotificacionCreate(BaseModel):
    producto_id: int
    cantidad_deseada: int

class NotificacionResponse(BaseModel):
    id: int
    proveedor_id: int
    tipo: str
    asunto: str
    cuerpo: str
    datos_extra: Optional[str] = None
    leida: bool
    fecha_creacion: datetime

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
        }

# --- Chatbot specific Pydantic models ---
class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    analysisData: Optional[List[dict]] = None # Updated to list of dict for analysis data

# --- UTILIDADES DE SEGURIDAD ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/proveedores/login") # Adjusted tokenUrl

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- DEPENDENCIAS ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper dependency to get the authenticated user with a specific role
def get_current_user_with_role(required_role: str):
    def _get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudieron validar las credenciales",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            user_role: str = payload.get("role")

            if email is None or user_role is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception
        
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No tiene permisos para acceder a este recurso. Rol requerido: '{required_role}', Rol del usuario: '{user_role}'",
            )

        if user_role == "admin":
            user = db.query(Administrador).filter(Administrador.email == email).first()
        elif user_role == "afiliado":
            user = db.query(models.Cliente).filter(models.Cliente.email_corporativo == email).first()
        elif user_role == "proveedor":
            user = db.query(models.SolicitudProveedor).filter(
                models.SolicitudProveedor.email_contacto == email,
                models.SolicitudProveedor.estado == EstadoSolicitudEnum.aprobado
            ).first()
        else:
            user = None

        if user is None:
            raise credentials_exception
        return user
    return _get_current_user

# New dependency to get the supplier ID from the authenticated supplier's token
def get_current_supplier_id(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales del proveedor.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_role: str = payload.get("role")

        if email is None or user_role != "proveedor":
            raise credentials_exception
        
        supplier = db.query(SolicitudProveedor).filter(
            SolicitudProveedor.email_contacto == email,
            SolicitudProveedor.estado == EstadoSolicitudEnum.aprobado
        ).first()
        if supplier is None:
            raise credentials_exception
        return supplier.id
    except JWTError:
        raise credentials_exception

# --- RUTAS (ENDPOINTS) ---

@app.post("/afiliados/registro", response_model=Cliente, status_code=status.HTTP_201_CREATED, tags=["Clientes"])
def registrar_cliente(cliente: ClienteCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(cliente.contrasena)
    db_cliente = models.Cliente(**cliente.dict(exclude={"contrasena"}), contrasena_hash=hashed_password)
    try:
        db.add(db_cliente)
        db.commit()
        db.refresh(db_cliente)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El correo electrónico o el RFC ya están registrados.")
    return db_cliente

@app.post("/afiliados/login", response_model=Token, tags=["Clientes"])
def login_cliente(form_data: LoginRequest, db: Session = Depends(get_db)):
    cliente_db = db.query(models.Cliente).filter(models.Cliente.email_corporativo == form_data.email).first()
    if not cliente_db or not verify_password(form_data.password, cliente_db.contrasena_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo electrónico o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": cliente_db.email_corporativo, "role": "afiliado"})
    return {"token": access_token, "user_name": cliente_db.nombres, "user_role": "afiliado"}

@app.get("/afiliados/me", response_model=Cliente, tags=["Clientes"])
def read_users_me(current_user: models.Cliente = Depends(get_current_user_with_role("afiliado"))):
    return current_user

@app.patch("/afiliados/me", response_model=Cliente, tags=["Clientes"])
def update_user_me(user_update: ClienteUpdate, db: Session = Depends(get_db), current_user: models.Cliente = Depends(get_current_user_with_role("afiliado"))):
    update_data = user_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(current_user, key, value)
    try:
        db.add(current_user)
        db.commit()
        db.refresh(current_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El correo electrónico ya está en uso por otra cuenta.")
    return current_user 


@app.post("/proveedores/registro", status_code=status.HTTP_201_CREATED, tags=["Proveedores"])
def registrar_solicitud_proveedor(solicitud: SolicitudProveedorCreate, db: Session = Depends(get_db)):
    categorias_db = db.query(models.Categoria).filter(models.Categoria.id.in_(solicitud.categorias)).all()
    if len(categorias_db) != len(solicitud.categorias):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Una o más categorías enviadas no son válidas.")
    
    db_solicitud = models.SolicitudProveedor(
        nombre_empresa=solicitud.empresa,
        rfc=solicitud.rfc,
        anios_experiencia=solicitud.anios,
        nombre_contacto=solicitud.nombre,
        puesto_contacto=solicitud.puesto,
        email_contacto=solicitud.email,
        telefono_principal=solicitud.telefono,
        whatsapp=solicitud.whatsapp,
        capacidad_mensual=solicitud.capacidad,
        tiempo_entrega=solicitud.tiempo,
        certificaciones=solicitud.certificaciones,
        estado=EstadoSolicitudEnum.pendiente # Use the Enum here
    )
    
    for categoria_db in categorias_db:
        db_solicitud.categorias_asociadas.append(categoria_db)

    try:
        db.add(db_solicitud)
        db.commit()
        db.refresh(db_solicitud)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El RFC o el email de contacto ya han sido registrados en una solicitud previa.")
    
    return {"message": "Solicitud de registro enviada con éxito. Nuestro equipo la revisará pronto."}

@app.post("/proveedores/login", response_model=Token, tags=["Proveedores"])
def login_proveedor(form_data: LoginRequest, db: Session = Depends(get_db)):
    proveedor_db = db.query(models.SolicitudProveedor).filter(
        models.SolicitudProveedor.email_contacto == form_data.email,
        models.SolicitudProveedor.estado == EstadoSolicitudEnum.aprobado # Use the Enum here
    ).first()

    if not proveedor_db or (proveedor_db.contrasena_hash is None or not verify_password(form_data.password, proveedor_db.contrasena_hash)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de proveedor incorrectas o cuenta no aprobada",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": proveedor_db.email_contacto, "role": "proveedor"})
    
    return {
        "token": access_token,
        "user_name": proveedor_db.nombre_contacto,
        "user_role": "proveedor"
    }

@app.post("/proveedores/productos", response_model=ProductoProveedorResponse, status_code=status.HTTP_201_CREATED, tags=["Proveedores", "Productos"])
async def create_product_for_supplier(
    product: ProductoProveedorCreate,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    categoria_exists = db.query(models.Categoria).filter(models.Categoria.id == product.categoria_id).first()
    if not categoria_exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"La categoría '{product.categoria_id}' no existe."
        )

    # Convertir lista de Pydantic PrecioPorVolumen a JSON string para DB
    precios_por_volumen_json = json.dumps([p.model_dump() for p in product.precios_por_volumen]) if product.precios_por_volumen else "[]"

    db_product = models.ProductoProveedor(
        proveedor_id=current_supplier.id,
        nombre=product.nombre,
        descripcion=product.descripcion,
        precio=product.precio,
        stock=product.stock,
        categoria_id=product.categoria_id,
        image_url=product.image_url,
        sku=product.sku,
        estado=ProductStatusEnumDB[product.estado.name], # Map Pydantic Enum to DB Enum
        unidad_medida=UnitOfMeasureEnumDB[product.unidad_medida.name], # Map Pydantic Enum to DB Enum
        cantidad_minima_pedido=product.cantidad_minima_pedido,
        precios_por_volumen=precios_por_volumen_json,
        peso_kg=product.peso_kg,
        dimension_largo_cm=product.dimension_largo_cm,
        dimension_ancho_cm=product.dimension_ancho_cm,
        dimension_alto_cm=product.dimension_alto_cm,
        codigo_barras=product.codigo_barras,
        fecha_caducidad=product.fecha_caducidad,
        tiempo_procesamiento_dias=product.tiempo_procesamiento_dias
    )
    
    try:
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        # Asegurarse de que precios_por_volumen se deserialice para la respuesta
        db_product.precios_por_volumen = json.loads(db_product.precios_por_volumen) if isinstance(db_product.precios_por_volumen, str) else db_product.precios_por_volumen
        return db_product
    except IntegrityError as e:
        db.rollback()
        if "sku" in str(e).lower():
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ya existe un producto con el SKU proporcionado.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error al crear el producto: {e.orig.pgerror}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error inesperado al crear el producto: {str(e)}")

@app.get("/proveedores/productos", response_model=List[ProductoProveedorResponse], tags=["Proveedores", "Productos"])
async def get_supplier_products(
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    products = db.query(models.ProductoProveedor).filter(
        models.ProductoProveedor.proveedor_id == current_supplier.id
    ).all()
    
    for product in products:
        product.precios_por_volumen = json.loads(product.precios_por_volumen) if isinstance(product.precios_por_volumen, str) else product.precios_por_volumen
    
    return products

@app.get("/proveedores/productos/{product_id}", response_model=ProductoProveedorResponse, tags=["Proveedores", "Productos"])
async def get_supplier_product_by_id(
    product_id: int,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    product = db.query(models.ProductoProveedor).filter(
        models.ProductoProveedor.id == product_id,
        models.ProductoProveedor.proveedor_id == current_supplier.id
    ).first()
    
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Producto no encontrado o no pertenece a este proveedor.")
    
    product.precios_por_volumen = json.loads(product.precios_por_volumen) if isinstance(product.precios_por_volumen, str) else product.precios_por_volumen
    
    return product

@app.put("/proveedores/productos/{product_id}", response_model=ProductoProveedorResponse, tags=["Proveedores", "Productos"])
async def update_supplier_product(
    product_id: int,
    product_update: ProductoProveedorUpdate,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    db_product = db.query(models.ProductoProveedor).filter(
        models.ProductoProveedor.id == product_id,
        models.ProductoProveedor.proveedor_id == current_supplier.id
    ).first()

    if not db_product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Producto no encontrado o no pertenece a este proveedor.")

    update_data = product_update.model_dump(exclude_unset=True) # Use model_dump for Pydantic v2

    if "categoria_id" in update_data:
        categoria_exists = db.query(models.Categoria).filter(models.Categoria.id == update_data["categoria_id"]).first()
        if not categoria_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"La categoría '{update_data['categoria_id']}' no existe."
            )

    if "precios_por_volumen" in update_data:
        update_data["precios_por_volumen"] = json.dumps([p.model_dump() for p in update_data["precios_por_volumen"]])
    
    if "estado" in update_data:
        # Convert Pydantic Enum to SQLAlchemy Enum value
        update_data["estado"] = ProductStatusEnumDB[update_data["estado"].name]
    if "unidad_medida" in update_data:
        # Convert Pydantic Enum to SQLAlchemy Enum value
        update_data["unidad_medida"] = UnitOfMeasureEnumDB[update_data["unidad_medida"].name]

    for key, value in update_data.items():
        setattr(db_product, key, value)
    
    db_product.fecha_actualizacion = datetime.now(timezone.utc) # Manually update timestamp

    try:
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        db_product.precios_por_volumen = json.loads(db_product.precios_por_volumen) if isinstance(db_product.precios_por_volumen, str) else db_product.precios_por_volumen
        return db_product
    except IntegrityError as e:
        db.rollback()
        if "sku" in str(e).lower():
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ya existe un producto con el SKU proporcionado.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error al actualizar el producto: {e.orig.pgerror}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error inesperado al actualizar el producto: {str(e)}")

# --- FIN DE ENDPOINTS DE GESTIÓN DE PRODUCTOS PARA PROVEEDORES ---

# --- NUEVO ENDPOINT PARA SUBIR IMÁGENES ---
@app.post("/upload-image", tags=["General", "Imágenes"])
async def upload_image(file: UploadFile = File(...)):
    """
    Sube un archivo de imagen y lo guarda en el directorio estático.
    Retorna la URL accesible de la imagen.
    """
    upload_dir = "static/images"
    os.makedirs(upload_dir, exist_ok=True)

    file_extension = file.filename.split(".")[-1]
    unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(8)}.{file_extension}"
    file_location = os.path.join(upload_dir, unique_filename)

    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(await file.read())
        
        # Usa la variable de entorno BACKEND_BASE_URL
        image_url = f"{BACKEND_BASE_URL}/static/images/{unique_filename}"
        return {"imageUrl": image_url}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al subir la imagen: {str(e)}")

# Endpoint público para obtener productos por ID, ahora devuelve ProductoProveedorResponseDetallada
@app.get("/productos/{product_id}", response_model=ProductoProveedorResponseDetallada, tags=["Productos Públicos"])
async def get_product_by_id(
    product_id: int,
    db: Session = Depends(get_db)
):
    """
    Obtiene los detalles de un producto específico por su ID, incluyendo información del proveedor.
    Solo retorna productos con estado 'Activo'.
    """
    product = db.query(models.ProductoProveedor).options(
        joinedload(models.ProductoProveedor.proveedor)
    ).filter(
        models.ProductoProveedor.id == product_id,
        models.ProductoProveedor.estado == ProductStatusEnumDB.Activo # Use the Enum here
    ).first()

    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Producto no encontrado o no disponible.")
    
    product.precios_por_volumen = json.loads(product.precios_por_volumen) if isinstance(product.precios_por_volumen, str) else product.precios_por_volumen
    
    return product

@app.get("/productos", response_model=List[ProductoProveedorResponse], tags=["Productos Públicos"], summary="Obtener todos los productos activos")
async def get_all_products(
    categoria_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Obtiene una lista de todos los productos disponibles, opcionalmente filtrados por categoría.
    Solo retorna productos con estado 'Activo'.
    """
    query = db.query(models.ProductoProveedor).filter(models.ProductoProveedor.estado == ProductStatusEnumDB.Activo) # Use the Enum here
    
    if categoria_id:
        query = query.filter(models.ProductoProveedor.categoria_id == categoria_id)
        
    products = query.all()
    
    for product in products:
        product.precios_por_volumen = json.loads(product.precios_por_volumen) if isinstance(product.precios_por_volumen, str) else product.precios_por_volumen
    
    return products


# --- ENDPOINTS PARA NOTIFICACIONES ---

@app.post("/notificaciones/solicitar-inventario", status_code=status.HTTP_202_ACCEPTED, tags=["Notificaciones", "Clientes"])
async def solicitar_llenado_inventario(
    request_data: NotificacionCreate,
    db: Session = Depends(get_db),
    current_client: models.Cliente = Depends(get_current_user_with_role("afiliado"))
):
    producto = db.query(models.ProductoProveedor).filter(models.ProductoProveedor.id == request_data.producto_id).first()
    if not producto:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Producto no encontrado.")

    asunto_notificacion = f"Solicitud de Inventario: '{producto.nombre}' de {current_client.razon_social_empresa}"
    cuerpo_notificacion = (
        f"El cliente '{current_client.razon_social_empresa}' (ID: {current_client.id}) "
        f"ha solicitado reponer el inventario del producto '{producto.nombre}' (SKU: {producto.sku}). "
        f"Cantidad deseada: {request_data.cantidad_deseada} {producto.unidad_medida.value}. " # Use .value for Enum
        "Por favor, revisa tu gestión de productos para actualizar el stock."
    )
    
    datos_extra = json.dumps({
        "product_id": producto.id,
        "product_name": producto.nombre,
        "client_id": current_client.id,
        "client_name": current_client.razon_social_empresa,
        "requested_quantity": request_data.cantidad_deseada,
    })

    notificacion = models.Notificacion(
        proveedor_id=producto.proveedor_id,
        tipo="solicitud_inventario",
        asunto=asunto_notificacion,
        cuerpo=cuerpo_notificacion,
        datos_extra=datos_extra,
        leida=False,
    )

    try:
        db.add(notificacion)
        db.commit()
        db.refresh(notificacion)
        return {"message": "Solicitud de llenado de inventario enviada al proveedor.", "notification_id": notificacion.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al enviar la notificación: {str(e)}")

@app.get("/proveedores/notificaciones", response_model=List[NotificacionResponse], tags=["Notificaciones", "Proveedores"])
async def get_proveedor_notificaciones(
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor")),
):
    query = db.query(models.Notificacion).filter(models.Notificacion.proveedor_id == current_supplier.id)
    notificaciones = query.order_by(models.Notificacion.fecha_creacion.desc()).all()
    return notificaciones

@app.put("/proveedores/notificaciones/{notification_id}/leer", status_code=status.HTTP_200_OK, tags=["Notificaciones", "Proveedores"])
async def mark_notification_as_read(
    notification_id: int,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    notificacion = db.query(models.Notificacion).filter(
        models.Notificacion.id == notification_id,
        models.Notificacion.proveedor_id == current_supplier.id
    ).first()

    if not notificacion:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notificación no encontrada o no pertenece a este proveedor.")
    
    notificacion.leida = True
    try:
        db.add(notificacion)
        db.commit()
        db.refresh(notificacion)
        return {"message": "Notificación marcada como leída."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al marcar como leída: {str(e)}")

@app.delete("/proveedores/notificaciones/{notification_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Notificaciones", "Proveedores"])
async def delete_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    notificacion = db.query(models.Notificacion).filter(
        models.Notificacion.id == notification_id,
        models.Notificacion.proveedor_id == current_supplier.id
    ).first()

    if not notificacion:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notificación no encontrada o no pertenece a este proveedor.")
    
    try:
        db.delete(notificacion)
        db.commit()
        return {"message": "Notificación eliminada."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al eliminar notificación: {str(e)}")

@app.post("/admin/login", response_model=Token, tags=["Administradores"])
def login_admin(form_data: AdminLoginRequest, db: Session = Depends(get_db)):
    admin_db = db.query(Administrador).filter(Administrador.email == form_data.email).first()

    if not admin_db or not verify_password(form_data.password, admin_db.contrasena_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de administrador incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": admin_db.email, "role": "admin"})
    
    return {
        "token": access_token,
        "user_name": f"{admin_db.nombre} {admin_db.apellido}",
        "user_role": "admin"
    }

@app.get("/admin/proveedores/solicitudes/pendientes", response_model=List[SolicitudProveedorResponse], tags=["Administradores", "Proveedores"])
def get_pending_supplier_applications(
    db: Session = Depends(get_db),
    current_admin_user: Administrador = Depends(get_current_user_with_role("admin"))
):
    solicitudes = db.query(SolicitudProveedor).filter(SolicitudProveedor.estado == EstadoSolicitudEnum.pendiente).all() # Use the Enum here
    
    response_data = []
    for s in solicitudes:
        categorias_data = [{"id": cat.id, "nombre": cat.nombre} for cat in s.categorias_asociadas]
        response_data.append(
            SolicitudProveedorResponse(
                id=s.id,
                nombre_empresa=s.nombre_empresa,
                rfc=s.rfc,
                anios_experiencia=s.anios_experiencia,
                nombre_contacto=s.nombre_contacto,
                puesto_contacto=s.puesto_contacto,
                email_contacto=s.email_contacto,
                telefono_principal=s.telefono_principal,
                whatsapp=s.whatsapp,
                capacidad_mensual=s.capacidad_mensual,
                tiempo_entrega=s.tiempo_entrega,
                certificaciones=s.certificaciones,
                estado=s.estado.value, # Return the string value of the Enum
                fecha_solicitud=s.fecha_solicitud,
                categorias=categorias_data
            )
        )
    return response_data

async def send_welcome_email_task(email_to: str, subject: str, body: str):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype="html"
    )
    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        print(f"EMAIL ENVIADO: Correo a {email_to} - Asunto: {subject}")
    except Exception as e:
        print(f"ERROR AL ENVIAR EMAIL a {email_to}: {e}")

@app.post("/admin/proveedores/aprobar/{solicitud_id}", tags=["Administradores", "Proveedores"])
def approve_supplier_application(
    solicitud_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_admin_user: Administrador = Depends(get_current_user_with_role("admin"))
):
    solicitud = db.query(models.SolicitudProveedor).filter(models.SolicitudProveedor.id == solicitud_id).first()
    if not solicitud:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud de proveedor no encontrada.")
    if solicitud.estado != EstadoSolicitudEnum.pendiente: # Use the Enum here
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La solicitud ya no está pendiente.")

    temp_password = secrets.token_urlsafe(12)
    hashed_password = get_password_hash(temp_password)

    solicitud.estado = EstadoSolicitudEnum.aprobado # Use the Enum here
    solicitud.contrasena_hash = hashed_password
    
    try:
        db.add(solicitud)
        db.commit()
        db.refresh(solicitud)

        email_subject = "¡Tu solicitud de proveedor ha sido aprobada en ProVeo!"
        email_body = f"""
        <html>
            <body>
                <p>Estimado/a(s) {solicitud.nombre_contacto},</p>
                
                <p>Es un placer informarte que la solicitud de tu empresa, <strong>{solicitud.nombre_empresa}</strong>, para unirse a nuestra red de proveedores en ProVeo ha sido **APROBADA** con éxito. ¡Estamos muy entusiasmados con tu incorporación!</p>
                
                <p>A partir de ahora, ya puedes acceder a nuestra plataforma y comenzar a explorar las oportunidades disponibles. A continuación, te proporcionamos tus credenciales de acceso inicial:</p>
                
                <p>
                    <strong>Usuario (Email):</strong> <code>{solicitud.email_contacto}</code><br>
                    <strong>Contraseña Temporal:</strong> <code>{temp_password}</code>
                </p>
                
                <p>Por motivos de seguridad, te recomendamos encarecidamente que **cambies esta contraseña temporal** inmediatamente después de tu primer inicio de sesión. Esto garantizará la protección de tu cuenta y la información de tu empresa.</p>
                
                <p>Si tienes alguna pregunta o necesitas asistencia durante tus primeros pasos en la plataforma, no dudes en contactar a nuestro equipo de soporte.</p>
                
                <p>¡Te damos la más cordial bienvenida a la comunidad de ProVeo y esperamos una colaboración fructífera!</p>
                
                <p>Atentamente,</p>
                <p>El Equipo de ProVeo</p>
                <br>
                <hr>
                <p style="font-size: 0.8em; color: #777;">Este es un mensaje automático. Por favor, no respondas a este correo.</p>
            </body>
        </html>
        """
        background_tasks.add_task(send_welcome_email_task, solicitud.email_contacto, email_subject, email_body)

        return {"message": "Solicitud aprobada y proveedor registrado con éxito. Se envió un correo con la contraseña temporal."}
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error de base de datos al aprobar la solicitud: {e.orig}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error inesperado al aprobar: {str(e)}")

@app.post("/admin/proveedores/rechazar/{solicitud_id}", tags=["Administradores", "Proveedores"])
def reject_supplier_application(
    solicitud_id: int,
    db: Session = Depends(get_db),
    current_admin_user: Administrador = Depends(get_current_user_with_role("admin"))
):
    solicitud = db.query(models.SolicitudProveedor).filter(models.SolicitudProveedor.id == solicitud_id).first()
    if not solicitud:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud de proveedor no encontrada.")
    if solicitud.estado != EstadoSolicitudEnum.pendiente: # Use the Enum here
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La solicitud ya no está pendiente.")

    solicitud.estado = EstadoSolicitudEnum.rechazado # Use the Enum here
    solicitud.contrasena_hash = None
    
    try:
        db.add(solicitud)
        db.commit()
        db.refresh(solicitud)
        return {"message": "Solicitud de proveedor rechazada."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al rechazar solicitud: {str(e)}")
    
@app.get("/categorias", response_model=List[CategoriaResponse], tags=["General"])
async def get_all_categories(db: Session = Depends(get_db)):
    """
    Obtiene todas las categorías disponibles en el sistema.
    """
    categorias = db.query(models.Categoria).all()
    return categorias

# --- CHATBOT ENDPOINT PARA PROVEEDORES ---

@app.post("/chatbot/proveedor/ask", response_model=ChatResponse, tags=["Chatbot"])
async def chatbot_for_supplier(
    request: ChatRequest,
    db: Session = Depends(get_db),
    supplier_id: int = Depends(get_current_supplier_id) # Obtener el ID del proveedor autenticado
):
    message = request.message.lower().strip()
    response_text = "Disculpa, no entiendo tu pregunta. Puedo ayudarte con 'notificaciones', 'productos' o el 'estado de un producto'."

    if "notificaciones" in message or "novedades" in message or "alertas" in message:
        notifications = db.query(Notificacion).filter(
            Notificacion.proveedor_id == supplier_id
        ).order_by(Notificacion.fecha_creacion.desc()).limit(5).all()

        if not notifications:
            response_text = "No tienes notificaciones recientes. ¡Mantente atento a nuevas alertas!"
        else:
            response_text = "Aquí están tus últimas 5 notificaciones:\n\n"
            for i, notif in enumerate(notifications):
                status_text = "Leída" if notif.leida else "No Leída"
                response_text += (
                    f"**{i+1}. Asunto:** {notif.asunto}\n"
                    f"   **Tipo:** {notif.tipo.replace('_', ' ').title()}\n"
                    f"   **Estado:** {status_text}\n"
                    f"   **Fecha:** {notif.fecha_creacion.strftime('%Y-%m-%d %H:%M')}\n"
                    f"   **Cuerpo:** {notif.cuerpo[:100]}...\n\n"
                )
            response_text += "Para consultar más detalles y gestionar todas tus notificaciones, visita la sección de notificaciones en tu panel de ProVeo."

    elif "productos" in message and ("mis" in message or "lista" in message or "cuántos" in message):
        products = db.query(ProductoProveedor).filter(
            ProductoProveedor.proveedor_id == supplier_id
        ).order_by(ProductoProveedor.fecha_creacion.desc()).limit(5).all()

        if not products:
            response_text = "Actualmente no tienes productos registrados en tu cuenta de ProVeo. ¿Te gustaría añadir alguno?"
        else:
            response_text = "Aquí están tus últimos 5 productos registrados:\n\n"
            for i, prod in enumerate(products):
                response_text += (
                    f"**{i+1}. Nombre:** {prod.nombre}\n"
                    f"   **SKU:** {prod.sku or 'N/A'}\n"
                    f"   **Precio:** {prod.precio}\n"
                    f"   **Stock:** {prod.stock} {prod.unidad_medida.value}\n"
                    f"   **Estado:** {prod.estado.value}\n\n"
                )
            response_text += "Para ver todos tus productos, gestionar el stock o añadir nuevos, visita la sección 'Mis Productos'."

    elif "estado" in message and ("producto" in message or "item" in message or "inventario" in message):
        # Extraer el identificador del producto (SKU o ID) del mensaje
        product_identifier = None
        
        # Intentar extraer un ID numérico
        import re
        match_id = re.search(r'(?:ID|id|número)\s*(\d+)', message)
        if match_id:
            product_identifier = int(match_id.group(1))
        else:
            # Intentar extraer un SKU alfanumérico
            match_sku = re.search(r'(?:SKU|sku|código)\s*:\s*([a-zA-Z0-9_-]+)', message)
            if match_sku:
                product_identifier = match_sku.group(1)
            else:
                # Último intento: buscar una palabra que podría ser un SKU o un nombre corto
                words = message.split()
                for word in words:
                    # Ignorar palabras comunes o muy cortas
                    if len(word) > 2 and word not in ["del", "un", "el", "de", "estado", "producto", "mi", "dame", "ver"]:
                        product_identifier = word
                        break
        
        product = None
        if product_identifier:
            if isinstance(product_identifier, int):
                product = db.query(ProductoProveedor).filter(
                    ProductoProveedor.proveedor_id == supplier_id,
                    ProductoProveedor.id == product_identifier
                ).first()
            elif isinstance(product_identifier, str):
                product = db.query(ProductoProveedor).filter(
                    ProductoProveedor.proveedor_id == supplier_id,
                    ProductoProveedor.sku == product_identifier
                ).first()
            
            # Si no se encontró por ID o SKU exacto, intentar por nombre parcial
            if not product and isinstance(product_identifier, str):
                product = db.query(ProductoProveedor).filter(
                    ProductoProveedor.proveedor_id == supplier_id,
                    ProductoProveedor.nombre.ilike(f'%{product_identifier}%') # Case-insensitive partial match
                ).first()


        if product:
            response_text = (
                f"El estado del producto **'{product.nombre}'** (ID: {product.id}, SKU: {product.sku or 'N/A'}):\n"
                f"   **Stock actual:** {product.stock} {product.unidad_medida.value}\n"
                f"   **Estado:** {product.estado.value}\n"
                f"   **Precio:** {product.precio}\n"
                f"   **Última actualización:** {product.fecha_actualizacion.strftime('%Y-%m-%d %H:%M')}\n"
            )
            # Ejemplo de alerta de stock bajo
            if product.stock <= 5 and product.estado.value != ProductStatusEnumDB.Inactivo.value:
                response_text += "\n⚠️ ¡Advertencia! El stock de este producto es **bajo**. Considera reponerlo pronto para evitar interrupciones."
            elif product.stock == 0 and product.estado.value != ProductStatusEnumDB.Inactivo.value:
                response_text += "\n❌ ¡Alerta! Este producto está **agotado**. ¡Necesitas reponerlo urgentemente!"
        else:
            response_text = "No pude encontrar ese producto en tu inventario. Por favor, asegúrate de proporcionar el **ID**, **SKU** o parte del **nombre** del producto para que pueda buscarlo."
    
    # Placeholder for "pedidos" - since you don't have an 'orders' table yet.
    elif "pedidos" in message or "órdenes" in message or "compras" in message:
        response_text = "Actualmente no tengo acceso directo a la información de tus pedidos o historial de compras aquí. Por favor, consulta la sección 'Mis Pedidos' en tu panel de control de ProVeo para ver el estado y los detalles de tus órdenes."
    
    elif "hola" in message or "que tal" in message or "saludos" in message:
        response_text = "¡Hola! Soy tu asistente virtual de ProVeo. ¿En qué puedo ayudarte hoy? Puedes preguntarme sobre tus **notificaciones**, el **estado de tus productos**, o ver una **lista de tus productos**."

    return ChatResponse(response=response_text)

# --- NEW ANALYZE CONTRACT ENDPOINT ---
# This endpoint assumes you have a separate service or library
# that can handle PDF/DOCX analysis. For this example, it will be a dummy.
@app.post("/api/analyze-contract", tags=["General", "AI Analysis"])
async def analyze_contract_endpoint(
    contract_file: UploadFile = File(...),
    language: str = Form("es"),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    """
    Endpoint para analizar un contrato subido.
    Este es un placeholder; la lógica de análisis real de contratos debería
    implementarse aquí, posiblemente llamando a un servicio externo de IA.
    """
    if contract_file.content_type not in ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain"]:
        raise HTTPException(status_code=400, detail="Tipo de archivo no soportado. Sube un PDF, DOC, DOCX o TXT.")
    
    # Simulate processing time
    import asyncio
    await asyncio.sleep(5) # Simulate a 5-second analysis

    # Dummy analysis data based on the original Vue structure
    dummy_analysis_data = [
        {"clauseType": "Vigencia del Contrato", "riskLevel": "Bajo", "suggestion": "La cláusula de vigencia es clara y estándar. No se requiere ninguna acción."},
        {"clauseType": "Condiciones de Pago", "riskLevel": "Medio", "suggestion": "Sugiero revisar el período de pago de 30 días, considerar si un pago anticipado es posible o si hay cláusulas de penalización por retraso."},
        {"clauseType": "Alcance de Servicios", "riskLevel": "Alto", "suggestion": "El alcance de servicios es demasiado genérico. Se recomienda especificar con mayor detalle los entregables y las responsabilidades de ambas partes para evitar malentendidos."},
        {"clauseType": "Confidencialidad", "riskLevel": "Bajo", "suggestion": "La cláusula de confidencialidad es robusta. Asegúrate de que todos los empleados con acceso a información sensible estén al tanto de esta cláusula."},
        {"clauseType": "Terminación Anticipada", "riskLevel": "Medio", "suggestion": "La penalización por terminación anticipada parece ser unilateral. Negocia términos más equitativos o una ventana de notificación más larga."},
        {"clauseType": "Garantías", "riskLevel": "Bajo", "suggestion": "Las garantías ofrecidas son estándar para la industria. Asegúrate de tener procesos internos para cumplir con ellas."},
        {"clauseType": "Jurisdicción", "riskLevel": "Alto", "suggestion": "La jurisdicción exclusiva en un país extranjero podría implicar altos costos legales en caso de disputa. Considera la mediación o arbitraje antes de recurrir a los tribunales."}
    ]

    return {"response": "Análisis de contrato completado.", "analysisData": dummy_analysis_data}