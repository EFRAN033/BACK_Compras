# main.py

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, UploadFile, File # Added UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets
from dotenv import load_dotenv
from enum import Enum

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from decimal import Decimal
from datetime import date
import json

import models
from database import SessionLocal, engine
from models import Administrador, SolicitudProveedor, Categoria, Cliente

# NEW: Import StaticFiles for serving static files (like uploaded images)
from fastapi.staticfiles import StaticFiles

load_dotenv()

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

# --- UTILIDADES DE SEGURIDAD ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/afiliados/login")

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
            # Si el token es de proveedor, busca en SolicitudProveedor
            user = db.query(models.SolicitudProveedor).filter(
                models.SolicitudProveedor.email_contacto == email,
                models.SolicitudProveedor.estado == 'aprobado' # Solo si está aprobado
            ).first()
        else:
            user = None

        if user is None:
            raise credentials_exception
        return user
    return _get_current_user

# --- Modelos Pydantic para Productos ---
class ProductStatusEnum(str, Enum):
    activo = "Activo"
    inactivo = "Inactivo"
    borrador = "Borrador"

class UnitOfMeasureEnum(str, Enum):
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
    suscripcion = "Suscripción"

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

# --- MODELO PYDANTIC para Categoría (Respuesta) ---
class CategoriaResponse(BaseModel):
    id: str
    nombre: str

    class Config:
        from_attributes = True

# --- INSTANCIA Y CONFIGURACIÓN DE FASTAPI ---
app = FastAPI(title="ProVeo API", version="1.0.0")

# MONTAR EL DIRECTORIO ESTÁTICO PARA IMÁGENES
# Asegúrate de que exista una carpeta 'static' en la raíz de tu proyecto backend
# Y dentro de 'static', una carpeta 'images'.
# Ejemplo de estructura:
# tu_proyecto_backend/
# ├── main.py
# ├── models.py
# ├── static/
# │   └── images/
# └── ...
app.mount("/static", StaticFiles(directory="static"), name="static") # Added Static Files mounting

origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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
        estado='pendiente'
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

# --- NUEVO ENDPOINT: Login para Proveedores ---
@app.post("/proveedors/login", response_model=Token, tags=["Proveedores"])
def login_proveedor(form_data: LoginRequest, db: Session = Depends(get_db)):
    # Busca al proveedor en la tabla solicitudes_proveedores por email_contacto
    # Solo los proveedores con estado 'aprobado' pueden iniciar sesión
    proveedor_db = db.query(models.SolicitudProveedor).filter(
        models.SolicitudProveedor.email_contacto == form_data.email,
        models.SolicitudProveedor.estado == 'aprobado'
    ).first()

    if not proveedor_db or not verify_password(form_data.password, proveedor_db.contrasena_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de proveedor incorrectas o cuenta no aprobada",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Crea un token de acceso con el rol 'proveedor'
    access_token = create_access_token(data={"sub": proveedor_db.email_contacto, "role": "proveedor"})
    
    # Devuelve el token y el nombre del contacto del proveedor, incluyendo el rol
    return {
        "token": access_token,
        "user_name": proveedor_db.nombre_contacto,
        "user_role": "proveedor"
    }

# --- INICIO DE ENDPOINTS DE GESTIÓN DE PRODUCTOS PARA PROVEEDORES ---
@app.post("/proveedores/productos", response_model=ProductoProveedorResponse, status_code=status.HTTP_201_CREATED, tags=["Proveedores", "Productos"])
async def create_product_for_supplier(
    product: ProductoProveedorCreate,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    # Verificar si la categoría existe
    categoria_exists = db.query(models.Categoria).filter(models.Categoria.id == product.categoria_id).first()
    if not categoria_exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"La categoría '{product.categoria_id}' no existe."
        )

    # Convertir List[PrecioPorVolumen] a JSONB string
    precios_por_volumen_json = json.dumps([p.dict() for p in product.precios_por_volumen]) if product.precios_por_volumen else "[]"


    db_product = models.ProductoProveedor(
        proveedor_id=current_supplier.id,
        nombre=product.nombre,
        descripcion=product.descripcion,
        precio=product.precio,
        stock=product.stock,
        categoria_id=product.categoria_id,
        image_url=product.image_url,
        sku=product.sku,
        estado=product.estado.value,
        unidad_medida=product.unidad_medida.value,
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

    update_data = product_update.dict(exclude_unset=True)

    if "categoria_id" in update_data:
        categoria_exists = db.query(models.Categoria).filter(models.Categoria.id == update_data["categoria_id"]).first()
        if not categoria_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"La categoría '{update_data['categoria_id']}' no existe."
            )

    if "precios_por_volumen" in update_data:
        update_data["precios_por_volumen"] = json.dumps([p.dict() for p in update_data["precios_por_volumen"]])
    
    if "estado" in update_data:
        update_data["estado"] = update_data["estado"].value
    if "unidad_medida" in update_data:
        update_data["unidad_medida"] = update_data["unidad_medida"].value

    for key, value in update_data.items():
        setattr(db_product, key, value)
    
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

@app.delete("/proveedores/productos/{product_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Proveedores", "Productos"])
async def delete_supplier_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_supplier: models.SolicitudProveedor = Depends(get_current_user_with_role("proveedor"))
):
    db_product = db.query(models.ProductoProveedor).filter(
        models.ProductoProveedor.id == product_id,
        models.ProductoProveedor.proveedor_id == current_supplier.id
    ).first()

    if not db_product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Producto no encontrado o no pertenece a este proveedor.")

    try:
        db.delete(db_product)
        db.commit()
        return {"message": "Producto eliminado con éxito."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al eliminar el producto: {str(e)}")

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
        
        image_url = f"http://localhost:8000/static/images/{unique_filename}"
        return {"imageUrl": image_url}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al subir la imagen: {str(e)}")

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

# --- ENDPOINTS PARA LA GESTIÓN DE PROVEEDORES POR EL ADMINISTRADOR ---

@app.get("/admin/proveedores/solicitudes/pendientes", response_model=List[SolicitudProveedorResponse], tags=["Administradores", "Proveedores"])
def get_pending_supplier_applications(
    db: Session = Depends(get_db),
    current_admin_user: Administrador = Depends(get_current_user_with_role("admin"))
):
    solicitudes = db.query(SolicitudProveedor).filter(SolicitudProveedor.estado == 'pendiente').all()
    
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
                estado=s.estado,
                fecha_solicitud=s.fecha_solicitud,
                categorias=categorias_data
            )
        )
    return response_data

# Función para enviar un correo electrónico real usando FastMail
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
    if solicitud.estado != 'pendiente':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La solicitud ya no está pendiente.")

    temp_password = secrets.token_urlsafe(12)
    hashed_password = get_password_hash(temp_password)

    solicitud.estado = 'aprobado'
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
    if solicitud.estado != 'pendiente':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La solicitud ya no está pendiente.")

    solicitud.estado = 'rechazado'
    solicitud.contrasena_hash = None # Limpiar contraseña si se rechaza

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