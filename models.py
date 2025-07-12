# models.py

from sqlalchemy import Column, Integer, String, Table, ForeignKey, DateTime, Text, Numeric, Date, Boolean # <--- ¡Boolean AÑADIDO aquí!
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, ENUM 

import enum 

from database import Base


# --- Tabla de Unión para la relación muchos-a-muchos ---
solicitud_categoria_junction = Table(
    'solicitud_categoria_junction',
    Base.metadata,
    Column('solicitud_id', Integer, ForeignKey('solicitudes_proveedores.id', ondelete="CASCADE"), primary_key=True),
    Column('categoria_id', String, ForeignKey('categorias.id', ondelete="RESTRICT"), primary_key=True)
)

# --- NUEVO MODELO PARA ADMINISTRADORES ---
class Administrador(Base):
    __tablename__ = "administradores"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    contrasena_hash = Column(String, nullable=False)
    nombre = Column(String, nullable=False)
    apellido = Column(String, nullable=False)

class Cliente(Base):
    __tablename__ = "clientes"

    id = Column(Integer, primary_key=True, index=True)
    nombres = Column(String, index=True)
    apellidos = Column(String)
    email_corporativo = Column(String, unique=True, index=True)
    telefono_contacto = Column(String)
    puesto_cargo = Column(String)
    razon_social_empresa = Column(String)
    rfc_empresa = Column(String, unique=True, index=True)
    industria_sector = Column(String)
    tamano_empresa = Column(String)
    contrasena_hash = Column(String)
    fecha_registro = Column(DateTime(timezone=True), server_default=func.now())
    aceptar_terminos = Column(Boolean, default=True)


# --- MODELOS PARA PROVEEDORES ---
class SolicitudProveedor(Base):
    __tablename__ = "solicitudes_proveedores"

    id = Column(Integer, primary_key=True, index=True)
    nombre_empresa = Column(String, index=True)
    rfc = Column(String, unique=True, index=True)
    anios_experiencia = Column(Integer)
    nombre_contacto = Column(String)
    puesto_contacto = Column(String)
    email_contacto = Column(String, unique=True, index=True)
    telefono_principal = Column(String)
    whatsapp = Column(String, nullable=True)
    capacidad_mensual = Column(String)
    tiempo_entrega = Column(String)
    certificaciones = Column(String, nullable=True)
    
    estado = Column(String, default='pendiente') # 'pendiente', 'aprobado', 'rechazado'
    contrasena_hash = Column(String, nullable=True)
    
    fecha_solicitud = Column(DateTime(timezone=True), server_default=func.now())

    categorias_asociadas = relationship(
        "Categoria",
        secondary=solicitud_categoria_junction,
        back_populates="solicitudes"
    )
    
    # Relación inversa para ProductosProveedor
    productos = relationship("ProductoProveedor", back_populates="proveedor", cascade="all, delete-orphan")
    # AÑADIDO: Relación inversa para Notificaciones
    notificaciones = relationship("Notificacion", back_populates="proveedor", cascade="all, delete-orphan")


class Categoria(Base):
    __tablename__ = "categorias"

    id = Column(String(50), primary_key=True, index=True)
    nombre = Column(String(100), unique=True)
    
    solicitudes = relationship(
        "SolicitudProveedor",
        secondary=solicitud_categoria_junction,
        back_populates="categorias_asociadas"
    )

# --- Enums para el estado del producto (debe coincidir con tu DB) ---
class ProductStatusEnumDB(enum.Enum):
    Activo = "Activo"
    Inactivo = "Inactivo"
    Borrador = "Borrador"

# --- Enums para la unidad de medida (debe coincidir con tu DB) ---
class UnitOfMeasureEnumDB(enum.Enum):
    Unidad = "Unidad"
    Caja = "Caja"
    Paquete = "Paquete"
    Kg = "Kg"
    Ltr = "Ltr"
    Docena = "Docena"
    Bulto = "Bulto"
    Palet = "Palet"
    Servicio = "Servicio"
    Licencia = "Licencia"
    Suscripcion = "Suscripcion"

# --- MODELO PARA PRODUCTOS DE PROVEEDORES ---
class ProductoProveedor(Base):
    __tablename__ = "productos_proveedores"

    id = Column(Integer, primary_key=True, index=True)
    proveedor_id = Column(Integer, ForeignKey("solicitudes_proveedores.id", ondelete="CASCADE"), nullable=False)
    nombre = Column(String(255), nullable=False)
    descripcion = Column(Text)
    precio = Column(Numeric(10, 2), nullable=False)
    stock = Column(Integer, nullable=False, default=0)
    categoria_id = Column(String(50), ForeignKey("categorias.id", ondelete="RESTRICT"))
    image_url = Column(String(2048))
    sku = Column(String(100), unique=True)
    
    # Mapeo de enums a tipos de PostgreSQL
    # 'create_type=False' es importante para que SQLAlchemy no intente crear el tipo ENUM si ya existe en la DB.
    estado = Column(ENUM(ProductStatusEnumDB, name="product_status_enum", create_type=False), nullable=False, default="Borrador")
    unidad_medida = Column(ENUM(UnitOfMeasureEnumDB, name="unit_of_measure_enum", create_type=False), nullable=False, default="Unidad")
    
    cantidad_minima_pedido = Column(Integer, nullable=False, default=1)
    precios_por_volumen = Column(JSONB, default=[]) # Mapeo para el tipo JSONB
    peso_kg = Column(Numeric(10, 3))
    dimension_largo_cm = Column(Numeric(10, 2))
    dimension_ancho_cm = Column(Numeric(10, 2))
    dimension_alto_cm = Column(Numeric(10, 2))
    codigo_barras = Column(String(100))
    fecha_caducidad = Column(Date) # Mapeo para el tipo DATE
    tiempo_procesamiento_dias = Column(Integer)
    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())
    fecha_actualizacion = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relaciones con otras tablas
    proveedor = relationship("SolicitudProveedor", back_populates="productos")
    categoria = relationship("Categoria")

# AÑADIDO: Modelo para Notificaciones
class Notificacion(Base):
    __tablename__ = "notificaciones"

    id = Column(Integer, primary_key=True, index=True)
    # ID del proveedor a quien va dirigida la notificación
    proveedor_id = Column(Integer, ForeignKey('solicitudes_proveedores.id'), nullable=False)
    # Tipo de notificación (ej. 'nuevo_pedido', 'solicitud_contacto', etc.)
    tipo = Column(String(50), nullable=False)
    # Asunto o título de la notificación
    asunto = Column(String(255), nullable=False)
    # Cuerpo/contenido de la notificación
    cuerpo = Column(Text, nullable=False)
    # Campo para almacenar datos adicionales en formato JSON (ej. ID de producto, cantidad)
    datos_extra = Column(Text, nullable=True) # Puede ser JSON
    # Estado de lectura
    leida = Column(Boolean, default=False)
    # Fecha de creación
    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())

    # Relación con el proveedor (para obtener el objeto proveedor fácilmente)
    proveedor = relationship("SolicitudProveedor", back_populates="notificaciones")