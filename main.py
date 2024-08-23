import shutil
from urllib.request import Request

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File
from fastapi.exceptions import RequestValidationError
from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr, constr
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional, List
import os
from pydantic import BaseModel, EmailStr

from starlette.responses import FileResponse, JSONResponse

# Configuración de la base de datos
DATABASE_URL = "mysql+pymysql://root:0000@localhost/ZegoDB"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Inicialización del esquema de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Definición del modelo Usuario
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nombre_empleado = Column(String(100), nullable=False)
    correo = Column(String(100), unique=True, nullable=False)
    contraseña = Column(String(100), nullable=False)
    rol = Column(String(50), nullable=False)
    token = Column(String(255), nullable=True)  # Añadido el campo token

# Definición del modelo Cliente
class Cliente(Base):
    __tablename__ = "clientes"

    id = Column(Integer, primary_key=True, index=True)
    nombre_cliente = Column(String(100), nullable=False)
    nombre_sucursal = Column(String(100), nullable=False)
    correo_cliente = Column(String(100), unique=True, nullable=False)
    contraseña = Column(String(100), nullable=False)
    direccion = Column(String(255), nullable=False)
    region = Column(String(50), nullable=False)
    giro_empresa = Column(String(50), nullable=False)

    licencias = relationship("LicenciaSanitaria", back_populates="cliente")

# Definición del modelo LicenciaSanitaria
class LicenciaSanitaria(Base):
    __tablename__ = "licenciasanitaria"
    id = Column(Integer, primary_key=True, index=True)
    nombre_archivo = Column(String(255))
    contenido = Column(LargeBinary)
    cliente_id = Column(Integer, ForeignKey('clientes.id'))

    cliente = relationship("Cliente", back_populates="licencias")

# Creación de las tablas en la base de datos
Base.metadata.create_all(bind=engine)

# Esquemas para la entrada y salida de datos
class UsuarioCreate(BaseModel):
    nombre_empleado: str
    correo: EmailStr
    contraseña: constr(min_length=6)
    rol: str

class UsuarioOut(BaseModel):
    id: int
    nombre_empleado: str
    correo: str
    rol: str

    class Config:
        orm_mode = True

class UsuarioLogin(BaseModel):
    correo: EmailStr
    contraseña: constr(min_length=6)

class ClienteCreate(BaseModel):
    nombre_cliente: str
    nombre_sucursal: str
    correo_cliente: EmailStr
    contraseña: str
    direccion: str
    region: str
    giro_empresa: str

class ClienteOut(BaseModel):
    id: int
    nombre_cliente: str
    nombre_sucursal: str
    correo_cliente: str
    direccion: str
    region: str
    giro_empresa: str

    class Config:
        orm_mode = True

class LicenciaSanitariaCreate(BaseModel):
    nombre_archivo: str
    cliente_id: int

class LicenciaSanitariaOut(BaseModel):
    id: int
    nombre_archivo: str
    cliente_id: int

    class Config:
        orm_mode = True

# Configuración de JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"

def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# Operaciones CRUD
def create_usuario(db: Session, usuario: UsuarioCreate):
    hashed_password = pwd_context.hash(usuario.contraseña)
    db_usuario = Usuario(
        nombre_empleado=usuario.nombre_empleado,
        correo=usuario.correo,
        contraseña=hashed_password,
        rol=usuario.rol
    )
    db.add(db_usuario)
    db.commit()
    db.refresh(db_usuario)
    return db_usuario

def authenticate_user(db: Session, correo: str, contraseña: str):
    usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
    if usuario and pwd_context.verify(contraseña, usuario.contraseña):
        return usuario
    return None

def create_cliente(db: Session, cliente: ClienteCreate):
    hashed_password = pwd_context.hash(cliente.contraseña)
    db_cliente = Cliente(
        nombre_cliente=cliente.nombre_cliente,
        nombre_sucursal=cliente.nombre_sucursal,
        correo_cliente=cliente.correo_cliente,
        contraseña=hashed_password,
        direccion=cliente.direccion,
        region=cliente.region,
        giro_empresa=cliente.giro_empresa
    )
    db.add(db_cliente)
    db.commit()
    db.refresh(db_cliente)
    return db_cliente

def get_clientes(db: Session):
    return db.query(Cliente).all()

def get_cliente(db: Session, cliente_id: int):
    return db.query(Cliente).filter(Cliente.id == cliente_id).first()

def delete_cliente(db: Session, cliente_id: int):
    cliente = db.query(Cliente).filter(Cliente.id == cliente_id).first()
    if cliente:
        db.delete(cliente)
        db.commit()
        return True
    return False

def create_licencia_sanitaria(db: Session, nombre_archivo: str, cliente_id: int, contenido: bytes):
    db_licencia_sanitaria = LicenciaSanitaria(
        nombre_archivo=nombre_archivo,
        contenido=contenido,
        cliente_id=cliente_id
    )
    db.add(db_licencia_sanitaria)
    db.commit()
    db.refresh(db_licencia_sanitaria)
    return db_licencia_sanitaria

def get_licencias_sanitarias(db: Session, cliente_id: int):
    return db.query(LicenciaSanitaria).filter(LicenciaSanitaria.cliente_id == cliente_id).all()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token requerido")
    try:
        token = authorization.split(" ")[1]  # Suponiendo que el token está en formato "Bearer token"
        payload = verify_jwt_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Token inválido")
        usuario = db.query(Usuario).filter(Usuario.correo == payload.get("sub")).first()
        if not usuario:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        return usuario
    except IndexError:
        raise HTTPException(status_code=401, detail="Formato de token incorrecto")

app = FastAPI()

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ajusta los orígenes permitidos según tus necesidades
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rutas de la API
@app.post("/api/login")
def login(usuario: UsuarioLogin, db: Session = Depends(get_db)):
    db_usuario = authenticate_user(db, usuario.correo, usuario.contraseña)
    if not db_usuario:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token_data = {"sub": db_usuario.correo}
    token = create_jwt_token(token_data)
    return {
        "token": token,
        "token_type": "bearer",
        "rol": db_usuario.rol,
        "nombre_empleado": db_usuario.nombre_empleado
    }

@app.post("/api/register", response_model=UsuarioOut)
def register_usuario(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    db_usuario = create_usuario(db, usuario)
    return db_usuario

@app.get("/api/user", response_model=UsuarioOut)
def get_user(current_user: Usuario = Depends(get_current_user)):
    return current_user

@app.get("/api/auth")
def auth_user(current_user: Usuario = Depends(get_current_user)):
    return {
        "nombre_empleado": current_user.nombre_empleado,
        "rol": current_user.rol,
        "correo": current_user.correo
    }

@app.post("/api/logout")
def logout(current_user: Usuario = Depends(get_current_user)):
    # Aquí deberías invalidar el token del usuario
    return {"message": "Logout exitoso"}

@app.post("/api/clientes", response_model=ClienteOut)
def crear_cliente(cliente: ClienteCreate, db: Session = Depends(get_db)):
    db_cliente = create_cliente(db, cliente)
    return db_cliente

@app.get("/api/clientes", response_model=List[ClienteOut])
def leer_clientes(db: Session = Depends(get_db)):
    clientes = get_clientes(db)
    return clientes

@app.delete("/api/clientes/{cliente_id}")
def eliminar_cliente(cliente_id: int, db: Session = Depends(get_db)):
    if delete_cliente(db, cliente_id):
        return {"message": "Cliente eliminado exitosamente"}
    else:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

@app.post("/api/licencias-sanitarias/", response_model=LicenciaSanitariaOut)
async def subir_licencia(
    archivo: UploadFile = File(...),
    cliente_id: int = None,
    db: Session = Depends(get_db)
):
    if not cliente_id:
        raise HTTPException(status_code=400, detail="ID del cliente requerido")
    try:
        contenido = await archivo.read()
        db_licencia = create_licencia_sanitaria(db, archivo.filename, cliente_id, contenido)
        return db_licencia
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al subir el archivo: {e}")

@app.get("/api/licencias-sanitarias/{cliente_id}", response_model=List[LicenciaSanitariaOut])
def obtener_licencias(cliente_id: int, db: Session = Depends(get_db)):
    licencias = get_licencias_sanitarias(db, cliente_id)
    if not licencias:
        raise HTTPException(status_code=404, detail="Licencias no encontradas")
    return licencias

# Función para crear el directorio si no existe
def ensure_directory_exists(directory: str):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Manejo de archivos y almacenamiento
@app.post("/api/upload-file/")
async def upload_file(file: UploadFile = File(...)):
    directory = "files"
    ensure_directory_exists(directory)

    file_location = os.path.join(directory, file.filename)
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)

    return {"info": f"File '{file.filename}' uploaded successfully"}


@app.get("/api/download-file/{filename}")
async def download_file(filename: str):
    file_location = f"files/{filename}"
    if os.path.exists(file_location):
        return FileResponse(path=file_location, filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found")


class EmpresaSeleccionada(BaseModel):
    id: int
    nombre_cliente: str
    nombre_sucursal: str
    direccion: str

@app.post("/api/seleccionarEmpresa")
def seleccionar_empresa(empresa: EmpresaSeleccionada):
    global empresa_seleccionada
    empresa_seleccionada = empresa.dict()
    return {"message": "Empresa seleccionada"}

@app.get("/api/empresaSeleccionada")
def obtener_empresa_seleccionada():
    return empresa_seleccionada



#actualizar empresa xD
class ClienteUpdate(BaseModel):
    nombre_cliente: Optional[str] = None
    nombre_sucursal: Optional[str] = None
    correo_cliente: Optional[EmailStr] = None
    contraseña: Optional[str] = None
    direccion: Optional[str] = None
    region: Optional[str] = None  # Puede ser opcional si no se actualiza
    giro_empresa: Optional[str] = None  # Puede ser opcional si no se actualiza



# Función CRUD para actualizar cliente
def update_cliente(db: Session, cliente_id: int, cliente_update: ClienteUpdate):
    cliente = db.query(Cliente).filter(Cliente.id == cliente_id).first()
    if not cliente:
        return None

    if cliente_update.nombre_cliente is not None:
        cliente.nombre_cliente = cliente_update.nombre_cliente
    if cliente_update.nombre_sucursal is not None:
        cliente.nombre_sucursal = cliente_update.nombre_sucursal
    if cliente_update.correo_cliente is not None:
        cliente.correo_cliente = cliente_update.correo_cliente
    if cliente_update.contraseña is not None:
        cliente.contraseña = pwd_context.hash(cliente_update.contraseña)
    if cliente_update.direccion is not None:
        cliente.direccion = cliente_update.direccion
    if cliente_update.region is not None:
        cliente.region = cliente_update.region
    if cliente_update.giro_empresa is not None:
        cliente.giro_empresa = cliente_update.giro_empresa

    db.commit()
    db.refresh(cliente)
    return cliente

# Ruta para editar cliente
@app.put("/api/clientes/{cliente_id}", response_model=ClienteOut)
def editar_cliente(cliente_id: int, cliente_update: ClienteUpdate, db: Session = Depends(get_db)):
    db_cliente = update_cliente(db, cliente_id, cliente_update)
    if db_cliente is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return db_cliente



@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    body = exc.body
    return JSONResponse(
        status_code=422,
        content={
            "detail": errors,
            "body": body
        },
    )


# Ejecución de la aplicación
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
