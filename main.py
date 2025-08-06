# main.py
import os
from datetime import timedelta, datetime
from typing import Annotated, Union

from fastapi import Depends, FastAPI, HTTPException, status # type: ignore
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm # type: ignore
from fastapi.responses import FileResponse
from jose import JWTError, jwt # type: ignore
from passlib.context import CryptContext # type: ignore
from pydantic import BaseModel # type: ignore

from project.agent_domain import start_with_domain
from project.agent_ip import start_with_ip

# --- 1. 应用实例与配置 ---

# 创建 FastAPI 应用实例 (修复了重复创建的问题)
app = FastAPI(
    title="安全分析API",
    description="基于agent的恶意域名及恶意IP自动检测",
    version="4.3",  # 版本号更新
)

# --- 添加CORS中间件配置 ---
# 允许所有来源（origins），在生产环境中应配置为你的前端域名
# origins = [
#     # "*", # 这是一个通配符，允许所有来源
#     # "http://localhost",
#     "http://localhost:8080",
#     "https://your-frontend-domain.com",
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"], # 允许所有HTTP方法
#     allow_headers=["*"], # 允许所有请求头
# )

# --- 2. 安全与认证 (重大改进) ---

# a. JWT 配置
# !! 重要: 这个密钥应该通过环境变量等方式加载，绝不能硬编码在代码中 !!
# 例如: SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key")
SECRET_KEY = "your-super-secret-key-that-is-long-and-random"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# b. 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# c. OAuth2 方案
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# d. 辅助函数：密码验证与Token创建
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- 3. Pydantic 模型定义 ---

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str

class AnalysisRequest(BaseModel):
    target: str

class AnalysisResult(BaseModel):
    status: str
    label: str
    detail: str 


# --- 4. 模拟数据库和用户获取 ---

fake_users_db = {
    "user": {
        "username": "user",
        "hashed_password": get_password_hash("gsta@2025"), # 真实哈希
        "disabled": False,
    },
}

def get_user(db, username: str) -> Union[UserInDB, None]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

# --- 5. 依赖项：用户认证 ---

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # type: ignore
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = get_user(fake_users_db, username=token_data.username) # type: ignore
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    """获取当前活动用户，如果用户被禁用则抛出异常"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# --- 6. API 端点 (Endpoints) ---

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """用户登录以获取访问令牌"""
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """获取当前用户的个人信息"""
    return current_user


# (核心业务端点 - 已受保护)
@app.post("/analyze/domain", response_model=AnalysisResult)
async def analyze_domain_endpoint(
    request: AnalysisRequest,
    current_user: Annotated[User, Depends(get_current_active_user)] # <--- 添加了安全依赖
):
    domain = request.target
    try:
        result = start_with_domain(domain)
        return result
    except Exception as e:
        # 添加基本的异常处理
        raise HTTPException(status_code=500, detail=f"An error occurred during domain analysis: {e}")


# (核心业务端点 - 已受保护)
@app.post("/analyze/ip", response_model=AnalysisResult)
async def analyze_ip_endpoint(
    request: AnalysisRequest,
    current_user: Annotated[User, Depends(get_current_active_user)] # <--- 添加了安全依赖
):
    ip = request.target
    # 可以在这里添加对输入IP的格式验证逻辑

    # 调用核心业务逻辑
    try:
        result = start_with_ip(ip)
        return result
    except Exception as e:
        # 添加基本的异常处理
        raise HTTPException(status_code=500, detail=f"An error occurred during IP analysis: {e}")

@app.get("/", response_class=FileResponse)
async def serve_frontend():
    return "static/index.html"

@app.get("/")
def read_root():
    return {"message": "欢迎使用安全分析API v4.3，请访问 /docs 查看API文档。"}