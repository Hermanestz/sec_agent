# main.py
from fastapi import FastAPI
from pydantic import BaseModel # 用于定义请求体的数据结构

# 从你的项目逻辑模块中导入核心函数
from project.agent_domain import start_with_domain
from project.agent_ip import start_with_ip

# 1. 创建 FastAPI 应用实例
# 你可以添加标题、描述等信息，这些会显示在自动生成的文档中
app = FastAPI(
    title="安全分析API",
    description="基于agent的恶意域名及恶意ip自动检测",
    version="1.0.0",
)

# 2. 定义请求体模型 (Request Body)
# 使用 Pydantic 的 BaseModel，FastAPI 会自动处理数据类型验证和转换
class TextRequest(BaseModel):
    text: str
    # 你可以添加更多字段，例如：
    # method: str = 'default'

# 3. 创建一个 API 端点 (Endpoint)
# @app.post("/analyze/") 定义了一个接受 POST 请求的路径
# 当用户向 http://your_server/analyze/ 发送 POST 请求时，这个函数会被调用
@app.post("/analyze/domain")
def analyze_domain_endpoint(request: TextRequest):
    # 从请求体中获取文本
    domain = request.text
    
    # 调用你的核心业务逻辑
    result = start_with_domain(domain)
    
    # FastAPI 会自动将返回的字典转换为 JSON 格式的响应
    return result

@app.post("/analyze/ip")
def analyze_ip_endpoint(request: TextRequest):
    # 从请求体中获取文本
    ip = request.text
    
    # 调用你的核心业务逻辑
    result = start_with_ip(ip)
    
    # FastAPI 会自动将返回的字典转换为 JSON 格式的响应
    return result

# 你也可以创建一个根端点用于测试
@app.get("/")
def read_root():
    return {"message": "欢迎使用安全分析API，请访问 /docs 查看API文档。"}