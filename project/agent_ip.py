import sys
from langchain.agents import Tool # type: ignore
from langchain_google_genai import ChatGoogleGenerativeAI # type: ignore
from langchain.agents import initialize_agent, AgentType # type: ignore
from langchain.chat_models import init_chat_model # type: ignore
from langchain_community.llms import Tongyi # type: ignore
from langchain_community.chat_models import ChatZhipuAI # type: ignore
from langchain_ollama import OllamaLLM # type: ignore
from langchain.chains import RetrievalQA # type: ignore
from langchain_community.vectorstores import Chroma # type: ignore
from langchain_community.embeddings import HuggingFaceEmbeddings # type: ignore
from langchain_community.embeddings import OllamaEmbeddings # type: ignore
from langchain.text_splitter import RecursiveCharacterTextSplitter # type: ignore
from langchain_community.document_loaders import DirectoryLoader, PyPDFLoader, TextLoader # type: ignore

import os
import time
from datetime import datetime
import getpass
import requests # type: ignore
from bs4 import BeautifulSoup # type: ignore
import whois # type: ignore
from OpenSSL import SSL # type: ignore
from cryptography import x509 # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
import socket
import ssl
import dns.resolver # type: ignore
import csv
import json
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type # type: ignore
from google.api_core.exceptions import ResourceExhausted # type: ignore
from OTXv2 import OTXv2 # type: ignore
import IndicatorTypes # type: ignore

# ---------- 文件路径定义 (已修改为IP) ----------
INPUT_FILE = 'data/ips.csv'
CACHE_FILE = 'data/cache_ip.csv'
CSV_HEADER = ['ip', 'label', 'timestamp']  # 定义CSV文件的表头
LOG_FILE = 'log_ip.txt'
PROMPT_FILE = 'prompt_ip.txt'
KNOWLEDGE_BASE_DIR = 'knowledge_base'
PERSIST_DIRECTORY = 'db_ip' # 建议为IP分析使用独立的向量数据库


VT_API_KEY = '98ba6009319dffa00a02e4e81a1f68f93becfc391e7f4fcc3515378aa9f4ab5f'
GOOGLE_API_KEY = 'AIzaSyA5Hsd3kfVLYr0cxI9X37AXB-HVfTzyQNw'
DASHSCOPE_API_KEY = 'sk-dd3e949c8b134f71bfb00764707658a4'

# -------- 工具辅助函数定义 --------
# (无需修改)
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:
        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

# ---------- 工具函数定义 (核心修改区域) ----------

# 【修改】获取IP的Whois信息（ASN、归属等）
def get_ip_whois_info(ip_address):
    """(基础工具)查询一个IP地址的Whois信息，获取其ASN、网络所有者和国家等信息。"""
    try:
        # 使用ip-api.com作为示例，因为它能提供更结构化的ASN信息
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,org,as,query")
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            return (f"IP: {data['query']}\n"
                    f"Country: {data.get('country', 'N/A')}\n"
                    f"Organization: {data.get('org', 'N/A')}\n"
                    f"ASN: {data.get('as', 'N/A')}")
        else:
            return f"查询IP Whois信息失败: {data.get('message', 'Unknown error')}"
    except Exception as e:
        return f"获取IP Whois信息时出错: {e}"

# 【替换】使用OTX进行反向DNS查询
def get_reverse_dns_lookup(ip_address):
    """(基础工具)通过OTX平台查询一个IP地址上曾经解析过的域名历史记录。"""
    try:
        OTX_API_KEY = 'd65a1499bb1a9f13f205246063662f937cf76f94e5f2e4e15ef428ee8c66fbcb'
        otx = OTXv2(OTX_API_KEY)
        # 使用 IndicatorTypes.IPv4 进行查询
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip_address, 'passive_dns')
        hostnames = [item.get('hostname') for item in result.get('passive_dns', [])]
        if hostnames:
            # 返回最近的10个域名以保持简洁
            return f"在IP {ip_address} 上发现的历史域名: {', '.join(list(set(hostnames))[:10])}"
        else:
            return "未发现与该IP关联的历史域名。"
    except Exception as e:
        return f"查询OTX反向DNS时出错: {e}"

# 【修改】直接连接IP获取SSL证书
def get_ip_ssl_certificate_info(ip_address):
    """(基础工具)直接连接一个IP地址的443端口，获取并分析其SSL/TLS证书信息。"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip_address, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                cert_der = ssock.getpeercert(True)
        cert = x509.load_der_x509_certificate(cert_der, default_backend()) # type: ignore
        
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        cert_details = (
            f"Subject: {subject}\n"
            f"Issuer: {issuer}\n"
            f"Valid From: {not_valid_before}\n"
            f"Valid Until: {not_valid_after}"
        )
        return cert_details
    except socket.timeout:
        return "连接443端口超时，可能未开放或网络问题。"
    except (ConnectionRefusedError, ssl.SSLError):
        return "无法连接到443端口或协商SSL失败，该端口可能未开放或未配置SSL。"
    except Exception as e:
        return f"获取SSL证书时发生未知错误: {e}"

# 【微调】从IP地址获取网页内容
def get_website_content(ip_address):
    """(基础工具)获取一个IP地址在80或443端口上托管的网页文本内容。"""
    # 优先尝试HTTPS
    for scheme in ['https://', 'http://']:
        try:
            url = f"{scheme}{ip_address}"
            response = requests.get(url, timeout=10, verify=False) # verify=False忽略SSL证书错误
            soup = BeautifulSoup(response.text, 'html.parser')
            text_content = soup.get_text()
            if text_content and not text_content.isspace():
                 return text_content[:2000] # 截取前2000字符
        except requests.exceptions.RequestException:
            continue
    return "无法从此IP地址获取任何有效的网页内容。"

# 【修改】从OTX获取IP的威胁情报
def get_otx_ip_analyses(ip_address):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
    if not OTX_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    try:
        otx = OTXv2(OTX_API_KEY)
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip_address, 'general')
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            alerts = [f"In pulse: {pulse['name']}" for pulse in pulses if 'name' in pulse]
            if alerts:
                return '检测到威胁情报：' + str(alerts)
        return '未检测到威胁情报'
    except Exception as e:
        return f"查询OTX威胁情报时出错: {e}"

# 通过VirusTotal获取IP的安全声誉
def get_vt_ip_report(ip_address):
    if not os.environ.get("VT_API_KEY"):
        os.environ["VT_API_KEY"] = getpass.getpass("Enter API key for VirusTotal: ")
    VT_API_KEY = os.environ.get("VT_API_KEY")
    if not VT_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        if not data:
            return f"VirusTotal数据库中没有关于 '{ip_address}' 的信息。"
        
        stats = data.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        
        verdict = "【低风险】"
        if malicious_count > 3:
            verdict = "【高风险】"
        elif malicious_count > 0 or suspicious_count > 0:
            verdict = "【中度风险/可疑】"

        report = (
            f"VirusTotal安全声誉:\n"
            f"- 综合评估: {verdict}{malicious_count}个安全厂商将其标记为恶意，{suspicious_count}个标记为可疑。\n"
            f"- ASN所有者: {data.get('as_owner', 'N/A')}\n"
            f"- 国家: {data.get('country', 'N/A')}"
        )
        return report
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return f"VirusTotal数据库中没有找到IP '{ip_address}' 的分析报告。"
        elif e.response.status_code == 401:
            return "错误：VirusTotal API Key无效或权限不足。"
        return f"访问VirusTotal API时发生HTTP错误: {e}"
    except Exception as e:
        return f"查询VirusTotal时发生未知错误: {e}"

# --------- 缓存相关函数定义 (已修改为IP) ---------

def load_cache_from_csv():
    ip_cache = {}
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if row:
                    ip_cache[row[0]] = row[1]
        print(f"成功从 '{CACHE_FILE}' 加载 {len(ip_cache)} 条缓存记录。")
    except FileNotFoundError:
        print(f"缓存文件 '{CACHE_FILE}' 未找到，将自动创建。")
    except (StopIteration, IndexError):
        print(f"缓存文件 '{CACHE_FILE}' 为空或格式不正确。")
    return ip_cache

def append_to_cache_csv(ip, status):
    file_exists = os.path.isfile(CACHE_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(CACHE_FILE, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CACHE_FILE) == 0:
                writer.writerow(CSV_HEADER)
            writer.writerow([ip, status, timestamp])
    except IOError as e:
        print(f"写入缓存文件 '{CACHE_FILE}' 时发生错误: {e}")

# --------- 初始化函数定义 ---------

# 初始化知识库
def setup_rag_retriever(llm):
    if not os.path.exists(KNOWLEDGE_BASE_DIR):
        print(f"   - [警告] 知识库目录 '{KNOWLEDGE_BASE_DIR}' 未找到。RAG工具将不可用。")
        return None
    loaded_documents = []
    print(f"   - 开始从 '{KNOWLEDGE_BASE_DIR}' 手动加载文件...")
    for root, _, files in os.walk(KNOWLEDGE_BASE_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"     - 正在处理文件: {file_path}")
            try:
                if file.endswith(".pdf"):
                    loader = PyPDFLoader(file_path)
                    loaded_documents.extend(loader.load())
                elif file.endswith(".md") or file.endswith(".txt"):
                    loader = TextLoader(file_path, encoding='utf-8')
                    loaded_documents.extend(loader.load())
            except Exception as e:
                print(f"     - [错误] 加载文件 {file_path} 失败: {e}")
    if not loaded_documents:
        print(f"   - [警告] 知识库目录 '{KNOWLEDGE_BASE_DIR}' 中没有找到可加载的文档。RAG工具将不可用。")
        return None
    print(f"   - 成功从 '{KNOWLEDGE_BASE_DIR}' 加载 {len(loaded_documents)} 个文档。")
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    texts = text_splitter.split_documents(loaded_documents)
    print("   - 正在初始化嵌入模型 (这可能需要一些时间)...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    print("   - 正在创建并持久化向量数据库...")
    db = Chroma.from_documents(texts, embeddings, persist_directory=PERSIST_DIRECTORY)
    db.persist()
    retriever = db.as_retriever(search_kwargs={"k": 2})
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm, chain_type="stuff", retriever=retriever, return_source_documents=True
    )
    print("   - RAG检索器设置成功。")
    return qa_chain

# 读取待分析的IP
def read_ips_to_analyze(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)
            ips = [row[0] for row in reader if row and row[0].strip()]
        print(f"   - 成功从 '{file_path}' 文件中读取 {len(ips)} 个待分析IP。")
        return ips
    except FileNotFoundError:
        print(f"   - [错误] IP文件 '{file_path}' 未找到。")
        return []
    except (StopIteration, IndexError):
        print(f"   - IP文件 '{file_path}' 为空或格式不正确。")
        return []

def initialize_llm():
    # 使用谷歌gemini-2.0-flash大模型
    if not os.environ.get("GOOGLE_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = getpass.getpass("Enter API key for Google Gemini: ")
    model = init_chat_model("gemini-2.0-flash", temperature=0.1, model_provider="google_genai")
    return model

    # 使用智谱GLM-4大模型
    # if not os.environ.get("ZHIPUAI_API_KEY"):
    #     os.environ["ZHIPUAI_API_KEY"] = getpass.getpass("Enter API key for Zhipu GLM-4: ")
    # model = ChatZhipuAI(temperature=0.1, model_name="glm-4")
    # return model

    # 使用通义千问qwen-turbo大模型
    # if not os.environ.get("DASHSCOPE_API_KEY"):
    #   os.environ["DASHSCOPE_API_KEY"] = getpass.getpass("Enter API key for Qwen: ")
    # model = Tongyi(temperature=0.1, model_name = 'qwen-turbo-latest')
    # return model

    # 使用通义千问qwen3:8b（本地部署）大模型
    # model = OllamaLLM(model="qwen2.5:1.5b")
    # return model

# ---------- 重要函数定义  ----------

def process_ip_analysis(ip, agent, ip_cache):
    if ip in ip_cache:
        status = ip_cache[ip]
        print(f"   [缓存命中] '{ip}' 是已知的 {status} IP，跳过分析。")
        return status
    
    print(f"   [缓存未命中] '{ip}' 是新IP，开始执行Agent分析...")
    print(f"🚀 开始分析IP: {ip} 🚀")
    start_time = time.perf_counter()

    with open(PROMPT_FILE, 'r', encoding='utf-8') as file:
        prompt_template = file.read()
    
    prompt = prompt_template.format(ip=ip) # <-- 修改

    try:
        response = run_agent_with_retry(agent, prompt)
        result_output = response.get('output', '未能获取到输出。')
        print("="*50)
        print(result_output)
        print("\n" + "="*50)

        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*50 + "\n")
            f.write(result_output)
            f.write("\n" + "="*50 + "\n")

        if "高风险（恶意IP）" in result_output:
            status = 'malicious'
        elif "低风险（安全IP）" in result_output:
            status = 'safe'
        else:
            status = 'suspicious'
        
        print(f"   [更新缓存] 将 '{ip}' 标记为 '{status}' 并写入缓存。")
        append_to_cache_csv(ip, status)
        ip_cache[ip] = status
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"\n✅ IP {ip} 分析完成，用时: {duration:.2f} 秒")
        print("\n" + "="*50)
        return status

    except Exception as e:
        error_message = f"在分析IP {ip} 时发生严重错误: {e}"
        print(error_message)
        return error_message

# (无需修改)
@retry(
    wait=wait_exponential(multiplier=1, min=20, max=90),
    stop=stop_after_attempt(8),
    retry=retry_if_exception_type(ResourceExhausted)
)
def run_agent_with_retry(agent, prompt):
    print("   - 正在调用 Agent API...")
    response = agent.invoke({"input": prompt})
    print("   - Agent API 调用成功")
    return response

# ------------- 主函数 (核心修改区域) -------------

def start_with_ip(ip):
    model = initialize_llm()
    rag_qa_chain = setup_rag_retriever(model)

    # --- 【核心修改】创建新的IP分析工具列表 ---
    tools = [
        Tool(
            name="IP Whois Information Fetcher",
            func=get_ip_whois_info,
            description="(基础工具)查询一个IP地址的Whois信息，获取其ASN、网络所有者和国家等信息。输入应为一个IP地址，例如 '8.8.8.8'。"
        ),
        Tool(
            name="Reverse DNS Lookup",
            func=get_reverse_dns_lookup,
            description="(基础工具)查询一个IP地址上曾经托管过的域名历史记录。输入应为一个IP地址，例如 '8.8.8.8'。"
        ),
        Tool(
            name="IP SSL Certificate Analyzer",
            func=get_ip_ssl_certificate_info,
            description="(基础工具)直接连接一个IP地址的443端口，获取其SSL/TLS证书信息。仅在端口扫描发现443端口开放时使用。输入应为一个IP地址。"
        ),
        Tool(
            name="Website Content Fetcher",
            func=get_website_content,
            description="(基础工具)获取一个IP地址在80或443端口上托管的网页的文本内容。仅在端口扫描发现80或443端口开放时使用。输入应为一个IP地址。"
        ),
        Tool(
            name="OTX IP Threat Intelligence",
            func=get_otx_ip_analyses,
            description="(基础工具)通过OTX威胁情报共享平台获取一个IP地址的威胁情报。输入应为一个IP地址。"
        ),
        Tool(
            name="VirusTotal IP Report",
            func=get_vt_ip_report,
            description="(拓展工具)通过VirusTotal专业威胁情报平台获取一个IP地址的安全声誉。当第二步分析不能确定IP是恶意还是安全时，才需要使用该工具。输入应为一个IP地址。"
        )
    ]

    if rag_qa_chain:
        def run_rag_chain(query: str):
            result = rag_qa_chain({"query": query})
            source_docs = "\n".join([f"Source: {doc.metadata.get('source', 'Unknown')}" for doc in result['source_documents']])
            return f"Retrieved Information:\n{result['result']}\n\nSources:\n{source_docs}"
        rag_tool = Tool(
            name="Knowledge Base Retriever",
            func=run_rag_chain,
            description="从内部知识库中检索与查询相关的信息。当你需要关于特定威胁、攻击活动（如C2服务器IP）、或分析技术的背景知识时使用它。"
        )
        tools.insert(0, rag_tool)

    agent = initialize_agent(
        tools,
        model,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,
        handle_parsing_errors="请检查你的输出并确保其符合格式要求！"
    )

    ip_cache = load_cache_from_csv()
    result = process_ip_analysis(ip, agent, ip_cache)

    return result


if __name__ == "__main__":
    ip = input("请输入要查询的ip地址 (例如: 8.8.8.8): ").strip()
    start_with_ip(ip)