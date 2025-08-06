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
# from langchain_community.embeddings import HuggingFaceEmbeddings # type: ignore
from langchain_huggingface import HuggingFaceEmbeddings # type: ignore
from langchain_community.embeddings import OllamaEmbeddings # type: ignore
from langchain.text_splitter import RecursiveCharacterTextSplitter # type: ignore
from langchain_community.document_loaders import DirectoryLoader, PyPDFLoader, TextLoader # type: ignore
from langchain.output_parsers import PydanticOutputParser
from typing import TypedDict, List, Optional, Literal
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, END

import re
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
CACHE_FILE = 'data/cache_ip.csv'
CSV_HEADER = ['ip', 'status', 'label', 'location', 'detail', 'timestamp']  # 定义CSV文件的表头
LOG_FILE = 'log_ip.txt'
INPUT_FILE = 'ip_list.csv'
# PROMPT_FILE = 'prompt_ip.txt'
# KNOWLEDGE_BASE_DIR = 'knowledge_base'
# PERSIST_DIRECTORY = 'db_ip' # 建议为IP分析使用独立的向量数据库


# -------- 工具辅助函数定义 --------
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

# ---------- 工具函数定义 ----------

# 获取IP的Whois信息（ASN、归属等）
def get_whois_info(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,org,as,query")
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            return (f"IP: {data['query']}\n"
                    f"Country: {data.get('country', 'N/A')}\n"
                    f"Region: {data.get('regionName', 'N/A')}\n"
                    f"City: {data.get('city', 'N/A')}\n"
                    f"ISP: {data.get('isp', 'N/A')}\n"
                    f"Organization: {data.get('org', 'N/A')}\n"
                    f"ASN: {data.get('as', 'N/A')}\n"
                    f"isProxy: {data.get('proxy', 'N/A')}\n"
                    f"isHosting: {data.get('hosting', 'N/A')}\n"
                    f"isMobile: {data.get('mobile', 'N/A')}\n"
                    )
        else:
            return f"查询Whois信息失败: {data.get('message', 'Unknown error')}"
    except Exception as e:
        return f"获取Whois信息时出错: {e}"

# 使用OTX进行反向DNS查询
def get_reverse_dns_domains(ip_address):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
    if not OTX_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    try:
        OTX_SERVER = 'https://otx.alienvault.com/'
        otx = OTXv2(OTX_API_KEY, server=OTX_SERVER)
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

# 直接连接IP获取SSL证书
def get_ssl_certificate_info(ip_address):
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
        return "连接443端口超时，可能未开放或网络问题"
    except (ConnectionRefusedError, ssl.SSLError):
        return "无法连接到443端口或协商SSL失败"
    except Exception as e:
        return f"获取SSL证书时发生未知错误: {e}"

# 从IP地址获取网页内容
def get_website_content(ip_address):
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
    return "无法获取有效的网页内容"

# 从OTX获取IP的威胁情报
def get_otx_ip_analyses(ip_address):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
    if not OTX_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    try:
        otx = OTXv2(OTX_API_KEY)
        alerts = []
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip_address, 'general')
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        verdict = "低风险"
        if len(alerts) > 2:
            verdict = "高风险"
        elif len(alerts) > 0:
            verdict = "中风险"
        report = (
            f"OTX威胁情报检测结果:\n"
            f"- 评级: {verdict}\n"
            f"- 情报内容: {alerts}"
        )
        return report
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

# --------- 缓存相关函数定义  ---------

def load_cache_from_csv():
    ip_cache = {} # Key: ip, Value: dict with full report info
    try:
        if not os.path.isfile(CACHE_FILE):
             raise FileNotFoundError
        with open(CACHE_FILE, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            try:
                header = next(reader) # Skip header
            except StopIteration:
                return {} # Return empty dict for empty file
            for row in reader:
                if row and len(row) >= 5:
                    ip = row[0]
                    ip_cache[ip] = {
                        "status": row[1],
                        "label": row[2] if row[2] else None, # Handle empty string
                        "location": row[3] if row[3] else None,
                        "detail": row[4]
                    }
        print(f"成功从 '{CACHE_FILE}' 加载 {len(ip_cache)} 条缓存记录。")
    except FileNotFoundError:
        print(f"缓存文件 '{CACHE_FILE}' 未找到，将自动创建。")
    except IndexError:
        print(f"缓存文件 '{CACHE_FILE}' 格式不正确。")
    return ip_cache

# 写入缓存操作
def append_to_cache_csv(ip, status, label, location, detail):
    file_exists = os.path.isfile(CACHE_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(CACHE_FILE, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CACHE_FILE) == 0:
                writer.writerow(CSV_HEADER) # 如果是新文件或空文件，先写入表头
            writer.writerow([ip, status, label, location, detail, timestamp])
    except IOError as e:
        print(f"写入缓存文件 '{CACHE_FILE}' 时发生错误: {e}")

# --------- 初始化函数定义 ---------

    # 从CSV文件中读取待分析的IP
    # def read_ips_to_analyze(file_path):
    #     try:
    #         with open(file_path, 'r', encoding='utf-8', newline='') as f:
    #             reader = csv.reader(f)
    #             header = next(reader)
    #             ips = [row[0] for row in reader if row and row[0].strip()]
    #         print(f"   - 成功从 '{file_path}' 文件中读取 {len(ips)} 个待分析IP。")
    #         return ips
    #     except FileNotFoundError:
    #         print(f"   - [错误] '{file_path}' 未找到。")
    #         return []
    #     except (StopIteration, IndexError):
    #         print(f"   - '{file_path}' 为空或格式不正确。")
    #         return []

def initialize_llm():
    # 使用谷歌gemini-2.0-flash大模型
    # if not os.environ.get("GOOGLE_API_KEY"):
    #     os.environ["GOOGLE_API_KEY"] = getpass.getpass("Enter API key for Google Gemini: ")
    # model = init_chat_model("gemini-2.0-flash", temperature=0.1, model_provider="google_genai")
    # return model

    # 使用通义千问qwen-turbo大模型
    # if not os.environ.get("DASHSCOPE_API_KEY"):
    #   os.environ["DASHSCOPE_API_KEY"] = getpass.getpass("Enter API key for Qwen: ")
    # model = Tongyi(temperature=0.1, model_name = 'qwen-turbo-latest')
    # return model

    # 使用通义千问qwen3:8b（本地部署）大模型
    model = OllamaLLM(model="qwen3:14b", temperature=0.1, base_url="http://192.168.3.98:11434")
    # model = OllamaLLM(model="qwen2.5:14b", temperature=0.1, base_url="http://host.docker.internal:11434")
    print("   - 初始化本地LLM (qwen3:14b)...")
    return model

# ---------- LangGraph定义 ----------

class IPReport(BaseModel):
    """最终的域名安全分析报告的结构化输出。"""
    status: Literal["Safe", "Suspicious", "Malicious"] = Field(description="对IP的最终裁决")
    label: Optional[str] = Field(None, description="如果IP是可疑或恶意的，用中文列出一个或多个特定的恶意行为类型，如'钓鱼网站', '垃圾邮件', '远程访问木马', 'C2服务器'，'勒索软件'，'僵尸网络'等，当威胁情报有明确的恶意类型时，需要全部列出。安全IP则为'-'。")
    location: Optional[str] = Field(None, description="用中文列出IP所在的国家或地区")
    detail: str = Field(description="用中文一句话简要总结做出判断的核心原因")

class IPAnalysisState(TypedDict):
    """图的状态，在节点之间传递信息"""
    ip: str
    otx_report: Optional[str]
    virustotal_report: Optional[str]
    whois_info: Optional[str]
    dns_domains: Optional[str]
    ssl_info: Optional[str]
    website_content: Optional[str]
    final_report: Optional[IPReport] # The final, structured report

# 节点定义

def initial_threat_intel_node(state: IPAnalysisState) -> dict:
    """节点1：获取初始威胁情报"""
    ip = state["ip"]
    print(f"--- [Node] 获取 {ip} 的初始威胁情报 ---")
    otx_report = get_otx_ip_analyses(ip)
    virustotal_report = get_vt_ip_report(ip)
    whois_info = get_whois_info(ip)
    print(otx_report)
    print(virustotal_report)
    return {
        "whois_info": whois_info,
        "otx_report": otx_report,
        "virustotal_report": virustotal_report
    }


def supplementary_info_node(state: IPAnalysisState) -> dict:
    """节点2：获取补充信息"""
    ip = state["ip"]
    print(f"--- [Node] 为 {ip} 获取补充信息 ---")
    # For a more robust solution, these could be run in parallel
    dns_domains = get_reverse_dns_domains(ip)
    ssl_info = get_ssl_certificate_info(ip)
    website_content = get_website_content(ip)
    return {
        "dns_domains": dns_domains,
        "ssl_info": ssl_info,
        "website_content": website_content
    }

def final_analysis_node(state: IPAnalysisState) -> dict:
    """节点3：进行最终的综合分析并生成报告 (使用OutputParser适配本地模型)"""
    ip = state["ip"]
    print(f"--- [Node] 对 {ip} 进行最终综合分析 ---")
    
    # 2. 创建一个Pydantic解析器实例
    parser = PydanticOutputParser(pydantic_object=IPReport)

    # 3. 在Prompt中加入格式化指令
    prompt_context = f"""
你是一名顶尖的网络安全分析师。你已经收集到了关于IP地址 '{ip}' 的所有情报信息。
请基于下面提供的全部上下文，进行深入分析，判断该域名的性质。

**已收集情报:**
- OTX情报: {state.get('otx_report', '未收集')}
- VirusTotal情报: {state.get('virustotal_report', '未收集')}
- Whois信息: {state.get('whois_info', '未收集')}
- DNS反向解析信息: {state.get('dns_domains', '未收集')}
- SSL证书信息: {state.get('ssl_info', '未收集')}
- 网站内容摘要: {state.get('website_content', '未收集')}

**任务:**
综合上述所有信息，推断潜在的恶意行为。

**重要：请严格按照以下JSON格式输出你的最终报告，不要包含任何其他多余的文字或解释。**
{parser.get_format_instructions()}
"""
    
    llm = initialize_llm()
    
    try:
        # 2. 首先，只调用LLM，获取它可能包含多余文本的原始输出
        raw_output = llm.invoke(prompt_context)
        print(f"--- [Debug] LLM原始输出:\n{raw_output}\n---")

        # 3. 使用正则表达式从原始输出中提取JSON部分
        # re.DOTALL 使得 '.' 可以匹配包括换行在内的任意字符
        json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        
        if not json_match:
            # 如果在输出中完全找不到JSON，则抛出错误
            raise ValueError("LLM的输出中未找到有效的JSON对象。")
            
        json_string = json_match.group(0)
        
        # 4. 最后，将提取出的纯净JSON字符串交给解析器进行解析
        final_report = parser.parse(json_string)

    except Exception as e:
        print(f"!!! 解析LLM输出时发生错误: {e}")
        # 增加对原始输出的打印，方便调试
        if 'raw_output' in locals():
            print(f"!!! 导致错误的原始输出是: {raw_output}")
        return {"final_report": None}

    return {"final_report": final_report}

# --- Conditional Edge Function ---
def should_gather_more_info(state: IPAnalysisState) -> Literal["gather_supplementary_info", "analyze_directly"]:
    """条件边：根据初始情报判断是否需要进一步收集信息"""
    print("--- [Edge] 判断是否需要补充信息 ---")
    otx = state.get("otx_report", "")
    vt = state.get("virustotal_report", "")

    if "高风险" in vt or "高风险" in otx: # type: ignore
        print(" -> 决策：威胁情报充足，直接分析")
        return "analyze_directly"

    print(" -> 决策：初始情报不足，进一步收集补充信息分析")
    return "gather_supplementary_info"

# ------------- 主函数 -------------

# 退避函数（防止超过限额）

@retry(
    wait=wait_exponential(multiplier=1, min=20, max=90),
    stop=stop_after_attempt(8),
    retry=retry_if_exception_type(ResourceExhausted)
)
def run_graph_with_retry(app, ip):
    print("   - 正在调用 LangGraph...")
    response = app.invoke({"ip": ip})
    print("   - LangGraph 调用成功")
    return response

def process_cached_ip(ip, cached_report_data):
        # 从缓存数据重建 DomainReport 对象
        report = IPReport(
            status=cached_report_data['status'],
            label=cached_report_data['label'],
            location=cached_report_data.get('location'),
            detail=cached_report_data['detail']
        )
        print(f"\n   [缓存命中] '{ip}' 的分析结果已从缓存加载。")
        # 格式化并打印与新分析一致的输出
        result_output = f"性质: {report.status}\n"
        if report.label:
            result_output += f"类型：{report.label}\n"
        if report.location:
            result_output += f"地理位置：{report.location}\n"
        result_output += f"核心理由: {report.detail}"
        print("\n" + "="*50)
        print("✅ 分析完成，最终报告：")
        print(result_output)
        print("="*50)
        
        # 返回完整的报告对象，保持类型一致性
        return report

def process_uncached_ip(ip):
    print(f"   [缓存未命中] '{ip}' 是新IP，开始执行LangGraph分析...")
    print("\n" + "="*50)
    print(f"   开始分析IP: {ip} ")
    print("="*50)
    start_time = time.perf_counter()

    # --- LangGraph Definition ---
    graph = StateGraph(IPAnalysisState)

    # Add nodes
    graph.add_node("initial_threat_intel", initial_threat_intel_node)
    graph.add_node("supplementary_info", supplementary_info_node)
    graph.add_node("final_analysis", final_analysis_node)

    # Set entry point
    graph.set_entry_point("initial_threat_intel")

    # Add edges
    graph.add_conditional_edges(
        "initial_threat_intel",
        should_gather_more_info,
        {
            "gather_supplementary_info": "supplementary_info",
            "analyze_directly": "final_analysis",
        }
    )
    graph.add_edge("supplementary_info", "final_analysis")
    graph.add_edge("final_analysis", END)

    # Compile the graph into a runnable app
    app = graph.compile()

    try:
        # Run the graph
        final_state = run_graph_with_retry(app, ip)
        report: IPReport = final_state.get('final_report')

        if not report:
            raise ValueError("未能生成最终报告。")

        # --- Process the structured result ---
        result_output = (
            f"Final Answer: {report.status}\n"
        )
        if report.status:
            result_output += f"类型：{report.label}\n"
        if report.location:
            result_output += f"地理位置：{report.location}\n"
        result_output += f"核心理由: {report.detail}"
        
        print("\n" + "="*50)
        print("✅ 分析完成，最终报告：")
        print(result_output)
        print("="*50)

        # Log to file
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*50 + f"\nIP: {ip}\n" + result_output + "\n" + "="*50 + "\n")
        
        print(f"   [更新缓存] 将 '{ip}' 标记为 '{report.status}' 并写入缓存。")
        append_to_cache_csv(ip, report.status, report.label, report.location, report.detail)
            
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"\n运行时间: {duration:.2f} 秒")
        print("\n" + "="*50)
        return report

    except Exception as e:
        error_message = f"在分析IP {ip} 时发生严重错误: {e}"
        print(error_message)
        # Optionally log the full state for debugging
        print("--- ERROR STATE ---", final_state)
        return "ERROR"


if __name__ == "__main__":
    # if len(sys.argv) > 1:
    #     ip = sys.argv[1].strip()
    # else:
    #     ip = input("请输入要查询的IP地址: ").strip()
    
    required_keys = ["VT_API_KEY", "OTX_API_KEY"]
    missing_keys = [key for key in required_keys if not os.environ.get(key)]
    
    if missing_keys:
        print(f"错误: 以下环境变量未设置，程序无法继续: {', '.join(missing_keys)}")
        print("请在运行前设置好API密钥。")
        sys.exit(1) # 程序直接退出
    
    # 批量读取csv文件中的所有域名
    csv_path = os.path.join(os.path.dirname(__file__), INPUT_FILE)
    ips = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].strip():
                # 只取第一列，去除前后空白
                ip = row[0].strip()
                ips.append(ip)
    
    print(f"共读取到 {len(ips)} 个待分析IP。\n")
    ip_cache = load_cache_from_csv()
    for idx, ip in enumerate(ips, 1):
        print(f"\n===== 正在分析第 {idx}/{len(ips)} 个IP: {ips} =====\n")
        if ip in ip_cache:
            cached_report_data = ip_cache[ip]
            process_cached_ip(ip, cached_report_data)
        else:
            process_uncached_ip(ip)
    print("\n所有域名分析完成。程序结束。\n")