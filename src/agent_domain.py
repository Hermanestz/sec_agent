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
from langchain.output_parsers import PydanticOutputParser # type: ignore
from typing import TypedDict, List, Optional, Literal
from pydantic import BaseModel, Field # type: ignore
from langgraph.graph import StateGraph, END # type: ignore

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
import dns.resolver # type: ignore
import csv
import json
import joblib # type: ignore
from collections import Counter # 新增
import numpy as np # type: ignore
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type # type: ignore
from google.api_core.exceptions import ResourceExhausted # type: ignore
from OTXv2 import OTXv2 # type: ignore
import IndicatorTypes # type: ignore

# ---------- 文件路径定义 ----------

# 定义域名输入文件
CACHE_FILE = 'data/cache_domain.csv'
CSV_HEADER = ['domain', 'status', 'label', 'location', 'detail', 'timestamp']  # 定义CSV文件的表头
LOG_FILE = 'log_domain.txt'
INPUT_FILE = 'domain_list.csv'

# 全局变量存储OTX alerts
# PROMPT_FILE = 'prompt_domain.txt'
# KNOWLEDGE_BASE_DIR = 'knowledge_base'
# PERSIST_DIRECTORY = 'db_domain'

# -------- 工具辅助函数定义 --------

# 从字典或列表中根据给定的键获取对应的值
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


# 在check_dga_with_ml函数中调用，提取域名字符串的DGA特征，返回特征值
def extract_features_for_prediction(domain):
    def get_entropy(s):
        if not s: return 0
        p = Counter(s)
        return -sum(count / len(s) * np.log2(count / len(s)) for count in p.values())
    def get_vowel_consonant_ratio(s):
        s = s.lower(); vowels = "aeiou"; vowel_count = sum(1 for c in s if c in vowels); consonant_count = sum(1 for c in s if c.isalpha() and c not in vowels); return vowel_count / consonant_count if consonant_count else vowel_count
    def get_digit_ratio(s):
        return sum(1 for c in s if c.isdigit()) / len(s) if len(s) > 0 else 0
    def get_longest_consecutive_chars(s, char_type='alpha'):
        max_len = 0; current_len = 0
        for char in s:
            is_target = (char_type == 'alpha' and char.isalpha()) or \
                        (char_type == 'digit' and char.isdigit()) or \
                        (char_type == 'consonant' and char.isalpha() and char.lower() not in "aeiou")
            if is_target: current_len += 1
            else: max_len = max(max_len, current_len); current_len = 0
        return max(max_len, current_len)
    domain = str(domain).lower()
    tld = domain.split('.')[-1]
    domain_without_tld = '.'.join(domain.split('.')[:-1])
    return [len(domain_without_tld), get_entropy(domain_without_tld), get_vowel_consonant_ratio(domain_without_tld), get_digit_ratio(domain_without_tld), get_longest_consecutive_chars(domain_without_tld, 'consonant')]

# ---------- 工具函数定义 ----------

# 使用预训练的机器学习模型判断域名是否由DGA算法生成
def check_dga_with_ml(domain):
    global dga_model, scaler # 确保能访问全局模型
    if not dga_model or not scaler:
        return "DGA detected model unloaded"
    try:
        if '://' in domain: domain = domain.split('//')[1].split('/')[0]
        features = np.array(extract_features_for_prediction(domain)).reshape(1, -1)
        features_scaled = scaler.transform(features)
        prediction = dga_model.predict(features_scaled)
        # print(f"\nAgent成功获取DGA预测结果")
        return "根据字符串特征判定域名疑似DGA生成" if prediction[0] == 1 else "域名字符串特征较正常，无法确定为DGA生成"
    except Exception as e:
        return f"DGA检测时发生错误: {e}"

# 使用python-whois库获取域名的whois注册信息，返回全部whois信息
def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        # print(f"\nAgent成功获取whois信息")
        return str(info)
    except Exception as e:
        return f"Error fetching Whois info: {e}"

# 使用python-dns库获取域名解析后的ip地址，再通过request获取IP地址的相关消息，返回包含所有IP地址的解析信息
def get_dns_ips(domain):
    try:
        ip_records = {'A': [], 'CNAME': None}
        # 清理输入，确保是纯域名
        if '://' in domain:
            domain = domain.split('//')[1].split('/')[0]
        # 设置DNS解析器和超时时间
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            ttl_value = a_records.rrset.ttl # type: ignore
            ip_records['A'] = [ip.to_text() for ip in a_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass # 没有A记录是正常情况
        # 查询CNAME记录
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            ip_records['CNAME'] = cname_records[0].target.to_text(omit_final_dot=True) # type: ignore
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass # 没有CNAME记录也是正常情况
        if not ip_records['A'] and not ip_records['CNAME']:
            return f"无法解析域名 '{domain}' 的任何A或CNAME记录。"
        report = {
            "ip_records": ip_records,
            "status": "success",
            "domain": domain,
            "dns_ttl": ttl_value,
            "ip_addresses": ip_records['A'],
            "ip_details": [] # 默认为空列表
        }
        api_url = "http://ip-api.com/batch"
        headers = {"Content-Type": "application/json"}
        try:
            # 发起 POST 请求，将IP列表作为JSON数据发送，为了精简信息只选择了一些关键字段返回
            # 可以根据需要修改 fields 参数（参考文档: https://ip-api.com/docs/batch）
            response = requests.post(api_url, json=ip_records['A'], headers=headers, timeout=15)
            response.raise_for_status() # 如果请求失败（如4xx或5xx错误），则抛出异常
            # print(f"\nAgent成功获取ip地址相关信息")
            report["ip_details"] = response.json()
            return report   # 返回包含所有IP详情的JSON对象列表
        except requests.exceptions.RequestException as e:
            return f"Network error: {e}"
        except Exception as e:
            return f"Error: {e}"
    except dns.resolver.NXDOMAIN:
        # 域名完全不存在
        return f"Error: NXDOMAIN"
    except dns.resolver.Timeout:
        # DNS查询超时
        return f"Error：DNS Resolver Timeout"
    except Exception as e:
        # 捕获其他所有可能的异常，例如输入格式问题
        return f"Error：{e}"

# 通过otx平台获取域名的过去解析到的 IP 地址历史
def get_passive_dns_ips(domain):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
    if not OTX_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    OTX_SERVER = 'https://otx.alienvault.com/'
    try:
        otx = OTXv2(OTX_API_KEY, server=OTX_SERVER)
        dns_result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, domain, 'passive_dns')
        return(dns_result)
    except Exception as e:
        return f"Error fetching OTX Analyse: {e}"

# 使用dns库查询 MX, TXT (用于SPF和DMARC) 和 _domainkey 子域名下的TXT记录 
def get_dns_auth_records(domain):
    records = {"MX": [], "SPF": "未找到", "DMARC": "未找到", "DKIM_Selectors": []}
    resolver = dns.resolver.Resolver()
    try:
        # 查询MX
        mx_records = resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in mx_records] # type: ignore
    except dns.resolver.NoAnswer:
        records['MX'] = "无MX记录"
    except Exception: pass

    try:
        # 查询SPF和DMARC (都在TXT记录里)
        txt_records = resolver.resolve(domain, 'TXT')
        for r in txt_records:
            txt_data = r.to_text()
            if 'v=spf1' in txt_data:
                records['SPF'] = txt_data
            elif 'v=DMARC1' in txt_data: # DMARC记录在 _dmarc.example.com
                 dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                 for dr in dmarc_records:
                     if 'v=DMARC1' in dr.to_text():
                         records['DMARC'] = dr.to_text()
                         break
    except dns.resolver.NoAnswer:
        pass # 没有TXT记录
    except Exception: pass
    return records

# 使用socket库建立433端口连接，获取并解析一个域名的SSL/TLS证书信息，返回整理后的证书内容
def get_ssl_certificate_info(domain):
    output_list = []  # 初始化一个空列表来存储结果
    try:
        # 2. 发送 API 请求
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        if not response.text:
            return f"未找到域名 '{domain}' 的任何证书记录。"
        json_data = response.json()
        if not json_data:
            return f"未找到域名 '{domain}' 的任何证书记录。"
        # 处理数据
        unique_certs = {cert['id']: cert for cert in json_data}.values()
        # 格式化信息并添加到列表
        sorted_certs = sorted(unique_certs, key=lambda x: x['not_before'], reverse=True)
        for cert in sorted_certs:
            # 将时间戳转换为可读格式
            try:
                not_before = datetime.strptime(cert.get('not_before'), "%Y-%m-%dT%H:%M:%S").strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                not_before = 'N/A'
            try:
                not_after = datetime.strptime(cert.get('not_after'), "%Y-%m-%dT%H:%M:%S").strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                not_after = 'N/A'
            matching_identities = cert.get('name_value', 'N/A').replace('\n', ', ')
            # 使用 f-string 创建一个格式化的多行字符串
            cert_details_string = (
                f"crt.sh ID: {cert.get('id', 'N/A')}\n"
                f"Common name: {cert.get('common_name', 'N/A')}\n"
                f"Issuer: {cert.get('issuer_name', 'N/A')}\n"
                f"Valid From: {not_before}\n"
                f"Valid Until: {not_after}\n"
                f"Identities: {matching_identities}\n"
            )
            # 将格式化后的字符串添加到列表中
            output_list.append(cert_details_string)
            return "\n".join(output_list)
    except requests.exceptions.RequestException as e:
        return f"查询SSL过程中发生错误: {e}"
    except json.JSONDecodeError:
        return "解析返回数据时出错，可能没有找到任何记录或返回格式不正确"
    except Exception as e:
        return f"获取SSL证书时发生未知错误: {e}"

# 使用BeatifulSoup工具获取网页内容信息，返回文本信息
def get_website_content(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        # print("\nAgent成功获取网页内容信息")
        return soup.get_text()[:2000] # 截取前2000字符以防内容过长
    except Exception as e:
        return f"Error fetching website content: {e}"

# 通过otx平台获取域名威胁情报，返回统计信息
def get_otx_domain_analyses(domain):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
    if not OTX_API_KEY:
        return "错误：OTX API Key 未配置"
    try:
        OTX_SERVER = 'https://otx.alienvault.com/'
        otx = OTXv2(OTX_API_KEY, server=OTX_SERVER)
        alerts = []
        hostname_result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, domain, 'general')
        domain_result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, domain, 'general')
        malware_result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, domain, 'malware')
        validation = getValue(hostname_result, ['validation'])
        if not validation:
            pulses = getValue(hostname_result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        validation = getValue(domain_result, ['validation'])
        if not validation:
            pulses = getValue(domain_result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        if malware_result:
            malware_result = malware_result.get('malware', [])
            for malware in malware_result:
                if 'name' in malware:
                    alerts.append('In malware: ' + malware['name'])
        
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
        return f"Error fetching OTX Analyse: {e}"

# 通过VT平台获取域名安全声誉
def get_vt_domain_report(domain):
    if not os.environ.get("VT_API_KEY"):
        os.environ["VT_API_KEY"] = getpass.getpass("Enter API key for VirusTotal: ")
    VT_API_KEY = os.environ.get("VT_API_KEY")
    if not VT_API_KEY:
        return "错误：VirusTotal API Key 未配置"
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=20)    
        # 检查是否因为权限或无效Key导致请求失败
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        if not data:
            return f"VirusTotal 数据库中没有关于 '{domain}' 的信息。"
        # --- 解析关键信息 ---
        stats = data.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        categories = list(data.get('categories', {}).values())
        # --- 格式化输出报告 ---
        verdict = "低风险"
        if malicious_count > 3:
            verdict = "高风险"
        elif malicious_count > 0 or suspicious_count > 0:
            verdict = "中风险"
        report = (
            f"VirusTotal威胁情报检测结果:\n"
            f"- 评级: {verdict}\n"
            f"- 综合评估: {malicious_count}个安全厂商将其标记为恶意，{suspicious_count}个标记为可疑。\n"
            f"- 网站分类: {', '.join(categories) if categories else '未分类'}\n"
        )
        return report
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return f"VirusTotal 数据库中没有找到域名 '{domain}' 的分析报告。"
        elif e.response.status_code == 401:
             return "错误：VirusTotal API Key 无效或权限不足。"
        return f"访问VirusTotal API时发生HTTP错误: {e}"
    except Exception as e:
        return f"查询VirusTotal时发生未知错误: {e}"

# --------- 缓存相关函数定义 ---------

# 加载缓存函数
def load_cache_from_csv():
    domain_cache = {} # Key: domain, Value: dict with full report info
    try:
        # The file needs to exist to be read
        if not os.path.isfile(CACHE_FILE):
             raise FileNotFoundError
        with open(CACHE_FILE, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            try:
                header = next(reader) # Skip header
            except StopIteration:
                return {} # Return empty dict for empty file
            for row in reader:
                # Ensure the row has enough columns to prevent IndexError
                if row and len(row) >= 5:
                    domain = row[0]
                    # Store the relevant parts of the report in a dictionary
                    domain_cache[domain] = {
                        "status": row[1],
                        "label": row[2] if row[2] else None, # Handle empty string for label
                        "location": row[3] if row[3] else None,
                        "detail": row[4]
                    }
        print(f"成功从 '{CACHE_FILE}' 加载 {len(domain_cache)} 条缓存记录。")
    except FileNotFoundError:
        print(f"缓存文件 '{CACHE_FILE}' 未找到，将自动创建。")
    except IndexError: # Handles malformed row
        print(f"缓存文件 '{CACHE_FILE}' 格式不正确。")
    return domain_cache

# 写入缓存操作
def append_to_cache_csv(domain, status, label, location, detail):
    file_exists = os.path.isfile(CACHE_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(CACHE_FILE, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CACHE_FILE) == 0:
                writer.writerow(CSV_HEADER) # 如果是新文件或空文件，先写入表头
            writer.writerow([domain, status, label, location, detail, timestamp])
    except IOError as e:
        print(f"写入缓存文件 '{CACHE_FILE}' 时发生错误: {e}")

# --------- 初始化函数定义 ---------

# 加载DGA检测训练模型
def load_dga_models():
    try:
        model = joblib.load('ml_model/dga_classifier.pkl')
        scaler_model = joblib.load('ml_model/scaler.pkl')
        print("   - DGA检测模型和标准化器加载成功")
        return model, scaler_model
    except FileNotFoundError:
        print("   - [警告] DGA模型文件未找到。请先运行 'train_dga_model.py'进行训练。DGA检测工具将不可用。")
        return None, None

# 从CSV文件中读取待分析的域名
# def read_domains_to_analyze(file_path):
#     try:
#         with open(file_path, 'r', encoding='utf-8', newline='') as f:
#             reader = csv.reader(f)
#             header = next(reader)
#             domains = [row[0] for row in reader if row and row[0].strip()]
#         print(f"   - 成功从 '{file_path}' 文件中读取 {len(domains)} 个待分析域名。")
#         return domains
#     except FileNotFoundError:
#         print(f"   - [错误] '{file_path}' 未找到。")
#         return []
#     except (StopIteration, IndexError):
#         print(f"   - '{file_path}' 为空或格式不正确。")
#         return []

# 初始化llm
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
    print("   - 初始化本地LLM (qwen3:14b)...")
    return model

# ---------- LangGraph定义 ----------

class DomainReport(BaseModel):
    """最终的域名安全分析报告的结构化输出。"""
    status: Literal["Safe", "Suspicious", "Malicious"] = Field(description="对域名的最终裁决")
    label: Optional[str] = Field(None, description="如果域名是可疑或恶意的，用中文列出一个或多个特定的恶意行为类型，如'钓鱼网站', '垃圾邮件', '远程访问木马', 'C2服务器'，'勒索软件'，'僵尸网络'等，当威胁情报有明确的恶意类型时，需要全部列出。安全域名则为'-'。")
    location: Optional[str] = Field(None, description="用中文列出域名所在的国家或地区")
    detail: str = Field(description="用中文一句话简要总结做出判断的核心原因")

class DomainAnalysisState(TypedDict):
    """图的状态，在节点之间传递信息"""
    domain: str
    otx_report: Optional[str]
    virustotal_report: Optional[str]
    dga_result: Optional[str]
    whois_info: Optional[str]
    dns_ips: Optional[str]
    passive_dns: Optional[str]
    dns_auth: Optional[str]
    ssl_info: Optional[str]
    website_content: Optional[str]
    final_report: Optional[DomainReport] # The final, structured report

# 节点定义

def initial_threat_intel_node(state: DomainAnalysisState) -> dict:
    """节点1：获取初始威胁情报"""
    domain = state["domain"]
    print(f"--- [Node] 获取 {domain} 的初始威胁情报 ---")
    otx_report = get_otx_domain_analyses(domain)
    virustotal_report = get_vt_domain_report(domain)
    whois_info = get_whois_info(domain)
    print(otx_report)
    print(virustotal_report)
    return {
        "whois_info": whois_info,
        "otx_report": otx_report,
        "virustotal_report": virustotal_report
    }

def dga_check_node(state: DomainAnalysisState) -> dict:
    """节点2：进行DGA检测"""
    domain = state["domain"]
    print(f"--- [Node] 对 {domain} 进行DGA检测 ---")
    dga_result = check_dga_with_ml(domain)
    return {"dga_result": dga_result}

def supplementary_info_node(state: DomainAnalysisState) -> dict:
    """节点3：获取补充信息"""
    domain = state["domain"]
    print(f"--- [Node] 为 {domain} 获取补充信息 ---")
    # For a more robust solution, these could be run in parallel
    dns_ips = json.dumps(get_dns_ips(domain), indent=2) # Convert dict to string for display
    passive_dns = json.dumps(get_passive_dns_ips(domain), indent=2)
    dns_auth = json.dumps(get_dns_auth_records(domain), indent=2)
    ssl_info = get_ssl_certificate_info(domain)
    # Add protocol for website content fetching
    url = f"http://{domain}"
    website_content = get_website_content(url)
    return {
        "dns_ips": dns_ips,
        "passive_dns": passive_dns,
        "dns_auth": dns_auth,
        "ssl_info": ssl_info,
        "website_content": website_content
    }

def final_analysis_node(state: DomainAnalysisState) -> dict:
    """节点4：进行最终的综合分析并生成报告 (使用OutputParser适配本地模型)"""
    domain = state["domain"]
    print(f"--- [Node] 对 {domain} 进行最终综合分析 ---")
    
    # 2. 创建一个Pydantic解析器实例
    parser = PydanticOutputParser(pydantic_object=DomainReport)

    # 3. 在Prompt中加入格式化指令
    prompt_context = f"""
你是一名顶尖的网络安全分析师。你已经收集到了关于域名 '{domain}' 的所有情报信息。
请基于下面提供的全部上下文，进行深入分析，判断该域名的性质。

**已收集情报:**
- OTX情报: {state.get('otx_report', '未收集')}
- VirusTotal情报: {state.get('virustotal_report', '未收集')}
- DGA检测: {state.get('dga_result', '未收集')}
- Whois信息: {state.get('whois_info', '未收集')}
- DNS解析与IP信息: {state.get('dns_ips', '未收集')}
- 历史DNS记录: {state.get('passive_dns', '未收集')}
- 邮件安全记录 (MX, SPF, DMARC): {state.get('dns_auth', '未收集')}
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
def should_gather_more_info(state: DomainAnalysisState) -> Literal["gather_supplementary_info", "analyze_directly"]:
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
def run_graph_with_retry(app, domain):
    print("   - 正在调用 LangGraph...")
    response = app.invoke({"domain": domain})
    print("   - LangGraph 调用成功")
    return response

def process_cached_domain(domain, cached_report_data):
        # 从缓存数据重建 DomainReport 对象
        report = DomainReport(
            status=cached_report_data['status'],
            label=cached_report_data['label'],
            location=cached_report_data.get('location'),
            detail=cached_report_data['detail']
        )
        print(f"\n   [缓存命中] '{domain}' 的分析结果已从缓存加载。")
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

def process_uncached_domain(domain):
    print(f"   [缓存未命中] '{domain}' 是新域名，开始执行LangGraph分析...")
    print("\n" + "="*50)
    print(f"   开始分析域名: {domain} ")
    print("="*50)
    start_time = time.perf_counter()

    # 在全局加载一次dga检测机器学习模型
    global dga_model, scaler
    dga_model, scaler = load_dga_models()

    # --- LangGraph Definition ---
    graph = StateGraph(DomainAnalysisState)

    # Add nodes
    graph.add_node("initial_threat_intel", initial_threat_intel_node)
    graph.add_node("dga_check", dga_check_node)
    graph.add_node("supplementary_info", supplementary_info_node)
    graph.add_node("final_analysis", final_analysis_node)

    # Set entry point
    graph.set_entry_point("initial_threat_intel")

    # Add edges
    graph.add_edge("initial_threat_intel", "dga_check")
    graph.add_conditional_edges(
        "dga_check",
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
        final_state = run_graph_with_retry(app, domain)
        report: DomainReport = final_state.get('final_report')

        if not report:
            raise ValueError("未能生成最终报告。")

        # --- Process the structured result ---
        result_output = (
            f"性质: {report.status}\n"
        )
        if report.label:
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
            f.write("\n" + "="*50 + f"\nDomain: {domain}\n" + result_output + "\n" + "="*50 + "\n")
        
        print(f"   [更新缓存] 将 '{domain}' 标记为 '{report.status}' 并写入缓存。")
        append_to_cache_csv(domain, report.status, report.label, report.location, report.detail)
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"\n运行时间: {duration:.2f} 秒")
        print("\n" + "="*50)
        return report

    except Exception as e:
        error_message = f"在分析域名 {domain} 时发生严重错误: {e}"
        print(error_message)
        # Optionally log the full state for debugging
        print("--- ERROR STATE ---", final_state)
        return "ERROR"

if __name__ == "__main__":
    # if len(sys.argv) > 1:
    #     domain = sys.argv[1].strip()
    # else:
    #     domain = input("请输入要查询的域名: ").strip()
    
    required_keys = ["VT_API_KEY", "OTX_API_KEY"]
    missing_keys = [key for key in required_keys if not os.environ.get(key)]
    
    if missing_keys:
        print(f"错误: 以下环境变量未设置，程序无法继续: {', '.join(missing_keys)}")
        print("请在运行前设置好API密钥。")
        sys.exit(1) # 程序直接退出
    
    # 批量读取csv文件中的所有域名
    csv_path = os.path.join(os.path.dirname(__file__), INPUT_FILE)
    domains = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].strip():
                # 只取第一列，去除前后空白
                domain = row[0].strip()
                # 如果是URL，提取主域名部分，否则直接用
                if domain.startswith('http://') or domain.startswith('https://'):
                    domain = domain.split('//', 1)[1].split('/')[0]
                domains.append(domain)
    
    print(f"共读取到 {len(domains)} 个待分析域名。\n")
    domain_cache = load_cache_from_csv()
    for idx, domain in enumerate(domains, 1):
        print(f"\n===== 正在分析第 {idx}/{len(domains)} 个域名: {domain} =====\n")
        if domain in domain_cache:
            cached_report_data = domain_cache[domain]
            process_cached_domain(domain, cached_report_data)
        else:
            process_uncached_domain(domain)
    print("\n所有域名分析完成。程序结束。\n")