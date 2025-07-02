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
# INPUT_FILE = 'data/domains.csv'
CACHE_FILE = 'data/cache_domain.csv'
CSV_HEADER = ['domain', 'label', 'timestamp']  # 定义CSV文件的表头
LOG_FILE = 'log_domain.txt'
PROMPT_FILE = 'prompt_domain.txt'
KNOWLEDGE_BASE_DIR = 'knowledge_base'
PERSIST_DIRECTORY = 'db_domain'

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
    try:
        OTX_API_KEY = 'd65a1499bb1a9f13f205246063662f937cf76f94e5f2e4e15ef428ee8c66fbcb'
        OTX_SERVER = 'https://otx.alienvault.com/'
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
                f"------------------------------------------------------------\n"
                f"crt.sh ID:      {cert.get('id', 'N/A')}\n"
                f"通用名称:       {cert.get('common_name', 'N/A')}\n"
                f"颁发机构:       {cert.get('issuer_name', 'N/A')}\n"
                f"生效日期:       {not_before}\n"
                f"过期日期:       {not_after}\n"
                f"匹配的身份:     {matching_identities}\n"
                f"------------------------------------------------------------"
            )
            # 将格式化后的字符串添加到列表中
            output_list.append(cert_details_string)
            return "\n".join(output_list)
    except requests.exceptions.RequestException as e:
        return f"查询过程中发生错误: {e}"
    except json.JSONDecodeError:
        return "解析返回数据时出错，可能没有找到任何记录或返回格式不正确。"
    except KeyboardInterrupt:
        return "\n程序已由用户终止。"
    except Exception as e:
        return f"发生未知错误: {e}"

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
        return "错误：VirusTotal API Key 未配置"
    try:
        OTX_SERVER = 'https://otx.alienvault.com/'
        otx = OTXv2(OTX_API_KEY, server=OTX_SERVER)
        alerts = []
        result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, domain, 'general')
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        if len(alerts) > 0:
            return('检测到威胁情报：' + str(alerts))
        else:
            return('未检测到威胁情报')
    except Exception as e:
        return f"Error fetching OTX Analyse: {e}"

# 通过VT平台获取域名安全声誉
def get_comprehensive_domain_report(domain):
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
        harmless_count = stats.get('harmless', 0)
        categories = list(data.get('categories', {}).values())
        # --- 格式化输出报告 ---
        verdict = "【低风险】"
        if malicious_count > 3:
            verdict = "【高风险】"
        elif malicious_count > 0 or suspicious_count > 0:
            verdict = "【中度风险/可疑】"
        report = (
            f"VirusTotal安全声誉:\n"
            f"- 综合评估: {verdict}{malicious_count}个安全厂商将其标记为恶意，{suspicious_count}个标记为可疑。\n"
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
    domain_cache = {} # 使用字典存储，key为domain，value为status
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            header = next(reader) # 跳过表头
            for row in reader:
                if row:
                    domain_cache[row[0]] = row[1] # domain -> status
        print(f"成功从 '{CACHE_FILE}' 加载 {len(domain_cache)} 条缓存记录。")
    except FileNotFoundError:
        print(f"缓存文件 '{CACHE_FILE}' 未找到，将自动创建。")
    except (StopIteration, IndexError): # 文件为空或行数据不完整
        print(f"缓存文件 '{CACHE_FILE}' 为空或格式不正确。")
    return domain_cache

# 写入缓存操作
def append_to_cache_csv(domain, status):
    file_exists = os.path.isfile(CACHE_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(CACHE_FILE, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CACHE_FILE) == 0:
                writer.writerow(CSV_HEADER) # 如果是新文件或空文件，先写入表头
            writer.writerow([domain, status, timestamp])
    except IOError as e:
        print(f"写入缓存文件 '{CACHE_FILE}' 时发生错误: {e}")

# --------- 初始化函数定义 ---------

# 初始化RAG检索器
def setup_rag_retriever(llm):
    # Check if knowledge base directory exists
    if not os.path.exists(KNOWLEDGE_BASE_DIR):
        print(f"   - [警告] 知识库目录 '{KNOWLEDGE_BASE_DIR}' 未找到。RAG工具将不可用。")
        return None

    # --- NEW: Manual loading loop to bypass DirectoryLoader/Unstructured issues ---
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

    # Split documents into chunks
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    texts = text_splitter.split_documents(loaded_documents)

    # Create embeddings
    print("   - 正在初始化嵌入模型 (这可能需要一些时间)...")
    # 使用HuggingFaceEmbeddings开源嵌入模型
    embeddings = HuggingFaceEmbeddings(model_name='sentence-transformers/all-MiniLM-L6-v2')
    # 使用本地部署的nomic-embed-text开源嵌入模型（具有较大的标记上下文窗口）
    # embeddings = OllamaEmbeddings(model="nomic-embed-text")

    # Create and persist a Chroma vector store
    print("   - 正在创建并持久化向量数据库...")
    db = Chroma.from_documents(texts, embeddings, persist_directory=PERSIST_DIRECTORY)
    db.persist()

    # Create the retriever
    retriever = db.as_retriever(search_kwargs={"k": 2})  # Retrieve top 2 relevant chunks

    # Create the RetrievalQA chain
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=retriever,
        return_source_documents=True
    )

    print("   - RAG检索器设置成功。")
    return qa_chain

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

# 从CSV文件中读取待分析的URL
def read_domains_to_analyze(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)
            domains = [row[0] for row in reader if row and row[0].strip()]
        print(f"   - 成功从 '{file_path}' 文件中读取 {len(domains)} 个待分析域名。")
        return domains
    except FileNotFoundError:
        print(f"   - [错误] 域名文件 '{file_path}' 未找到。")
        return []
    except (StopIteration, IndexError):
        print(f"   - 域名文件 '{file_path}' 为空或格式不正确。")
        return []

# 初始化llm
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

# ---------- 重要函数定义 ----------

# 处理单个域名的分析流程
def process_domain_analysis(domain, agent, domain_cache):

    # 进行缓存检查
    if domain in domain_cache:
        status = domain_cache[domain]
        if status == 'safe':
            print(f"   [缓存命中] '{domain}' 是已知的安全域名，跳过分析。")
        elif status == 'malicious':
            print(f"   [缓存命中] '{domain}' 是已知的恶意域名，跳过分析。")
        else:
            print(f"   [缓存命中] '{domain}' 是已知的可疑域名，跳过分析。")
        return status
    
    print(f"   [缓存未命中] '{domain}' 是新域名，开始执行Agent分析...")
    # print("\n" + "="*50)
    print(f"🚀 开始分析域名: {domain} 🚀")
    # print("="*50)
    start_time = time.perf_counter()

    with open(PROMPT_FILE, 'r', encoding='utf-8') as file:
        prompt_template = file.read()
    
    # 将域名插入到prompt
    prompt = prompt_template.format(domain=domain)

    try:
        response = run_agent_with_retry(agent, prompt)
        result_output = response.get('output', '未能获取到输出。')
        print("="*50)
        # print("\nAgent的最终回答")
        print(result_output)
        print("\n" + "="*50)

        original_stdout = sys.stdout
        # 将结果记录在txt输出文件
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
        # 将 stdout 重定向到文件
            sys.stdout = f
            # 你的所有 print 语句都会写入到文件中
            print("\n" + "="*50)
            print(result_output)
            print("="*50)
        # 恢复原始的 stdout，这样后续的 print 语句会回到控制台
        sys.stdout = original_stdout

        # 更新缓存
        if "高风险（恶意域名）" in result_output:
            status = 'malicious'
            print(f"   [更新缓存] 将 '{domain}' 标记为 '{status}' 并写入缓存。")
            append_to_cache_csv(domain, status)
            domain_cache[domain] = status
        elif "低风险（安全域名）" in result_output:
            status = 'safe'
            print(f"   [更新缓存] 将 '{domain}' 标记为 '{status}' 并写入缓存。")
            append_to_cache_csv(domain, status)
            domain_cache[domain] = status
        else:
            status = 'suspicious'
            print(f"   [更新缓存] 将 '{domain}' 标记为 '{status}' 并写入缓存。")
            append_to_cache_csv(domain, status)
            domain_cache[domain] = status
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"\n✅ 域名 {domain} 分析完成")
        print(f"运行时间: {duration:.2f} 秒")
        print("\n" + "="*50)
        return status

    except Exception as e:
        error_message = f"在分析域名 {domain} 时发生严重错误: {e}"
        print(error_message)
        return error_message

# 退避函数（防止超过限额）
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

# ------------- 主函数 -------------

def start_with_domain(domain):
    # 初始化大模型
    model = initialize_llm()

    # 加载RAG检索器
    rag_qa_chain = setup_rag_retriever(model)

    # 在全局加载一次dga检测机器学习模型
    global dga_model, scaler
    dga_model, scaler = load_dga_models()

    # 创建工具列表
    tools = [
        Tool(
            name="DGA Detection ML Model",
            func=check_dga_with_ml,
            description="(基础工具)使用机器学习模型判断一个域名字符串本身是否符合DGA（域名生成算法）特征。由于目前高级算法能有效规避 DGA 检测，因此检测结果有误判的可能。输入应为一个域名，例如 'example.com'。"
        ),
        Tool(
            name="Whois Information Fetcher",
            func=get_whois_info,
            description="(基础工具)查询一个域名的注册信息。返回信息包含了含域名的注册时间以及域名注册商、注册人等信息。输入应为一个域名，例如 'example.com'。"
        ),
        Tool(
            name="DNS IP Resolver",
            func=get_dns_ips, 
            description="(基础工具)用于查找一个域名当前解析到的所有IPv4地址(包括A记录和CNAME记录)并获取这些IP地址的详细地理位置和ISP（互联网服务提供商）信息。成功时返回所有IP的相关信息。输入应为一个域名，例如 'example.com'。"
        ),
        Tool(
            name="Passive DNS Fetcher",
            func=get_passive_dns_ips,
            description="(基础工具)获取域名的过去解析到的IP地址历史，正常情况会返回包含这些IP地址和相关标签的列表，输入为一个域名"
        ),
        Tool(
            name="DNS Record Fetcher",
            func=get_dns_auth_records,
            description="(基础工具)获取并分析DNS记录MX,SPF,DMARC配置情况。输入应该是一个域名。"
        ),
        Tool(
            name="SSL Certificate Analyzer",
            func=get_ssl_certificate_info,
            description="(基础工具)获取并分析指定域名的SSL/TLS证书信息。用于检查网站的加密配置是否安全。证书由不受信任的机构颁发、信息不匹配或即将/已经过期都是危险信号。输入应该是一个域名。"
        ),
        Tool(
            name="Website Content Fetcher",
            func=get_website_content,
            description="(基础工具)获取一个URL主页的文本内容。用于分析网站的实际用途、寻找可疑关键词（如钓鱼、诈骗）或判断网站是否为空内容。输入应为一个完整的URL，例如 'https://example.com'。"
        ),
        Tool(
            name="OTX Domain Analyses",
            func=get_otx_domain_analyses,
            description="(基础工具)通过OTX威胁情报共享平台获取一个域名的威胁情报，当有相关情报时输出内容中每个脉冲（pulse）包含一组相关的威胁指标和描述信息，输入为一个域名"
        ),
        Tool(
            name="VirusTotal Domain Analyzer",
            func=get_comprehensive_domain_report,
            description="(拓展工具)通过VirusTotal专业威胁情报平台获取一个域名的安全声誉，当第二步分析不能确定域名是恶意域名也不能确定域名是安全域名时，才需要使用该工具来判断域名是否恶意，输入为一个域名"
        )
    ]

    # --- RAG Tool Integration ---
    # Add the RAG tool to the list if it was set up successfully
    if rag_qa_chain:
        def run_rag_chain(query: str):
            # Helper function to properly invoke the chain and format the output
            result = rag_qa_chain({"query": query})
            source_docs = "\n".join([f"Source: {doc.metadata.get('source', 'Unknown')}" for doc in result['source_documents']])
            return f"Retrieved Information:\n{result['result']}\n\nSources:\n{source_docs}"

        rag_tool = Tool(
            name="Knowledge Base Retriever",
            func=run_rag_chain,
            description="从内部知识库中检索与查询相关的信息。当你需要关于特定威胁、攻击活动、或分析技术的背景知识时使用它。例如，你可以查询 'QuickFlip phishing campaign' 或 'DataSnatcher trojan' 来获取上下文信息。"
        )
        tools.insert(0, rag_tool) # Insert at the beginning to encourage its use


    # 初始化 Agent
    agent = initialize_agent(
        tools,
        model,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,   # 展示完整思维链
        handle_parsing_errors="Check your output and make sure it conforms!"   # 添加自我纠错机制，防止输出的parsing error导致程序崩溃
    )
    
    domain_cache = load_cache_from_csv()
    result = process_domain_analysis(domain, agent, domain_cache)
    return result

if __name__ == "__main__":
    domain = input("请输入要查询的域名 (例如: google.com): ").strip()
    start_with_domain(domain)