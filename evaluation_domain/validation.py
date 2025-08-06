import csv
import ipaddress
from urllib.parse import urlparse
import os
import getpass
from OTXv2 import OTXv2
import IndicatorTypes
import requests

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

# 通过otx平台获取域名威胁情报，返回统计信息
def get_otx_domain_analyses(domain):
    if not os.environ.get("OTX_API_KEY"):
        os.environ["OTX_API_KEY"] = getpass.getpass("Enter API key for OTX: ")
    OTX_API_KEY = os.environ.get("OTX_API_KEY")
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
                        alerts.append(pulse['name'])
        validation = getValue(domain_result, ['validation'])
        if not validation:
            pulses = getValue(domain_result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append(pulse['name'])
        if malware_result:
            malware_result = malware_result.get('malware', [])
            for malware in malware_result:
                if 'name' in malware:
                    alerts.append(malware['name'])
        result = False
        if len(alerts) > 5:
            result = True
        return result
    except Exception as e:
        return False

# 通过VT平台获取域名安全声誉
def get_vt_domain_report(domain):
    if not os.environ.get("VT_API_KEY"):
        os.environ["VT_API_KEY"] = getpass.getpass("Enter API key for VirusTotal: ")
    VT_API_KEY = os.environ.get("VT_API_KEY")
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
        result = False
        if malicious_count > 3:
            result = True  
        return result
    except requests.exceptions.HTTPError as e:
        return False

# --- 主程序 ---

# 1. 定义输入和输出文件名
input_file_name = 'evaluation_domain/urlhaus_domains.csv'
output_file_name = 'evaluation_domain/malicious_list_domains.csv'
cache_file_name = 'evaluation_domain/cache_domains.csv'

# 2. 初始化用于去重的集合
seen_hostnames = set()
try:
    # 3. 使用 'with' 语句安全地打开所有文件
    with open(cache_file_name, mode='r', encoding='utf-8', newline='') as cache_file:
        csv_reader = csv.DictReader(cache_file)
        for row in csv_reader:
            hostname = row['domain_name']
            seen_hostnames.add(hostname)
except Exception as e:
    print(f"读取缓存文件过程中发生错误: {e}")

# 初始化计数器
processed_rows = 0

print(f"准备从文件 '{input_file_name}' 读取数据...")

try:
    # 3. 使用 'with' 语句安全地打开所有文件
    with open(input_file_name, mode='r', encoding='utf-8', newline='') as infile, \
         open(output_file_name, mode='a', encoding='utf-8', newline='') as outfile, \
         open(cache_file_name, mode='a', encoding='utf-8', newline='') as cache_file:

        # 使用 DictReader 可以通过列名（如 'url'）来访问数据
        csv_reader = csv.DictReader(infile)
        # 为输出文件创建写入器并写入表头
        writer = csv.writer(outfile)
        cache_writer = csv.writer(cache_file)
        writer.writerow(['domain_name'])
        cache_writer.writerow(['domain_name'])

        print("开始处理数据，去重后分类写入文件...")

        # 4. 遍历输入文件的每一行
        for row in csv_reader:
            processed_rows += 1
            hostname = row['domain_name']
            if hostname:
                    # 检查域名是否已经见过，如果没见过，则写入并添加到集合
                    if hostname not in seen_hostnames:
                        if get_otx_domain_analyses(hostname) or get_vt_domain_report(hostname):
                            writer.writerow([hostname])
                            seen_hostnames.add(hostname)
                            print(f"✅  {hostname} 验证成功")
                        else:
                            print(f"❌  {hostname} 验证失败")
                        cache_writer.writerow([hostname])
    print("\n处理完成！")
    print(f"总共处理了 {processed_rows} 行数据。")

except FileNotFoundError:
    print(f"错误: 输入文件 '{input_file_name}' 未找到！")
    print("请确保您的数据文件与脚本在同一个目录下，或者文件名已正确填写。")
except KeyError as e:
    print(f"错误: CSV文件中缺少必需的列: {e}。")
except Exception as e:
    print(f"处理过程中发生未知错误: {e}")