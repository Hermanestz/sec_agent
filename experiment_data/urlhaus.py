import csv
import ipaddress
from urllib.parse import urlparse

def extract_hostname(url_string):
    """
    从一个URL字符串中解析并提取主机名（域名或IP地址）。
    """
    if not url_string:
        return None
    try:
        # urlparse能够将URL分解为多个部分
        # .hostname属性可以直接获取域名或IP地址
        parsed_url = urlparse(url_string)
        return parsed_url.hostname
    except Exception as e:
        print(f"警告：无法解析格式错误的URL '{url_string}': {e}")
        return None

def is_ip_address(hostname):
    """
    检查一个字符串是否是有效的IP地址 (IPv4 或 IPv6)。
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

# --- 主程序 ---

# 1. 定义输入和输出文件名
input_file_name = 'evaluation_domain/urlhaus.csv'
ips_output_file = 'evaluation_domain/urlhaus_ips.csv'
domains_output_file = 'evaluation_domain/urlhaus_domains.csv'

# 2. 初始化用于去重的集合
seen_ips = set()
seen_domains = set()

# 初始化计数器
processed_rows = 0

print(f"准备从文件 '{input_file_name}' 读取数据...")

try:
    # 3. 使用 'with' 语句安全地打开所有文件
    with open(input_file_name, mode='r', encoding='utf-8', newline='') as infile, \
         open(ips_output_file, mode='w', encoding='utf-8', newline='') as ip_file, \
         open(domains_output_file, mode='w', encoding='utf-8', newline='') as domain_file:

        # 使用 DictReader 可以通过列名（如 'url'）来访问数据
        csv_reader = csv.DictReader(infile)
        
        # 为输出文件创建写入器并写入表头
        ip_writer = csv.writer(ip_file)
        domain_writer = csv.writer(domain_file)
        ip_writer.writerow(['ip_address'])
        domain_writer.writerow(['domain_name'])

        print("开始处理数据，去重后分类写入文件...")

        # 4. 遍历输入文件的每一行
        for row in csv_reader:
            processed_rows += 1
            # URLhaus的CSV转储文件可能包含以'#'开头的评论行，跳过它们
            if row['id'].startswith('#'):
                continue
            
            hostname = extract_hostname(row['url'])

            if hostname:
                # 5. 判断是IP还是域名
                if is_ip_address(hostname):
                    # 检查IP是否已经见过，如果没见过，则写入并添加到集合
                    if hostname not in seen_ips:
                        ip_writer.writerow([hostname])
                        seen_ips.add(hostname)
                else:
                    # 检查域名是否已经见过，如果没见过，则写入并添加到集合
                    if hostname not in seen_domains:
                        domain_writer.writerow([hostname])
                        seen_domains.add(hostname)
    
    print("\n处理完成！")
    print(f"总共处理了 {processed_rows} 行数据。")
    # 使用 len(set) 来获取最终的独立条目数
    print(f"✅ 成功将 {len(seen_ips)} 个独立IP地址保存到 '{ips_output_file}'")
    print(f"✅ 成功将 {len(seen_domains)} 个独立域名保存到 '{domains_output_file}'")

except FileNotFoundError:
    print(f"错误: 输入文件 '{input_file_name}' 未找到！")
    print("请确保您的数据文件与脚本在同一个目录下，或者文件名已正确填写。")
except KeyError as e:
    print(f"错误: CSV文件中缺少必需的列: {e}。")
    print("请确保您的CSV文件包含一个名为 'url' 的表头。")
except Exception as e:
    print(f"处理过程中发生未知错误: {e}")