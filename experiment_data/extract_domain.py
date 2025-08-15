import csv
import re

def extract_domain(url):
    # 去除协议头
    url = url.strip()
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    # 检查是否有斜杠且斜杠后面不为空
    if '/' in url:
        parts = url.split('/', 1)
        if len(parts) > 1 and parts[1].strip() != '':
            return None
        domain = parts[0]
    else:
        domain = url
    domain = domain.split(':')[0].split('?')[0]
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        return domain.lower()
    return None

input_file = r'D:\TeleResearch_GZ\SEC_AGENT\experiment_data\PhishTank.csv'
output_file = r'D:\TeleResearch_GZ\SEC_AGENT\experiment_data\phish_domains.csv'

# 用集合去重，key为 (domain, label)
domain_info_set = set()

with open(input_file, 'r', encoding='utf-8') as infile:
    reader = csv.reader(infile)
    header = next(reader, None)  # 跳过表头
    for row in reader:
        if row and row[0].strip():
            domain = extract_domain(row[0])
            label = row[1].strip() if len(row) > 1 else ''
            if domain:
                domain_info_set.add((domain, label))

with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
    writer = csv.writer(outfile)
    writer.writerow(['domain', 'label'])  # 新表头
    for domain, label in sorted(domain_info_set):
        writer.writerow([domain, label])

print("域名和信息筛选与提取完成，已保存到 domain.csv")