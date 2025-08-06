import csv
import random
import os
import getpass
from google.api_core.exceptions import Unknown
import requests
import OTXv2
import IndicatorTypes
from sqlalchemy import true
from sqlalchemy.sql import false


input_file = 'evaluation_domain/groundtruth.csv'
output_benign = 'evaluation_domain/benign_list_new.csv'
output_malicious = 'evaluation_domain/malicious_list_new.csv'

benign_domains = []
malware_domains = []
phishing_domains = []

# 读取数据并分类
with open(input_file, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        label = row['label'].strip().lower()
        domain = row['domain'].strip()
        if label == 'benign':
            benign_domains.append(domain)
        elif label == 'malware':
            malware_domains.append(domain)
        elif label == 'phishing':
            phishing_domains.append(domain)

# 随机采样
benign_sample = random.sample(benign_domains, min(3000, len(benign_domains)))
malware_sample = random.sample(malware_domains, min(995, len(malware_domains)))
phishing_sample = random.sample(phishing_domains, min(2005, len(phishing_domains)))

# 写入 benign_list.csv
with open(output_benign, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    for domain in benign_sample:
        writer.writerow([domain])

# 写入 malicious_list.csv
with open(output_malicious, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    for domain in malware_sample:
        writer.writerow([domain])
    for domain in phishing_sample:
        writer.writerow([domain])

print(f"已生成 {output_benign} 和 {output_malicious}")