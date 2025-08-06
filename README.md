# 智能域名安全分析Agent 项目说明文档

## 1. 项目简介

本项目是一个基于大型语言模型（LLM）和多工具集成的智能 Agent ，旨在自动化地对域名和ip进行全面准确快速的安全分析和风险评估,支持批量分析、缓存复用、知识库扩展，适合安全研究与自动化检测场景。本项目包含两个核心脚本：agent_domain.py 和 agent_ip.py。它们是基于大型语言模型（LLM）和 LangGraph 框架构建的自动化网络威胁情报分析工具。

agent_domain.py: 专注于对域名进行全方位安全分析，评估其是否为恶意域名（如钓鱼网站、C2服务器、DGA域名等）。
agent_ip.py: 专注于对IP地址进行综合安全研判，评估其是否与恶意活动相关。

## 2. 技术框架

### 开发框架Langchain介绍

LangChain 几乎可以作为所有 LLM 的通用接口，为构建 LLM 应用程序并将其与外部数据源和软件工作流程集成提供集中式开发环境。LangChain可以简单理解为是 LLM 领域的 Spring。该框架由几个部分组成：

- LangChain 库：Python 和 JavaScript 库。包含无数组件的接口和集成、将这些组件组合成链和代理的基本运行时，以及链和代理的现成实现。
- LangChain 模板：一系列易于部署的参考架构，适用于各种任务。
- LangServe：用于将 LangChain 链部署为 REST API 的库。
- LangSmith：用于调试、测试的开发者平台。

### Agent框架

本项目采用了LangGraph架构构建Agent。LangGraph是一个开源Agent框架（MIT-licensed），用于构建、管理和部署长时间运行、有状态的智能体。相比于其他框架，LangGraph提供了一个更显性的框架来处理特定任务，这不会将开发者限制在单一的黑盒认知架构中。

## 3. 工具模块详解

### 3.1 域名分析工具 (agent_domain.py)

Agent在分析域名时，会调用以下工具函数来获取所需的信息：

威胁情报工具：

- **`get_otx_domain_analyses(domain)`**：调用OTX开放平台API，获取平台收集的威胁情报脉搏，识别域名是否在已知威胁情报中。
- **`get_vt_domain_report(domain)`**：调用VirusTotal API，获取多个安全厂商对域名的检测结果和综合安全评分。

DNS与网络分析工具：

- **`get_dns_ips(domain)`**：解析域名指向的IP地址，获取A记录、CNAME记录，并通过ip-api.com获取IP的地理位置、所属ISP等信息。
- **`get_passive_dns_ips(domain)`**：通过OTX平台获取域名的历史IP地址记录，发现域名是否频繁更换IP地址。
- **`get_dns_auth_records(domain)`**：查询域名的DNS认证记录，包括MX记录、SPF记录、DMARC记录、DKIM记录，用于判断域名的邮件安全配置。

机器学习检测工具：

- **`check_dga_with_ml(domain)`**：调用本地训练好的机器学习模型，判断域名字符串是否符合DGA（域名生成算法）特征，识别算法生成的恶意域名。

证书与安全分析工具：

- **`get_ssl_certificate_info(domain)`**：获取域名的SSL/TLS证书信息，包括证书颁发者(Issuer)、使用者(Subject)、有效期、证书链等，判断证书的合法性和安全性。

内容分析工具：

- **`get_website_content(url)`**：获取目标URL首页的纯文本内容，使用BeautifulSoup解析HTML，提取文本内容用于分析网站内容，识别钓鱼页面或恶意内容。

注册信息工具：

- **`get_whois_info(domain)`**：查询域名的Whois注册信息，包括注册人、注册商、创建时间、过期时间、域名服务器等，判断域名注册信息的真实性。

### 3.2 IP地址分析工具 (agent_ip.py)

Agent在分析IP地址时，会调用以下工具函数来获取所需的信息：

威胁情报工具：

- **`get_otx_ip_analyses(ip_address)`**：从OTX平台获取IP的威胁情报，查询IP是否在已知威胁情报中，获取IP的威胁等级评估。
- **`get_vt_ip_report(ip_address)`**：从VirusTotal获取IP的安全声誉，查询多个安全厂商对IP的检测结果，获取IP的综合安全评分。

网络拓扑分析工具：

- **`get_whois_info(ip_address)`**：获取IP地址的Whois信息，包括国家、组织、ASN、IP地址等，了解IP的地理位置和归属。
- **`get_reverse_dns_domains(ip_address)`**：通过OTX进行反向DNS查询，发现与该IP关联的历史域名，识别共享基础设施的恶意活动。

连接安全分析工具：

- **`get_ssl_certificate_info(ip_address)`**：直接连接IP获取SSL证书信息，建立SSL连接获取证书详情，判断IP的SSL配置安全性。
- **`get_website_content(ip_address)`**：从IP地址获取网页内容，尝试HTTP和HTTPS连接提取网页文本，分析IP上托管的网站内容。

## 4. 域名数据

域名测试数据来源：  
`https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/blob/master/data/data.csv`  

## 5. 使用指南

### 5.1 环境准备与安装

Python版本：Python 3.9+
安装所需Python库：  
`pip install --no-cache-dir -r requirements.txt`

### 5.2 API密钥配置

本项目需要以下API密钥，请在首次运行时根据提示输入，或预先设置为环境变量：

- `OTX_API_KEY`：用于调用OTX的威胁情报服务。
- `VT_API_KEY`：用于调用VirusTotal的威胁情报服务。
- `GOOGLE_API_KEY`：用于调用Google Gemini模型。
- `DASHSCOPE_API_KEY`：用于阿里百炼模型平台，调用通义千问和Deepseek模型。
- `DASHSCOPE_API_KEY`：用于调用智谱GLM模型。

**设置环境变量示例:**  

- Linux/macOS：  
    `export OTX_API_KEY="your_otx_api_key_here"`
    `export VT_API_KEY="your_virustotal_api_key_here"`
    `export GOOGLE_API_KEY="your_google_api_key_here"`  
    `export DASHSCOPE_API_KEY="your_tongyi_api_key_here"`  
    `export ZHIPUAI_API_KEY="your_zhipu_api_key_here"`  

- Windows:  
    `$env:OTX_API_KEY="your_otx_api_key_here"`
    `$env:VT_API_KEY="your_virustotal_api_key_here"`
    `$env:GOOGLE_API_KEY="your_google_api_key_here"`  
    `$env:DASHSCOPE_API_KEY="your_tongyi_api_key_here"`  
    `$env:ZHIPUAI_API_KEY="your_zhipu_api_key_here"`  

### 5.3 DGA模型训练

为了使用的DGA检测功能，在运行agent前需要先训练模型：

1. 创建 `legit_domains.txt` 和 `dga_domains.txt` 文件，并填入相应的训练样本（每行一个域名）。
2. 运行训练脚本： `python train_dga_model.py`
3. 成功后，会在项目下生成一个 `ml_model` 文件夹，内含 `dga_classifier.pkl` 和 `scaler.pkl` 两个模型文件。

### 5.4 运行分析

1. 创建并编辑 `domains.csv` 文件，。请确保第一行是表头 `domain`，后续每行一个待分析的域名。  

    **`domains.csv` 示例:**

        |    domain    |
        |  google.com  |
        |  github.com  |

2. 运行主程序：  
    `python main.py`  
3. 程序将开始执行分析。分析过的域名及其结果会自动记录在 `domain_analysis_cache.csv` 文件中，下次运行时将自动跳过。

## 6. 模型设置

LLM选型：

- **Google gemini-2.0-flash**（推荐）：可调用工具，速度快，需翻墙 *（价格：免费）*  
- **通义千问 qwen-turbo**（推荐）：可调用工具，速度中等 *（价格：输入 0.0008元/千token，输出 0.002/千token）*  
- **通义千问 qwen-plus**：可调用工具，推理性能好，速度稍慢 *（价格：输入 0.0003元/千token，输出 0.0006/千token）*  
- **智谱GLM-4**：支持工具调用 *（价格：免费）*  
- **deepseek-r1**：不支持工具调用  
- **deepseek-v3**：支持工具调用  

参数设置：  
Temperature（温度参数）是控制AI生成文本随机性的关键参数，取值范围通常为0到1（部分模型支持更高），在本项目中建议设置为0.1，保证文字输出的稳定性。

## 7. 项目文件结构

    /Agent_URL/
    |  
    |-- main.py                   # Agent主程序脚本  
    |-- train_dga_model.py        # DGA模型训练脚本  
    |
    |-- /data/  
    |   |-- domains.csv           # 待分析的域名列表
    |   |-- cache.csv             # 缓存已分析的域名列表
    |   |-- legit_domains.txt     # 用于训练的合法域名列表
    |   |-- dga_domains.txt       # 用于训练的DGA域名列表
    |  
    |-- /ml_model/                # (自动生成) 存放机器学习模型文件  
    |   |-- dga_classifier.pkl  
    |   |-- scaler.pkl  
    |  
    |-- prompt.txt                # 存放Agent的prompt提示词文本  
    |-- output.txt                # 记录Agent回答的输出文件  
    |-- README.md                 # 本说明文档  

## 8. 优化方向

- **增加更多工具**：例如SSL证书分析 *(6/12:已增加)*、资产测绘等。
- **IP地址反查域名**：通过反查域名所属ip地址的其他域名，深入分析域名的恶意可能性。
- **加入MCP**： 通过MCP扩展更多功能，如资产测绘。
- **结合研究院自有数据库**：将研究院数据库进行集成，允许Agent通过数据库中ip的相关信息进行分析。
- **异构信息网络 (HIN) 或图分析**：识别阴影域名、共享基础设施的DGA域名等高级威胁。
- **进程行为关联**：将进程信息（进程名、父进程、执行路径、启动时间等）作为新的节点类型加入HIN，或者作为域名行为特征的一部分。

## 9. 版本

- v0.5：增加证书分析工具，获取ip地址工具从原有的socket方法改为dns库的resolver
- v0.6：增加通义千问qwen-plus和qwen-turbo的模型选择
- v0.7：优化prompt和输出，增加运行时间计时
- v1.0：增加VirusTotal工具，可以获取域名的安全情报，提高对恶意域名判断的准确性
- v1.1：优化注释信息和函数名等代码细节
- v1.2：修复缓存记录错误bug,将有请求限额的VirusTotal平台改为免费无限额的OTX平台进行威胁情报分析
- v1.3：增加查询历史ip地址记录工具，将SSL工具优化增加查询历史ssl的功能，优化prompt的思路，让Agent能够更好识别出恶意域名的种类
- v2.0: 搭建知识库，增加恶意IP
- v4.0：更换框架，使用LangGraph取代ReACT Agent框架
- v4.5: 增加ip的whois信息

## 10.问题记录

- OTX访问不稳定
- 本地大模型LLM输出格式不稳定
- 缓存格式问题（已解决）
- 调用api安全认证（已解决）
- 标签不够准确
- 解决网络代理问题导致输出异常问题
- 增加AbuseIPDB威胁平台
