import pandas as pd
import numpy as np
import ipaddress
import random
import string
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score, classification_report, accuracy_score
import os
from langchain_ollama import OllamaLLM

# import matplotlib.pyplot as plt
# import matplotlib.dates as mdates

# 设置中文显示
# plt.rcParams['font.sans-serif'] = ['SimHei']
# plt.rcParams['axes.unicode_minus'] = False

def get_entropy(s):
    if not s:
        return 0
    p = Counter(s)
    entropy = -sum(count / len(s) * np.log2(count / len(s)) for count in p.values())
    return entropy

def get_vowel_consonant_ratio(s):
    s = s.lower()
    vowels = "aeiou"
    vowel_count = sum(1 for char in s if char in vowels)
    consonant_count = sum(1 for char in s if char.isalpha() and char not in vowels)
    if consonant_count == 0:
        return vowel_count / 1.0 # 避免除以零
    return vowel_count / consonant_count

def get_digit_ratio(s):
    if not s:
        return 0
    digit_count = sum(1 for char in s if char.isdigit())
    return digit_count / len(s)

def get_longest_consecutive_chars(s, char_type='alpha'):
    max_len = 0
    current_len = 0
    for i in range(len(s)):
        is_target = False
        if char_type == 'alpha' and s[i].isalpha():
            is_target = True
        elif char_type == 'digit' and s[i].isdigit():
            is_target = True
        if is_target:
            current_len += 1
        else:
            max_len = max(max_len, current_len)
            current_len = 0
    max_len = max(max_len, current_len) # 处理字符串末尾的连续字符
    return max_len

def extract_features(domain):
    domain = str(domain).lower() # 确保是字符串并转小写
    features = {
        'length': len(domain),
        'entropy': get_entropy(domain),
        'vowel_consonant_ratio': get_vowel_consonant_ratio(domain),
        'digit_ratio': get_digit_ratio(domain),
        'longest_consecutive_digits': get_longest_consecutive_chars(domain, 'digit'),
        'longest_consecutive_consonants': get_longest_consecutive_chars(domain, 'alpha') # 简单处理，字母为辅音
    }
    return features

# 模拟DGA域名生成
def generate_dga_domain(filepath='dga_test/dga_domains.txt'):
    try:
        with open(filepath, 'r') as f:
            dga_domains = [line.strip() for line in f if line.strip()]
        if not dga_domains:
            raise ValueError("合法域名文件为空或不包含任何域名。")
        return random.choice(dga_domains)
    except FileNotFoundError:
        print(f"错误：找不到文件 '{filepath}'。请确保该文件存在并包含合法域名。")
        return None
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return None
    

# 模拟正常域名生成
def generate_legit_domain(filepath='dga_test/legit_domains.txt'):
    try:
        with open(filepath, 'r') as f:
            legit_domains = [line.strip() for line in f if line.strip()]
        if not legit_domains:
            raise ValueError("合法域名文件为空或不包含任何域名。")
        return random.choice(legit_domains)
    except FileNotFoundError:
        print(f"错误：找不到文件 '{filepath}'。请确保该文件存在并包含合法域名。")
        return None
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return None


# 主函数 ---
def dga_detection_system(dns_file_path="dga_test/dns.csv"):
    try:
        df_dns = pd.read_csv(dns_file_path, sep=',', header=None)
        domains_to_analyze = df_dns[0];
    except FileNotFoundError:
        print(f"错误：找不到文件 '{dns_file_path}'。请确保该文件存在并包含合法域名。")
        return None
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return None
    print(f"已加载 {len(domains_to_analyze)} 个独立域名进行DGA检测。")

    # --- 模拟训练数据 (在实际应用中，您需要真实标记的数据集) ---
    num_samples = 10000
    legit_domains_train = [generate_legit_domain() for _ in range(num_samples // 2)]
    dga_domains_train = [generate_dga_domain() for _ in range(num_samples // 2)]

    train_data = pd.DataFrame({'domain': legit_domains_train + dga_domains_train,
                               'label': [0] * (num_samples // 2) + [1] * (num_samples // 2)}) # 0: 正常, 1: DGA

    # 为训练数据提取特征
    print("训练数据特征提取...")
    train_features_df = train_data['domain'].apply(lambda x: pd.Series(extract_features(x)))
    X_train = train_features_df
    y_train = train_data['label']

    # 数据标准化
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # --- 阶段一：基于随机森林的轻量级分类分析 ---
    print("\n--- 阶段一：随机森林分类检测 ---")
    rf_model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf_model.fit(X_train_scaled, y_train)
    print("随机森林模型训练完成")

    # 为要检测的域名提取特征
    print("为待检测域名提取特征...")
    df_domains_features = pd.DataFrame([extract_features(d) for d in domains_to_analyze])
    df_domains_features.index = domains_to_analyze # 将域名作为索引

    # 数据标准化 (使用训练集的scaler)
    df_domains_features_scaled = scaler.transform(df_domains_features)

    # 预测概率，以便后续筛选疑似DGA域名 (例如，概率 > 0.5)
    domain_probabilities = rf_model.predict_proba(df_domains_features_scaled)[:, 1] # 获取DGA类别的概率

    # 将预测结果合并到原始域名列表中
    df_domains_result = pd.DataFrame({'domain': domains_to_analyze, 'dga_probability': domain_probabilities})

    # 识别疑似DGA域名
    # 通常会设置一个概率阈值，例如 0.5
    suspicious_domains = df_domains_result[df_domains_result['dga_probability'] >= 0.8]
    print(f"随机森林分类结果：共识别出 {len(suspicious_domains)} 个疑似DGA域名。")
    print("疑似DGA域名:")
    print(suspicious_domains.sort_values(by='dga_probability', ascending=False).head(10))
    print("\n...")

    # --- 阶段二：基于聚类分析的进一步检测 ---
    print("\n\n--- 阶段二：聚类分析检测 ---")

    if suspicious_domains.empty:
        print("没有疑似DGA域名")
        return pd.DataFrame(), pd.DataFrame() # 返回空DataFrame
    
    # 重新提取疑似DGA域名的特征，可以考虑更丰富的特征
    # 这里我们继续使用已提取的特征，或可以根据需求增加 n-gram 频率等
    X_cluster = df_domains_features.loc[suspicious_domains['domain']]
    X_cluster_scaled = scaler.transform(X_cluster) # 使用同一个scaler进行标准化

    # 使用轮廓系数选择K值 (K-means的簇数量)
    # 论文提到X-means可以自动确定K，但K-means需要手动指定。
    # 这里我们尝试几个K值，并选择轮廓系数最高的
    print("通过轮廓系数选择K-means的最佳簇数量K...")
    silhouette_scores = []
    # 尝试的K值范围，需要根据实际数据调整
    k_range = range(2, min(len(X_cluster_scaled), 10)) # 至少2个簇，最多10个或样本数
    if len(k_range) < 2:
        print("疑似DGA域名数量过少")
        return pd.DataFrame(), pd.DataFrame()

    for k in k_range:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10) # n_init for robust centroid initialization
        cluster_labels = kmeans.fit_predict(X_cluster_scaled)
        if len(set(cluster_labels)) > 1: # 确保至少有两个不同的簇才能计算轮廓系数
            score = silhouette_score(X_cluster_scaled, cluster_labels)
            silhouette_scores.append((k, score))
            print(f"K={k}, 轮廓系数: {score:.3f}")
        else:
             print(f"K={k}, 无法计算轮廓系数 (只有1个簇或更少)")

    if not silhouette_scores:
        print("未能找到合适的K值进行聚类分析")
        return pd.DataFrame(), pd.DataFrame()
        
    best_k = max(silhouette_scores, key=lambda item: item[1])[0]
    print(f"最佳簇数量K为: {best_k}")

    # 使用最佳K值进行K-means聚类
    kmeans = KMeans(n_clusters=best_k, random_state=42, n_init=10)
    cluster_labels = kmeans.fit_predict(X_cluster_scaled)
    
    suspicious_domains['cluster'] = cluster_labels
    
    print(f"\n聚类分析完成")
    print("各簇的域名数量：")
    print(suspicious_domains['cluster'].value_counts().sort_index())

    # --- 聚类结果分析：识别DGA簇 ---
    # 论文中提到“集合分析方法”，这里我们通过检查簇内域名的共性来判断
    # 例如，DGA簇中的域名可能在某个特征（如熵、长度）上表现出相似性
    # 实际中可能需要结合人工审查或更复杂的统计分析
    
    dga_clusters = []
    print("\n--- 聚类结果分析 (识别DGA簇) ---")
    for cluster_id in sorted(suspicious_domains['cluster'].unique()):
        cluster_domains = suspicious_domains[suspicious_domains['cluster'] == cluster_id]
        print(f"\n簇 {cluster_id} ({len(cluster_domains)} 个域名):")
        # 打印该簇中域名的一些特征统计
        cluster_features_mean = X_cluster.loc[cluster_domains['domain']].mean()
        print("  平均特征值：")
        print(cluster_features_mean)

        # 简单判断DGA簇的启发式：例如，高平均熵值和/或高数字比例
        # 实际中需要更复杂的规则或人工审查
        if cluster_features_mean['entropy'] > 3.5 or cluster_features_mean['digit_ratio'] > 0.2:
            dga_clusters.append(cluster_id)
            print(f"  --> 簇 {cluster_id} 疑似DGA簇 (基于启发式判断)。")
    
    final_dga_domains = suspicious_domains[suspicious_domains['cluster'].isin(dga_clusters)]
    
    print(f"\n--- 最终检测结果 ---")
    print(f"通过两阶段检测，最终识别出 {len(final_dga_domains)} 个DGA域名。")
    print("最终识别的DGA域名示例：")
    print(final_dga_domains.head(20)) # 打印前20个DGA域名

    # ========== 第三阶段：Gemini API 验证 ==========
    def extract_classification(llm_response):
        """从LLM响应中提取分类结果"""
        if not llm_response:
            return "unknown"
        
        # 将响应转换为字符串并转换为小写
        response_str = str(llm_response).lower().strip()
        
        # 查找dga或normal关键词
        if "dga" in response_str:
            return "dga"
        elif "normal" in response_str:
            return "normal"
        else:
            return "unknown"
    
    def llm_check(domain):
        try:
            model = OllamaLLM(model="qwen3:14b", temperature=0.1, base_url="http://192.168.3.98:11434")
            prompt = f"""
            You are a domain name classification system. Your task is
            to classify domain names as either ’dga’ (Domain Generation
            Algorithm) or ’normal’. DGA domains are automatically
            generated by malware, while normal domains are not. I will
            provide you with labeled training data containing domain
            names and their classifications. After the training phase,
            you will classify a new domain and respond with either
            ’dga’ or ’normal’.

            domain: 517mrt.com, result: normal
            domain: siel.nl, result: normal
            domain: e-hps.com, result: normal
            domain: infowheel.com, result: normal
            domain: synirc.net, result: normal
            domain: justthedesign.com, result: normal
            domain: clone.gs, result: normal
            domain: yerdurumu.com, result: normal
            domain: greenwoodindentist.com, result: normal
            domain: codesphp.com, result: normal
            domain: lpvzs4cpq5w.com, result: dga
            domain: zifvh98m2j95c42tepvfboc64m6.com, result: dga
            domain: grdoguq9ybgczaym4.com, result: dga
            domain: 2uyq8llhk9x44qa373emvs.com, result: dga
            domain: 3w4cn54whygr7iq4s7ve3j27a.com, result: dga
            domain: trz92khj6ml1pcclz4rj978h4gi7d.com, result: dga
            domain: q42gpy2yftsa2f7oe.com, result: dga
            domain: jxfkcmayxgi5m.com, result: dga
            domain: 8un8orve1z958j.com, result: dga
            domain: grnvpfrta1znlchibbjdk7z8.com, result: dga

            Now you classify this domain: {domain}, only answer
            dga or normal. Do not provide any additional information
            or explanation.
            """
            llm_result = model.invoke(prompt)
            # 提取分类结果
            classification = extract_classification(llm_result)
            return classification
        except Exception as e:
            print(f"LLM调用失败: {e}")
            return "unknown"

    if not final_dga_domains.empty:
        print("\n--- 第三阶段：LLM 验证 ---")
        # 为每个域名调用LLM
        final_dga_domains['llm_classification'] = final_dga_domains['domain'].apply(lambda d: llm_check(d))
        print(final_dga_domains[['domain', 'llm_classification']].head(20))

    # 可视化聚类结果 (只针对两个最重要的特征进行可视化)
    # if not X_cluster.empty and X_cluster.shape[1] >= 2:
    #     plt.figure(figsize=(10, 7))
    #     scatter = plt.scatter(X_cluster['entropy'], X_cluster['length'], c=cluster_labels, cmap='viridis', alpha=0.6)
    #     plt.title('疑似DGA域名的聚类结果 (熵 vs 长度)')
    #     plt.xlabel('熵')
    #     plt.ylabel('域名长度')
    #     plt.colorbar(scatter, label='簇 ID')
    #     plt.tight_layout()
    #     plt.savefig('dga_cluster_scatter.png')
    #     print("已生成：dga_cluster_scatter.png (疑似DGA域名的聚类散点图)")
    #     plt.close()
    # else:
    #     print("疑似DGA域名特征维度不足或数量太少，无法生成聚类散点图。")

    return df_domains_result, final_dga_domains # 返回所有域名预测结果和最终DGA域名

# --- 运行检测系统 ---
if __name__ == "__main__":
    # 确保 dns.csv 文件在当前目录下
    all_domains_prediction, final_dga_detected = dga_detection_system("dga_test/dns.csv")

    # 可以在这里对 all_domains_prediction 和 final_dga_detected 进行后续处理
    # 例如保存到CSV文件
    if not all_domains_prediction.empty:
        all_domains_prediction.to_csv("dga_test/all_domains_dga_probability.csv", index=False)
        print("\n所有域名的DGA概率已保存到 all_domains_dga_probability.csv")
    if not final_dga_detected.empty:
        final_dga_detected.to_csv("dga_test/final_dga_domains.csv", index=False)
        print("最终识别的DGA域名已保存到 final_dga_domains.csv")