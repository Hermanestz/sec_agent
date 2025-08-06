# 如何使用API

## 认证说明

用户名：user  
密码：gsta@2025

## 1. 使用 curl

(1) 获取访问令牌：

Bash

    curl -X POST "http://127.0.0.1:8000/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=user&password=gsta@2025"

复制返回的 access_token。

(2) 使用令牌调用分析接口（将 <YOUR_TOKEN> 替换为第一步获取到的令牌）：

Bash

    curl -X POST "http://192.168.3.98:8000/analyze/domain" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"target": "example.com"}'

Bash

    curl -X POST "http://192.168.3.98:8000/analyze/ip" \
    -H "Authorization: Bearer <YOUR_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"target": "8.8.8.8"}'

## 2. 使用Python脚本进行批量调用

以下脚本展示了如何通过编程方式登录并批量处理一组域名和IP,运行前确保python为3.6以上版本，且已安装requests第三方库（pip安装命令：`pip install requests`），将`DOMAINS_TO_ANALYZE`和`IPS_TO_ANALYZE`替换为需要分析的域名和ip:

    import requests
    import json

    # --- 1. 配置信息 ---
    BASE_URL = "http://192.168.3.98:8000" 
    API_USERNAME = "user" #
    API_PASSWORD = "gsta@2025" #

    # --- 2. 准备需要批量分析的目标列表 ---
    DOMAINS_TO_ANALYZE = [
        "akl01.dnscry.pt",
        "vps329.brueggus.de",
        "gradio.danghf.cn"
    ]

    IPS_TO_ANALYZE = [
        "65.49.1.64",
        "199.16.158.8"
    ]

    # 通过API的/token接口进行身份认证，获取JWT访问令牌
    def get_access_token(base_url, username, password):
        token_url = f"{base_url}/token"
        login_data = {
            "username": username,
            "password": password
        }
        
        print("正在尝试获取访问令牌...")
        try:
            response = requests.post(token_url, data=login_data)
            # 如果服务器返回错误状态码 (如 401 Unauthorized), 则抛出异常。
            response.raise_for_status()
            token_info = response.json()
            access_token = token_info.get("access_token")
            if not access_token:
                print("错误：服务器响应中未找到'access_token'。")
                return None
            print("成功获取访问令牌")
            return access_token
        except requests.exceptions.HTTPError as http_err:
            print(f"身份认证时发生HTTP错误: {http_err}")
            print(f"服务器响应内容: {response.text}")
            return None
        except requests.exceptions.RequestException as req_err:
            print(f"身份认证时发生连接错误: {req_err}")
            return None

    # 将一系列目标发送到指定的分析接口进行处理
    def analyze_targets_in_batch(base_url, targets, endpoint, token):
        analysis_url = f"{base_url}/{endpoint}"
        # 准备认证请求头
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        print(f"\n--- 开始对接口 '{endpoint}' 进行批量分析 ---")
        for target in targets:
            # 请求体必须是包含 "target" 键的JSON对象
            payload = {"target": target}
            try:
                print(f"正在分析: {target}...")
                response = requests.post(analysis_url, headers=headers, json=payload)
                response.raise_for_status() # 如果请求失败则抛出异常
                result = response.json()
                print(f"  -> 分析结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
            except requests.exceptions.HTTPError as http_err:
                print(f"  -> 分析 {target} 时发生HTTP错误: {http_err}")
                print(f"     服务器响应: {response.text}")
            except requests.exceptions.RequestException as req_err:
                print(f"  -> 分析 {target} 时发生连接错误: {req_err}")


    if __name__ == "__main__":
        # 第一步：获取访问令牌
        access_token = get_access_token(BASE_URL, API_USERNAME, API_PASSWORD)
        # 只有成功获取令牌后，才继续执行后续的批量调用
        if access_token:
            # 第二步：批量分析域名列表
            analyze_targets_in_batch(
                base_url=BASE_URL,
                targets=DOMAINS_TO_ANALYZE,
                endpoint="analyze/domain", #
                token=access_token
            )
            # 第三步：批量分析IP地址列表
            analyze_targets_in_batch(
                base_url=BASE_URL,
                targets=IPS_TO_ANALYZE,
                endpoint="analyze/ip", #
                token=access_token
            )
        print("\n--- 所有批量任务已执行完毕。 ---")
